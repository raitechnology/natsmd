/* Copyright (c) 2026 Rai Technology.  All rights reserved.
 *  http://www.raitechnology.com
 *
 * nats_api.cpp -- the thread-safe NATS api (include/natsmd/natsapi.h).
 *
 * Layout follows omm's omm_api.cpp and sassrv's rv7_api.cpp: kv::ApiCore
 * owns the epoll thread, the id registry, the queues, timers and
 * dispatchers; this file adds the transport (an EvNatsClient with a
 * reconnect timer), the listeners (subjects and wildcards, matched to the
 * arriving publishes), publishing and the message handle.  Api calls that
 * touch the connection cross to the epoll thread as ApiOp records over the
 * ApiPipe; the listener tables are only touched on that thread. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <raikv/ev_publish.h>
#include <raikv/key_hash.h>
#include <raimd/md_msg.h>
#include <natsmd/ev_nats_client.h>
#include <natsmd/natscpp.h>

#ifndef NATSMD_VER
#define NATSMD_VER dev
#endif
#define STR2( s ) #s
#define STR( s ) STR2( s )

using namespace natsapi;

/* a NATS subject: tokens separated by '.', no whitespace, fits a uint16 */
static bool
valid_subject( const char *s,  size_t &len ) noexcept
{
  if ( s == NULL )
    return false;
  len = ::strlen( s );
  if ( len == 0 || len > MAX_SUBJECT_LEN )
    return false;
  for ( size_t i = 0; i < len; i++ )
    if ( (uint8_t) s[ i ] <= ' ' )
      return false;
  return true;
}

/* NATS wildcard match: '*' is one token, '>' the rest of the subject */
static bool
match_wildcard( const char *wild,  size_t wild_len,
                const char *sub,  size_t sub_len ) noexcept
{
  const char * w   = wild,
             * end = &wild[ wild_len ];
  size_t       k   = 0;

  for (;;) {
    if ( k == sub_len || w == end )
      return ( k == sub_len && w == end );
    if ( *w == '>' && ( w == wild || *(w-1) == '.' ) && w+1 == end )
      return true;
    if ( *w == '*' && ( w == wild || *(w-1) == '.' ) &&
         ( w+1 == end || *(w+1) == '.' ) ) {
      while ( k < sub_len && sub[ k ] != '.' )
        k++;
      w++;
      continue;
    }
    if ( *w != sub[ k ] )
      return false;
    w++;
    k++;
  }
}

api_Queue::api_Queue( Nats_API &a,  natsId i ) : ApiQueue( a, i ) {}

static Nats_API * nats_api;
static pthread_mutex_t nats_open_mutex = PTHREAD_MUTEX_INITIALIZER;

static nats_status
api_status( ApiStatus st )
{
  switch ( st ) {
    case API_OK:                  return NATS_OK;
    case API_TIMEOUT:             return NATS_TIMEOUT;
    case API_INVALID_QUEUE:       return NATS_INVALID_QUEUE;
    case API_INVALID_QUEUE_GROUP: return NATS_INVALID_QUEUE_GROUP;
    case API_INVALID_EVENT:       return NATS_INVALID_EVENT;
    case API_INVALID_DISPATCHER:  return NATS_INVALID_DISPATCHER;
    case API_INVALID_ARG:         return NATS_INVALID_ARG;
    default:                      return NATS_INIT_FAILURE;
  }
}

api_Transport::api_Transport( Nats_API &a,  natsId i ) noexcept
  : api( a ), id( i ), client( a.poll ), wild( 0 ), wild_cnt( 0 ),
    wild_size( 0 ), state_listener( 0 ), daemon( 0 ), name( 0 ), user( 0 ),
    password( 0 ), auth_token( 0 ), descr( 0 ),
    reconnect_secs( DEFAULT_RECONNECT_SECS ), advisory( 0 ), inbox_count( 1 ),
    dup_hash( 0 ), dup_len( 0 ), dup_crc( 0 ), dup_skip( 0 ),
    connected( false ), is_destroyed( false ), timer_armed( false ),
    connect_failed( false )
{
  pthread_mutex_init( &this->mutex, NULL );
  pthread_cond_init( &this->cond, NULL );
}

void
api_Transport::set_params( const natsTransportParams &p ) noexcept
{
  ApiCore::set_string( this->daemon, p.daemon != NULL ? p.daemon
                                                      : "127.0.0.1:4222" );
  ApiCore::set_string( this->name, p.name != NULL ? p.name : "natsapi" );
  ApiCore::set_string( this->user, p.user );
  ApiCore::set_string( this->password, p.password );
  ApiCore::set_string( this->auth_token, p.auth_token );
  this->reconnect_secs = ( p.reconnect_secs == 0 ? DEFAULT_RECONNECT_SECS
                                                 : p.reconnect_secs );
  this->advisory = ( p.advisory < 0 ? 0 : (uint32_t) p.advisory );
}

/* epoll thread: (re)connect the client; a refused connect is reported
 * through on_shutdown(), a failure here (bad host) arms the retry itself */
bool
api_Transport::connect( void ) noexcept
{
  EvNatsClientParameters parm = this->client_params();
  parm.opts |= kv::OPT_CONNECT_NB;
  if ( ! this->client.nats_connect( parm, this, this ) ) {
    this->connect_failed = true;
    this->arm_reconnect();
    return false;
  }
  return true;
}

void
api_Transport::arm_reconnect( void ) noexcept
{
  if ( this->is_destroyed || this->reconnect_secs < 0 || this->timer_armed )
    return;
  this->timer_armed = true;
  this->api.poll.timer.add_timer_double( *this, this->reconnect_secs,
                                         RECONNECT_TIMER_ID, this->id );
}

bool
api_Transport::timer_cb( uint64_t timer_id,  uint64_t ) noexcept
{
  if ( timer_id != RECONNECT_TIMER_ID )
    return false;
  if ( this->is_destroyed || this->connected ) {
    this->timer_armed = false;
    return false;
  }
  if ( this->client.fd == -1 )  /* connecting: the timer stays armed until */
    this->connect();            /* on_connect / on_shutdown decide; failed: */
  return true;                  /* retry at the next tick */
}

void
api_Transport::add_wild( api_Listener &l ) noexcept
{
  if ( this->wild_cnt == this->wild_size ) {
    this->wild_size = ( this->wild_size == 0 ? 8 : this->wild_size * 2 );
    this->wild = (api_Listener **)
      ::realloc( this->wild, this->wild_size * sizeof( this->wild[ 0 ] ) );
  }
  this->wild[ this->wild_cnt++ ] = &l;
}

void
api_Transport::remove_wild( api_Listener &l ) noexcept
{
  for ( size_t i = 0; i < this->wild_cnt; i++ ) {
    if ( this->wild[ i ] == &l ) {
      for ( ; i + 1 < this->wild_cnt; i++ )
        this->wild[ i ] = this->wild[ i + 1 ];
      this->wild_cnt--;
      return;
    }
  }
}

/* epoll thread, connected: SUB the listener's subject (+ queue group) */
void
api_Transport::start_sub( api_Listener &l ) noexcept
{
  if ( l.is_inbox )
    return;
  this->client.subscribe( l.subject, l.len, l.queue_group,
                          l.queue_group_len );
}

/* epoll thread: UNSUB when l was the last listener on its subject */
void
api_Transport::stop_sub( api_Listener &l ) noexcept
{
  if ( l.is_inbox || ! this->connected )
    return;
  if ( ! this->ht.other_live( &l ) )
    this->client.unsubscribe( l.subject, l.len );
}

/* epoll thread, connected, mutex held: the reply inbox pattern
 * _INBOX.<session>.> for natsTransport_CreateInbox(); the session is
 * made once and survives reconnects, the SUB does not */
void
api_Transport::subscribe_inbox( void ) noexcept
{
  if ( this->client.session_len == 0 )
    this->client.make_session(); /* also subscribes the pattern */
  else
    this->client.subscribe_inbox();
}

/* INFO received, CONNECT sent */
void
api_Transport::on_connect( EvSocket & ) noexcept
{
  pthread_mutex_lock( &this->mutex );
  this->connected      = true;
  this->connect_failed = false;
  this->timer_armed    = false;
  this->dup_skip       = 0;
  this->api.poll.timer.remove_timer_cb( *this, RECONNECT_TIMER_ID, this->id );
  pthread_cond_broadcast( &this->cond );
  this->subscribe_inbox();
  /* (re)subscribe every live listener; one SUB per distinct subject */
  for ( size_t i = 0; this->ht.ht != NULL && i <= this->ht.mask; i++ ) {
    for ( api_Listener *l = this->ht.ht[ i ].hd; l != NULL; l = l->next ) {
      if ( ! l->live() )
        continue;
      bool first = true;
      for ( api_Listener *p = this->ht.ht[ i ].hd; p != l; p = p->next )
        if ( p->live() && p->same_subject( *l ) ) {
          first = false;
          break;
        }
      if ( first )
        this->start_sub( *l );
    }
  }
  this->client.idle_push_write();
  pthread_mutex_unlock( &this->mutex );
  this->push_state( NATS_MSG_TRANSPORT_UP, "connected" );
}

void
api_Transport::on_shutdown( EvSocket &,  const char *err,
                            size_t err_len ) noexcept
{
  char text[ 256 ];
  int  n = ::snprintf( text, sizeof( text ), "transport disconnected%s%.*s",
                       err_len > 0 ? ": " : "", (int) err_len,
                       err != NULL ? err : "" );
  if ( n < 0 || (size_t) n >= sizeof( text ) )
    text[ sizeof( text ) - 1 ] = '\0';
  pthread_mutex_lock( &this->mutex );
  bool was_connected = this->connected;
  this->connected = false;
  this->dup_skip  = 0;
  pthread_cond_broadcast( &this->cond );
  pthread_mutex_unlock( &this->mutex );
  if ( was_connected )
    this->push_state( NATS_MSG_TRANSPORT_DOWN, text );
  this->arm_reconnect();
}

void
api_Transport::push_state( uint8_t msg_class,  const char *text ) noexcept
{
  api_Listener * l = this->state_listener;
  if ( l != NULL )
    this->api.deliver( *l, api_Msg::make_status( *l, msg_class, text ) );
}

/* epoll thread: a publish from the server.  The exact listeners are found
 * by hash, the wildcard listeners by matching.  NATS sends one copy per
 * matching subscription (sid); the copies of one publish are consecutive,
 * so after delivering the first the next nsub-1 identical ones are
 * dropped (identical = subject hash, length and payload crc) */
bool
api_Transport::on_nats_msg( EvPublish &pub ) noexcept
{
  uint32_t h   = kv_crc_c( pub.subject, pub.subject_len, 0 ),
           crc = 0;
  if ( this->dup_skip > 0 ) {
    crc = kv_crc_c( pub.msg, pub.msg_len, 0 );
    if ( h == this->dup_hash && pub.msg_len == this->dup_len &&
         crc == this->dup_crc ) {
      this->dup_skip--;
      return true;
    }
    this->dup_skip = 0;
  }
  uint32_t nsub = 0;
  pthread_mutex_lock( &this->mutex );
  ListenerList * b = this->ht.bucket( h );
  if ( b != NULL ) {
    bool exact = false;
    for ( api_Listener *l = b->hd; l != NULL; l = l->next ) {
      if ( ! l->live() || l->is_wild || l->hash != h ||
           ! l->same_subject( pub.subject, pub.subject_len ) )
        continue;
      if ( ! l->is_inbox )
        exact = true;
      this->api.deliver( *l, api_Msg::make( *l, pub ) );
    }
    if ( exact )
      nsub++;
  }
  /* the inbox pattern is a subscription of its own */
  if ( this->client.is_inbox( pub.subject, pub.subject_len ) != 0 )
    nsub++;
  for ( size_t i = 0; i < this->wild_cnt; i++ ) {
    api_Listener * l = this->wild[ i ];
    if ( ! l->live() ||
         ! match_wildcard( l->subject, l->len, pub.subject, pub.subject_len ) )
      continue;
    bool first = true;
    for ( size_t j = 0; j < i; j++ )
      if ( this->wild[ j ]->live() && this->wild[ j ]->same_subject( *l ) ) {
        first = false;
        break;
      }
    if ( first )
      nsub++;
    this->api.deliver( *l, api_Msg::make( *l, pub ) );
  }
  if ( nsub > 1 ) {
    this->dup_skip = nsub - 1;
    this->dup_hash = h;
    this->dup_len  = pub.msg_len;
    this->dup_crc  = ( crc != 0 ? crc : kv_crc_c( pub.msg, pub.msg_len, 0 ) );
  }
  pthread_mutex_unlock( &this->mutex );
  return true;
}

api_Msg *
api_Msg::make( api_Listener &l,  EvPublish &pub ) noexcept
{
  api_Msg * am = new ( ::malloc( sizeof( api_Msg ) ) ) api_Msg( l.id, l.cl );
  am->set_subject( pub.subject, pub.subject_len );
  if ( pub.reply_len > 0 )
    am->set_reply( pub.reply, pub.reply_len );
  am->set_data( pub.msg, pub.msg_len, 0 );
  am->recv_ns   = current_realtime_ns();
  am->msg_class = NATS_MSG_DATA;
  return am;
}

api_Msg *
api_Msg::make_status( api_Listener &l,  uint8_t msg_class,
                      const char *text ) noexcept
{
  api_Msg * am = new ( ::malloc( sizeof( api_Msg ) ) ) api_Msg( l.id, l.cl );
  am->set_subject( l.subject, l.len );
  am->recv_ns   = current_realtime_ns();
  am->msg_class = msg_class;
  am->enc_done  = true;
  if ( text != NULL )
    am->set_text( text, ::strlen( text ) );
  return am;
}

bool
api_Msg::release( void ) noexcept
{
  this->in_queue = false;
  if ( this->refs == 0 ) {
    delete this;
    return true;
  }
  return false;
}

void
Nats_API::dispatch_event( ApiQueueEvent &ev ) noexcept
{
  api_Msg * m = (api_Msg *) ev.msg;
  if ( ev.cb == NULL )
    return;
  ( (natsEventCallback) ev.cb )( ev.id, (natsMsg) m, (void *) ev.cl );
  if ( m != NULL )
    m->release();
  else {
    api_Timer * t = this->get_timer( ev.id );
    if ( t != NULL )
      t->in_queue = false;
  }
}

nats_status
Nats_API::open( void ) noexcept
{
  if ( this->open_pipe( 128 ) != API_OK )
    return NATS_INIT_FAILURE;
  if ( this->open_default_pipe( "nats_api_pipe" ) != API_OK )
    return NATS_INIT_FAILURE;
  this->default_queue = this->make<api_Queue>( NATS_ELEM_QUEUE, 0,
                                               NATS_DEFAULT_QUEUE );
  this->start_ev_thread();
  return NATS_OK;
}

#define API_CHECK() \
  if ( nats_api == NULL ) return NATS_NOT_INITIALIZED

extern "C" {

void
nats_InitTransportParams( natsTransportParams *p )
{
  ::memset( p, 0, sizeof( *p ) );
}

nats_status
nats_Open( void )
{
  nats_status st = NATS_OK;
  pthread_mutex_lock( &nats_open_mutex );
  if ( nats_api == NULL ) {
    Nats_API * api = new ( aligned_malloc( sizeof( Nats_API ) ) ) Nats_API();
    st = api->open();
    if ( st == NATS_OK )
      nats_api = api;
  }
  pthread_mutex_unlock( &nats_open_mutex );
  return st;
}

nats_status
nats_Close( void )
{
  return NATS_OK; /* the epoll thread lives for the process, like tibrv */
}

const char *
nats_Version( void )
{
  return STR( NATSMD_VER );
}

const char *
natsStatus_GetText( nats_status status )
{
  switch ( status ) {
    case NATS_OK:                  return "OK";
    case NATS_INIT_FAILURE:        return "Initialization failed";
    case NATS_NOT_INITIALIZED:     return "nats_Open() not called";
    case NATS_INVALID_TRANSPORT:   return "Invalid transport";
    case NATS_INVALID_QUEUE:       return "Invalid queue";
    case NATS_INVALID_QUEUE_GROUP: return "Invalid queue group";
    case NATS_INVALID_EVENT:       return "Invalid event";
    case NATS_INVALID_DISPATCHER:  return "Invalid dispatcher";
    case NATS_INVALID_ARG:         return "Invalid argument";
    case NATS_INVALID_SUBJECT:     return "Invalid subject";
    case NATS_NOT_CONNECTED:       return "Transport not connected";
    case NATS_TIMEOUT:             return "Timeout";
    case NATS_NOT_SUPPORTED:       return "Not supported";
    case NATS_NO_MEMORY:           return "Out of memory";
    case NATS_INVALID_MSG:         return "Invalid message";
    default:                       return "Unknown status";
  }
}

nats_status
natsTransport_Create( natsTransport *tport,  const natsTransportParams *parms )
{
  API_CHECK();
  *tport = NATS_INVALID_ID;
  natsTransportParams def;
  if ( parms == NULL ) {
    nats_InitTransportParams( &def );
    parms = &def;
  }
  api_Transport * t = nats_api->make<api_Transport>( NATS_ELEM_TRANSPORT );
  t->set_params( *parms );
  TportOp op( *t, 0 );
  pthread_mutex_lock( &t->mutex );
  nats_api->ev_read->exec( op );
  pthread_mutex_unlock( &t->mutex );
  *tport = t->id;
  return NATS_OK;
}

nats_status
natsTransport_Destroy( natsTransport tport )
{
  API_CHECK();
  api_Transport * t = nats_api->rem<api_Transport>( tport, NATS_ELEM_TRANSPORT );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  TportOp op( *t, 1 );
  pthread_mutex_lock( &t->mutex );
  nats_api->ev_read->exec( op );
  pthread_mutex_unlock( &t->mutex );
  /* the client socket is released by the epoll thread; the transport
   * record stays (listeners may still reference it) */
  return NATS_OK;
}

nats_status
natsTransport_IsConnected( natsTransport tport,  int *connected )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *connected = t->connected ? 1 : 0;
  return NATS_OK;
}

nats_status
natsTransport_WaitConnected( natsTransport tport,  double timeout )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  nats_status st = NATS_OK;
  pthread_mutex_lock( &t->mutex );
  if ( ! t->connected ) {
    struct timespec ts = api_ts_timeout( timeout, 1.0 );
    for (;;) {
      if ( timeout == NATS_WAIT_FOREVER )
        pthread_cond_wait( &t->cond, &t->mutex );
      else if ( pthread_cond_timedwait( &t->cond, &t->mutex, &ts ) == ETIMEDOUT )
        break;
      if ( t->connected || t->is_destroyed )
        break;
    }
    if ( ! t->connected )
      st = ( t->is_destroyed ? NATS_INVALID_TRANSPORT : NATS_TIMEOUT );
  }
  pthread_mutex_unlock( &t->mutex );
  return st;
}

nats_status
natsTransport_GetDaemon( natsTransport tport,  const char **daemon )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *daemon = t->daemon;
  return NATS_OK;
}

nats_status
natsTransport_GetName( natsTransport tport,  const char **name )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *name = t->name;
  return NATS_OK;
}

nats_status
natsTransport_GetUser( natsTransport tport,  const char **user )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *user = t->user;
  return NATS_OK;
}

nats_status
natsTransport_SetDescription( natsTransport tport,  const char *d )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  ApiCore::set_string( t->descr, d );
  return NATS_OK;
}

nats_status
natsTransport_GetDescription( natsTransport tport,  const char **d )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *d = t->descr;
  return NATS_OK;
}

nats_status
natsTransport_GetMaxPayload( natsTransport tport,  uint32_t *max_payload )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  *max_payload = ( t->connected ? (uint32_t) t->client.max_payload : 0 );
  return NATS_OK;
}

nats_status
natsTransport_CreateInbox( natsTransport tport,  char *inbox_str,
                           uint32_t inbox_len )
{
  API_CHECK();
  if ( inbox_len > 0 )
    inbox_str[ 0 ] = '\0';
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  char   inbox[ NATS_MAX_INBOX_LEN ];
  size_t len;
  pthread_mutex_lock( &t->mutex );
  if ( t->client.session_len == 0 ) { /* the session is made at connect */
    pthread_mutex_unlock( &t->mutex );
    return NATS_NOT_CONNECTED;
  }
  len = (size_t) ::snprintf( inbox, sizeof( inbox ), "_INBOX.%.*s.%u",
                             (int) t->client.session_len, t->client.session,
                             t->inbox_count++ );
  pthread_mutex_unlock( &t->mutex );
  if ( len >= sizeof( inbox ) )
    len = sizeof( inbox ) - 1;
  if ( inbox_len > 0 )
    ::memcpy( inbox_str, inbox, len + 1 <= inbox_len ? len + 1 : inbox_len );
  if ( inbox_len > 0 && len + 1 > inbox_len )
    inbox_str[ inbox_len - 1 ] = '\0';
  return NATS_OK;
}

nats_status
natsTransport_Send( natsTransport tport,  const char *subject,
                    const char *reply,  const void *data,  uint32_t len,
                    uint32_t msg_enc )
{
  API_CHECK();
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL || t->is_destroyed )
    return NATS_INVALID_TRANSPORT;
  size_t sublen, replen = 0;
  if ( ! valid_subject( subject, sublen ) )
    return NATS_INVALID_SUBJECT;
  if ( reply != NULL && reply[ 0 ] != '\0' && ! valid_subject( reply, replen ) )
    return NATS_INVALID_SUBJECT;
  if ( data == NULL && len != 0 )
    return NATS_INVALID_ARG;
  if ( ! t->connected )
    return NATS_NOT_CONNECTED;
  EvPublish pub( subject, sublen, replen > 0 ? reply : NULL, replen,
                 data, len, t->client.sub_route, t->client, 0, msg_enc );
  SendOp op( *t, pub );
  pthread_mutex_lock( &t->mutex );
  nats_api->ev_read->exec( op );
  pthread_mutex_unlock( &t->mutex );
  return op.sent ? NATS_OK : NATS_NOT_CONNECTED;
}

nats_status
natsTransport_SendMsg( natsTransport tport,  natsMsg msg )
{
  if ( msg == NULL )
    return NATS_INVALID_MSG;
  api_Msg * m = (api_Msg *) msg;
  if ( m->subject == NULL || m->subject_len == 0 )
    return NATS_INVALID_SUBJECT;
  return natsTransport_Send( tport, m->subject, m->reply, m->data,
                             m->data_len, m->msg_enc );
}

nats_status
natsTransport_SetStateListener( natsTransport tport,  natsQueue queue,
                                void ( *cb )( natsEvent, natsMsg, void * ),
                                const void *closure,  natsEvent *event )
{
  API_CHECK();
  *event = NATS_INVALID_ID;
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL )
    return NATS_INVALID_TRANSPORT;
  if ( nats_api->get_queue( queue ) == NULL )
    return NATS_INVALID_QUEUE;
  api_Listener * l = nats_api->make<api_Listener>( NATS_ELEM_LISTENER );
  l->subject  = ::strdup( "_TRANSPORT" );
  l->len      = 10;
  l->hash     = kv_crc_c( l->subject, l->len, 0 );
  l->cb       = cb;
  l->cl       = closure;
  l->queue    = queue;
  l->tport    = tport;
  l->is_state = true;
  pthread_mutex_lock( &t->mutex );
  api_Listener * old = t->state_listener;
  t->state_listener = l;
  pthread_mutex_unlock( &t->mutex );
  if ( old != NULL ) {
    nats_api->rem<api_Listener>( old->id, NATS_ELEM_LISTENER );
    delete old;
  }
  *event = l->id;
  return NATS_OK;
}

nats_status
natsQueue_Create( natsQueue *queue )
{
  API_CHECK();
  api_Queue * q = nats_api->make<api_Queue>( NATS_ELEM_QUEUE );
  *queue = q->id;
  return NATS_OK;
}
nats_status
natsQueue_Destroy( natsQueue queue )
{
  API_CHECK();
  return api_status( nats_api->destroy_queue( queue, NULL, NULL ) );
}
nats_status
natsQueue_DestroyEx( natsQueue queue,  natsQueueOnComplete cb,
                     const void *closure )
{
  API_CHECK();
  return api_status( nats_api->destroy_queue( queue, (ApiQueueOnComplete) cb,
                                              closure ) );
}
nats_status
natsQueue_TimedDispatch( natsQueue queue,  double timeout )
{
  API_CHECK();
  return api_status( nats_api->timed_dispatch_queue( queue, timeout ) );
}
nats_status
natsQueue_TimedDispatchOneEvent( natsQueue queue,  double timeout )
{
  API_CHECK();
  return api_status( nats_api->timed_dispatch_one_event( queue, timeout ) );
}
nats_status
natsQueue_Dispatch( natsQueue queue )
{
  return natsQueue_TimedDispatch( queue, NATS_WAIT_FOREVER );
}
nats_status
natsQueue_Poll( natsQueue queue )
{
  return natsQueue_TimedDispatch( queue, NATS_NO_WAIT );
}
nats_status
natsQueue_GetCount( natsQueue queue,  uint32_t *num_events )
{
  API_CHECK();
  return api_status( nats_api->get_queue_count( queue, *num_events ) );
}
nats_status
natsQueue_SetPriority( natsQueue queue,  uint32_t priority )
{
  API_CHECK();
  ApiQueue * q = nats_api->get_queue( queue );
  if ( q == NULL || q->done )
    return NATS_INVALID_QUEUE;
  q->priority = priority;
  if ( q->grp != NULL )
    q->grp->update = true;
  return NATS_OK;
}
nats_status
natsQueue_GetPriority( natsQueue queue,  uint32_t *priority )
{
  API_CHECK();
  ApiQueue * q = nats_api->get_queue( queue );
  if ( q == NULL )
    return NATS_INVALID_QUEUE;
  *priority = q->priority;
  return NATS_OK;
}
nats_status
natsQueue_SetName( natsQueue queue,  const char *name )
{
  API_CHECK();
  ApiQueue * q = nats_api->get_queue( queue );
  if ( q == NULL )
    return NATS_INVALID_QUEUE;
  ApiCore::set_string( q->name, name );
  return NATS_OK;
}
nats_status
natsQueue_GetName( natsQueue queue,  const char **name )
{
  API_CHECK();
  ApiQueue * q = nats_api->get_queue( queue );
  if ( q == NULL )
    return NATS_INVALID_QUEUE;
  *name = q->name;
  return NATS_OK;
}

nats_status
natsQueueGroup_Create( natsQueueGroup *grp )
{
  API_CHECK();
  *grp = nats_api->create_queue_group()->id;
  return NATS_OK;
}
nats_status
natsQueueGroup_Destroy( natsQueueGroup grp )
{
  API_CHECK();
  return api_status( nats_api->destroy_queue_group( grp ) );
}
nats_status
natsQueueGroup_Add( natsQueueGroup grp,  natsQueue queue )
{
  API_CHECK();
  return api_status( nats_api->add_queue_group( grp, queue ) );
}
nats_status
natsQueueGroup_Remove( natsQueueGroup grp,  natsQueue queue )
{
  API_CHECK();
  return api_status( nats_api->remove_queue_group( grp, queue ) );
}
nats_status
natsQueueGroup_TimedDispatch( natsQueueGroup grp,  double timeout )
{
  API_CHECK();
  return api_status( nats_api->timed_dispatch_group( grp, timeout ) );
}

nats_status
natsDispatcher_Create( natsDispatcher *disp,  natsDispatchable able,
                       double idle_timeout )
{
  API_CHECK();
  ApiDispatcher * d = nats_api->create_dispatcher( able, idle_timeout );
  *disp = d->id;
  return NATS_OK;
}
nats_status
natsDispatcher_Join( natsDispatcher disp )
{
  API_CHECK();
  return api_status( nats_api->join_dispatcher( disp ) );
}
nats_status
natsDispatcher_Destroy( natsDispatcher disp )
{
  API_CHECK();
  ApiDispatcher * d = nats_api->get_dispatcher( disp );
  if ( d == NULL )
    return NATS_INVALID_DISPATCHER;
  d->quit = true;
  return NATS_OK;
}
nats_status
natsDispatcher_SetName( natsDispatcher disp,  const char *name )
{
  API_CHECK();
  ApiDispatcher * d = nats_api->get_dispatcher( disp );
  if ( d == NULL )
    return NATS_INVALID_DISPATCHER;
  ApiCore::set_string( d->name, name );
  return NATS_OK;
}
nats_status
natsDispatcher_GetName( natsDispatcher disp,  const char **name )
{
  API_CHECK();
  ApiDispatcher * d = nats_api->get_dispatcher( disp );
  if ( d == NULL )
    return NATS_INVALID_DISPATCHER;
  *name = d->name;
  return NATS_OK;
}

nats_status
natsEvent_CreateQueueListener( natsEvent *event,  natsQueue queue,
                               natsTransport tport,  const char *subject,
                               const char *queue_group,  int flags,
                               natsEventCallback cb,  const void *closure )
{
  API_CHECK();
  *event = NATS_INVALID_ID;
  api_Transport * t = nats_api->get_tport( tport );
  if ( t == NULL || t->is_destroyed )
    return NATS_INVALID_TRANSPORT;
  if ( nats_api->get_queue( queue ) == NULL )
    return NATS_INVALID_QUEUE;
  if ( cb == NULL )
    return NATS_INVALID_ARG;
  size_t len, qlen = 0;
  if ( ! valid_subject( subject, len ) )
    return NATS_INVALID_SUBJECT;
  if ( queue_group != NULL && queue_group[ 0 ] != '\0' &&
       ! valid_subject( queue_group, qlen ) )
    return NATS_INVALID_ARG;

  api_Listener * l = nats_api->make<api_Listener>( NATS_ELEM_LISTENER );
  l->subject = ::strdup( subject );
  l->len     = (uint16_t) len;
  l->hash    = kv_crc_c( subject, len, 0 );
  l->cb      = cb;
  l->cl      = closure;
  l->queue   = queue;
  l->tport   = tport;
  l->flags   = flags;
  l->is_wild = ( t->client.is_wildcard( subject, len ) != NULL );
  if ( qlen > 0 ) {
    l->queue_group     = ::strdup( queue_group );
    l->queue_group_len = (uint16_t) qlen;
  }
  ListenOp op( *t, *l, 0 );
  pthread_mutex_lock( &t->mutex );
  nats_api->ev_read->exec( op );
  pthread_mutex_unlock( &t->mutex );
  *event = l->id;
  return NATS_OK;
}

nats_status
natsEvent_CreateListener( natsEvent *event,  natsQueue queue,
                          natsTransport tport,  const char *subject,
                          int flags,  natsEventCallback cb,
                          const void *closure )
{
  return natsEvent_CreateQueueListener( event, queue, tport, subject, NULL,
                                        flags, cb, closure );
}

nats_status
natsEvent_CreateTimer( natsEvent *event,  natsQueue queue,
                       natsEventCallback cb,  double interval,
                       const void *closure )
{
  API_CHECK();
  uint32_t  id;
  ApiStatus st = nats_api->create_timer( id, queue, (void *) cb, interval,
                                         closure );
  *event = ( st == API_OK ? id : NATS_INVALID_ID );
  return api_status( st );
}

nats_status
natsEvent_Destroy( natsEvent event )
{
  API_CHECK();
  natsEventType type;
  nats_status st = natsEvent_GetType( event, &type );
  if ( st != NATS_OK )
    return st;
  switch ( type ) {
    case NATS_TIMER_EVENT: {
      api_Timer * t = nats_api->destroy_timer( event );
      if ( t == NULL )
        return NATS_INVALID_EVENT;
      delete t;
      return NATS_OK;
    }
    case NATS_LISTEN_EVENT:
    case NATS_TRANSPORT_EVENT: {
      api_Listener * l = nats_api->rem<api_Listener>( event, NATS_ELEM_LISTENER );
      if ( l == NULL )
        return NATS_INVALID_EVENT;
      api_Transport * t = nats_api->get_tport( l->tport );
      l->cb = NULL;
      if ( t != NULL ) {
        if ( l->is_state ) {
          pthread_mutex_lock( &t->mutex );
          if ( t->state_listener == l )
            t->state_listener = NULL;
          pthread_mutex_unlock( &t->mutex );
        }
        else {
          ListenOp op( *t, *l, 1 );
          pthread_mutex_lock( &t->mutex );
          nats_api->ev_read->exec( op );
          pthread_mutex_unlock( &t->mutex );
        }
      }
      delete l;
      return NATS_OK;
    }
  }
  return NATS_INVALID_EVENT;
}

nats_status
natsEvent_GetType( natsEvent event,  natsEventType *type )
{
  API_CHECK();
  nats_status st = NATS_INVALID_EVENT;
  pthread_mutex_lock( &nats_api->map_mutex );
  if ( event < nats_api->map_size && nats_api->map[ event ].id == event &&
       nats_api->map[ event ].ptr != NULL ) {
    switch ( nats_api->map[ event ].type ) {
      case NATS_ELEM_TIMER:
        *type = NATS_TIMER_EVENT; st = NATS_OK; break;
      case NATS_ELEM_LISTENER:
        *type = ( ((api_Listener *) nats_api->map[ event ].ptr)->is_state
                  ? NATS_TRANSPORT_EVENT : NATS_LISTEN_EVENT );
        st = NATS_OK; break;
      default: break;
    }
  }
  pthread_mutex_unlock( &nats_api->map_mutex );
  return st;
}

nats_status
natsEvent_GetQueue( natsEvent event,  natsQueue *queue )
{
  API_CHECK();
  *queue = NATS_INVALID_ID;
  pthread_mutex_lock( &nats_api->map_mutex );
  if ( event < nats_api->map_size && nats_api->map[ event ].id == event &&
       nats_api->map[ event ].ptr != NULL ) {
    switch ( nats_api->map[ event ].type ) {
      case NATS_ELEM_TIMER:
        *queue = ((api_Timer *) nats_api->map[ event ].ptr)->queue; break;
      case NATS_ELEM_LISTENER:
        *queue = ((api_Listener *) nats_api->map[ event ].ptr)->queue; break;
      case NATS_ELEM_QUEUE:
        *queue = event; break;
      default: break;
    }
  }
  pthread_mutex_unlock( &nats_api->map_mutex );
  return *queue != NATS_INVALID_ID ? NATS_OK : NATS_INVALID_EVENT;
}

nats_status
natsEvent_GetListenerSubject( natsEvent event,  const char **subject )
{
  API_CHECK();
  api_Listener * l = nats_api->get_listener( event );
  if ( l == NULL )
    return NATS_INVALID_EVENT;
  *subject = l->subject;
  return NATS_OK;
}

nats_status
natsEvent_GetListenerTransport( natsEvent event,  natsTransport *tport )
{
  API_CHECK();
  api_Listener * l = nats_api->get_listener( event );
  if ( l == NULL )
    return NATS_INVALID_EVENT;
  *tport = l->tport;
  return NATS_OK;
}

nats_status
natsEvent_GetTimerInterval( natsEvent event,  double *interval )
{
  API_CHECK();
  return api_status( nats_api->get_timer_interval( event, *interval ) );
}

nats_status
natsEvent_ResetTimerInterval( natsEvent event,  double interval )
{
  API_CHECK();
  return api_status( nats_api->reset_timer_interval( event, interval ) );
}

#define MSG_CHECK() if ( msg == NULL ) return NATS_INVALID_MSG

nats_status
natsMsg_GetSubject( natsMsg msg,  const char **subject )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  *subject = ( m->subject != NULL ? m->subject : "" );
  return NATS_OK;
}
nats_status
natsMsg_GetReplySubject( natsMsg msg,  const char **reply )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  *reply = ( m->reply != NULL ? m->reply : "" );
  return NATS_OK;
}
nats_status
natsMsg_GetEvent( natsMsg msg,  natsEvent *event )
{
  MSG_CHECK();
  *event = ((api_Msg *) msg)->event;
  return NATS_OK;
}
nats_status
natsMsg_GetClosure( natsMsg msg,  void **closure )
{
  MSG_CHECK();
  *closure = (void *) ((api_Msg *) msg)->cl;
  return NATS_OK;
}
nats_status
natsMsg_GetMsgClass( natsMsg msg,  natsMsgClass *msg_class )
{
  MSG_CHECK();
  *msg_class = (natsMsgClass) ((api_Msg *) msg)->msg_class;
  return NATS_OK;
}
nats_status
natsMsg_GetStatusText( natsMsg msg,  const char **text )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  *text = ( m->status_text != NULL ? m->status_text : "" );
  return NATS_OK;
}
nats_status
natsMsg_GetRecvTime( natsMsg msg,  int64_t *recv_ns )
{
  MSG_CHECK();
  *recv_ns = ((api_Msg *) msg)->recv_ns;
  return NATS_OK;
}
nats_status
natsMsg_GetData( natsMsg msg,  const void **buf,  uint32_t *len )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  *buf = m->data;
  *len = m->data_len;
  return NATS_OK;
}
nats_status
natsMsg_GetMsgEnc( natsMsg msg,  uint32_t *msg_enc )
{
  MSG_CHECK();
  *msg_enc = ((api_Msg *) msg)->get_enc();
  return NATS_OK;
}
nats_status
natsMsg_Detach( natsMsg msg )
{
  MSG_CHECK();
  __sync_fetch_and_add( &((api_Msg *) msg)->refs, 1 );
  return NATS_OK;
}
nats_status
natsMsg_Destroy( natsMsg msg )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  if ( m->refs == 0 )
    return NATS_INVALID_MSG;
  if ( __sync_sub_and_fetch( &m->refs, 1 ) == 0 && ! m->in_queue )
    delete m;
  return NATS_OK;
}
nats_status
natsMsg_Print( natsMsg msg,  void *fp )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  FILE    * f = ( fp != NULL ? (FILE *) fp : stdout );
  if ( m->msg_class != NATS_MSG_DATA ) {
    fprintf( f, "%s: %s%s%s\n", m->subject != NULL ? m->subject : "",
             m->msg_class == NATS_MSG_TRANSPORT_UP ? "TRANSPORT_UP" :
             m->msg_class == NATS_MSG_TRANSPORT_DOWN ? "TRANSPORT_DOWN" : "?",
             m->status_text != NULL ? " " : "",
             m->status_text != NULL ? m->status_text : "" );
    return NATS_OK;
  }
  fprintf( f, "%s:%s%s len=%u enc=0x%x\n", m->subject != NULL ? m->subject : "",
           m->reply != NULL ? " reply=" : "", m->reply != NULL ? m->reply : "",
           m->data_len, m->get_enc() );
  if ( m->data_len == 0 )
    return NATS_OK;
  MDMsgMem tmp;
  MDMsg  * dm = MDMsg::unpack( m->data, 0, m->data_len, 0, NULL, tmp );
  MDOutput out;
  out.filep = f; /* print() writes through filep, stdout when NULL */
  if ( dm == NULL )
    out.print_hex( m->data, m->data_len );
  else
    dm->print( &out );
  out.filep = NULL;
  return NATS_OK;
}

nats_status
natsMsg_Create( natsMsg *msg )
{
  api_Msg * m = new ( ::malloc( sizeof( api_Msg ) ) ) api_Msg( 0, NULL );
  m->refs     = 1;     /* owned by the caller, natsMsg_Destroy frees */
  m->in_queue = false;
  m->enc_done = true;
  *msg = (natsMsg) m;
  return NATS_OK;
}
nats_status
natsMsg_SetSendSubject( natsMsg msg,  const char *subject )
{
  MSG_CHECK();
  size_t len;
  if ( ! valid_subject( subject, len ) )
    return NATS_INVALID_SUBJECT;
  ((api_Msg *) msg)->set_subject( subject, len );
  return NATS_OK;
}
nats_status
natsMsg_SetReplySubject( natsMsg msg,  const char *reply )
{
  MSG_CHECK();
  api_Msg * m = (api_Msg *) msg;
  size_t len;
  if ( reply == NULL || reply[ 0 ] == '\0' ) {
    m->reply     = NULL;
    m->reply_len = 0;
    return NATS_OK;
  }
  if ( ! valid_subject( reply, len ) )
    return NATS_INVALID_SUBJECT;
  m->set_reply( reply, len );
  return NATS_OK;
}
nats_status
natsMsg_SetData( natsMsg msg,  const void *buf,  uint32_t len,
                 uint32_t msg_enc )
{
  MSG_CHECK();
  if ( buf == NULL && len != 0 )
    return NATS_INVALID_ARG;
  api_Msg * m = (api_Msg *) msg;
  m->set_data( buf, len, msg_enc );
  m->enc_done = true;
  return NATS_OK;
}

} /* extern "C" */
