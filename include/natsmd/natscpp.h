#ifndef __rai__natsmd__natscpp_h__
#define __rai__natsmd__natscpp_h__
  
#include <raikv/ev_api_queue.h>
#include <natsmd/natsapi.h>
  
using namespace rai;
using namespace md;
using namespace kv;
using namespace natsmd;
  
namespace natsapi {

enum ElemType {   
  NATS_ELEM_TIMER       = API_ELEM_TIMER,
  NATS_ELEM_LISTENER    = API_ELEM_LISTENER, 
  NATS_ELEM_QUEUE       = API_ELEM_QUEUE,
  NATS_ELEM_QUEUE_GROUP = API_ELEM_QUEUE_GROUP,
  NATS_ELEM_TRANSPORT   = API_ELEM_TRANSPORT,
  NATS_ELEM_DISPATCHER  = API_ELEM_DISPATCHER
};    
      
struct Nats_API;
struct api_Transport;
struct api_Listener;
struct api_Msg;
typedef ApiTimer api_Timer;

static const double   DEFAULT_RECONNECT_SECS = 1.0;
static const uint64_t RECONNECT_TIMER_ID     = 0x0772;
static const size_t   MAX_SUBJECT_LEN        = 0xfff0;
  
struct api_Listener {
  api_Listener    * next, * back;
  char            * subject,
                  * queue_group; /* NATS queue group, NULL = none */
  const void      * cl;
  natsEventCallback cb;
  natsEvent         id;
  natsQueue         queue;
  natsTransport     tport;
  uint32_t          hash;
  uint16_t          len,
                    queue_group_len;
  int               flags;      /* NATS_LISTEN_* */
  bool              done,       /* destroyed */
                    is_state,   /* transport state listener, not a sub */
                    is_wild,    /* subject has a wildcard */
                    is_inbox;   /* _INBOX.<session>.<n>: covered by the
                                 * transport's inbox pattern, no SUB */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  api_Listener( Nats_API &,  natsId i ) : next( 0 ), back( 0 ), subject( 0 ),
    queue_group( 0 ), cl( 0 ), cb( 0 ), id( i ), queue( 0 ), tport( 0 ),
    hash( 0 ), len( 0 ), queue_group_len( 0 ), flags( 0 ), done( false ),
    is_state( false ), is_wild( false ), is_inbox( false ) {}
  ~api_Listener() {
    if ( this->subject != NULL )     ::free( this->subject );
    if ( this->queue_group != NULL ) ::free( this->queue_group );
  }
  bool same_subject( const char *s,  size_t l ) const {
    return this->len == l && ::memcmp( this->subject, s, l ) == 0;
  }
  bool same_subject( const api_Listener &l ) const {
    return this->hash == l.hash && this->same_subject( l.subject, l.len );
  }
  bool live( void ) const { return ! this->done && ! this->is_state; }
};
typedef DLinkList< api_Listener > ListenerList;

/* subject hash -> listeners (several listeners may share a subject) */
struct ListenerHT {
  ListenerList * ht;
  size_t         mask, count;
  ListenerHT() : ht( 0 ), mask( 0 ), count( 0 ) {}
  void init( size_t sz ) {
    this->mask  = sz - 1;
    this->count = 0;
    sz *= sizeof( this->ht[ 0 ] );
    this->ht = (ListenerList *) ::malloc( sz );
    ::memset( (void *) this->ht, 0, sz );
  }
  void resize( void ) {
    size_t sz = this->mask + 1;
    ListenerList * oht = this->ht;
    this->init( oht == NULL ? 16 : sz * 2 );
    if ( oht != NULL ) {
      for ( size_t i = 0; i < sz; i++ )
        while ( ! oht[ i ].is_empty() )
          this->push( oht[ i ].pop_hd() );
      ::free( oht );
    }
  }
  void push( api_Listener *l ) {
    if ( this->count >= this->mask )
      this->resize();
    this->ht[ l->hash & this->mask ].push_tl( l );
    this->count++;
  }
  void remove( api_Listener *l ) {
    this->ht[ l->hash & this->mask ].pop( l );
    this->count--;
  }
  ListenerList *bucket( uint32_t h ) {
    return this->ht == NULL ? NULL : &this->ht[ h & this->mask ];
  }
  /* another live listener on the same subject, other than x: those share
   * the one subscription */
  bool other_live( api_Listener *x ) {
    ListenerList * b = this->bucket( x->hash );
    if ( b != NULL ) {
      for ( api_Listener *l = b->hd; l != NULL; l = l->next )
        if ( l != x && l->live() && l->same_subject( *x ) )
          return true;
    }
    return false;
  }
};

struct api_Msg {
  natsEvent    event;
  const void * cl;
  uint32_t     refs;         /* detach count; 0 = freed after dispatch */
  bool         in_queue,
               enc_done;
  char       * subject,
             * reply,
             * status_text;
  uint16_t     subject_len,
               reply_len;
  uint8_t      msg_class;    /* natsMsgClass */
  int64_t      recv_ns;
  uint8_t    * data;
  uint32_t     data_len,
               data_cap,
               msg_enc;
  MDMsgMem     mem;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  api_Msg( natsEvent ev,  const void *c )
    : event( ev ), cl( c ), refs( 0 ), in_queue( true ), enc_done( false ),
      subject( 0 ), reply( 0 ), status_text( 0 ), subject_len( 0 ),
      reply_len( 0 ), msg_class( NATS_MSG_DATA ), recv_ns( 0 ), data( 0 ),
      data_len( 0 ), data_cap( 0 ), msg_enc( 0 ) {}

  char *copy_str( const void *s,  size_t l ) {
    char * p = (char *) this->mem.make( l + 1 );
    if ( l > 0 )
      ::memcpy( p, s, l );
    p[ l ] = '\0';
    return p;
  }
  void set_subject( const char *s,  size_t l ) {
    this->subject     = this->copy_str( s, l );
    this->subject_len = (uint16_t) l;
  }
  void set_reply( const void *s,  size_t l ) {
    this->reply     = this->copy_str( s, l );
    this->reply_len = (uint16_t) l;
  }
  void set_text( const char *s,  size_t l ) {
    this->status_text = this->copy_str( s, l );
  }
  void set_data( const void *b,  size_t l,  uint32_t enc ) {
    if ( l > this->data_cap ) {
      this->data     = (uint8_t *) this->mem.make( l );
      this->data_cap = (uint32_t) l;
    }
    if ( l > 0 )
      ::memcpy( this->data, b, l );
    this->data_len = (uint32_t) l;
    this->msg_enc  = enc;
    this->enc_done = ( enc != 0 );
  }
  /* a received publish: copy subject, reply and payload */
  static api_Msg *make( api_Listener &l,  EvPublish &pub ) noexcept;
  /* a synthesized transport state message */
  static api_Msg *make_status( api_Listener &l,  uint8_t msg_class,
                               const char *text ) noexcept;
  /* the raimd codec id of the payload, detected from the bytes */
  uint32_t get_enc( void ) noexcept {
    if ( ! this->enc_done ) {
      this->enc_done = true;
      if ( this->data_len > 0 )
        this->msg_enc = MDMsg::is_msg_type( this->data, 0, this->data_len, 0 );
    }
    return this->msg_enc;
  }
  bool release( void ) noexcept; /* after dispatch; true when freed */
};

struct api_Transport : public EvConnectionNotify, public NatsClientCB,
                       public EvTimerCallback {
  Nats_API      & api;
  natsTransport   id;
  EvNatsClient    client;
  ListenerHT      ht;
  api_Listener ** wild;        /* the wildcard listeners */
  size_t          wild_cnt,
                  wild_size;
  api_Listener  * state_listener;
  pthread_mutex_t mutex;
  pthread_cond_t  cond;
  char          * daemon, * name, * user, * password, * auth_token, * descr;
  double          reconnect_secs;
  uint32_t        advisory,     /* natsTransportParams::advisory */
                  inbox_count,
                  dup_hash,     /* consecutive copies of one publish, one */
                  dup_len,      /* per matching subscription: subject hash, */
                  dup_crc,      /* length and payload crc of the first, */
                  dup_skip;     /* copies still to drop */
  bool            connected,
                  is_destroyed,
                  timer_armed,
                  connect_failed;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { aligned_free( ptr ); }
  api_Transport( Nats_API &a,  natsId i ) noexcept;
  ~api_Transport() {
    ApiCore::set_string( this->daemon, NULL );
    ApiCore::set_string( this->name, NULL );
    ApiCore::set_string( this->user, NULL );
    ApiCore::set_string( this->password, NULL );
    ApiCore::set_string( this->auth_token, NULL );
    ApiCore::set_string( this->descr, NULL );
    if ( this->wild != NULL )
      ::free( this->wild );
  }
  void set_params( const natsTransportParams &p ) noexcept;
  EvNatsClientParameters client_params( void ) noexcept {
    EvNatsClientParameters p( this->daemon, this->name, this->user,
                              this->password, this->auth_token );
    p.advisory = this->advisory;
    return p;
  }
  /* epoll thread */
  bool connect( void ) noexcept;
  void add_wild( api_Listener &l ) noexcept;
  void remove_wild( api_Listener &l ) noexcept;
  void start_sub( api_Listener &l ) noexcept;
  void stop_sub( api_Listener &l ) noexcept;
  void subscribe_inbox( void ) noexcept;
  void push_state( uint8_t msg_class,  const char *text ) noexcept;
  void arm_reconnect( void ) noexcept;

  virtual void on_connect( EvSocket &conn ) noexcept;
  virtual void on_shutdown( EvSocket &conn,  const char *err,
                            size_t err_len ) noexcept;
  virtual bool on_nats_msg( EvPublish &pub ) noexcept;
  virtual bool timer_cb( uint64_t timer_id,  uint64_t event_id ) noexcept;
};

struct api_Queue : public ApiQueue {
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  api_Queue( Nats_API &a,  natsId i );
};

struct Nats_API : public ApiCore {
  api_Queue * default_queue;
  void * operator new( size_t, void *ptr ) { return ptr; }
  Nats_API() : ApiCore( 11 ), default_queue( 0 ) {}

  template<class T>
  T *make( ElemType type,  size_t add = 0,  natsId id = 0 ) {
    return this->ApiCore::make<T, Nats_API>( *this, (uint32_t) type, add, id,
                                             type == NATS_ELEM_TRANSPORT );
  }
  virtual void dispatch_event( ApiQueueEvent &ev ) noexcept;

  nats_status open( void ) noexcept;
  api_Transport *get_tport( natsTransport t ) {
    return this->get<api_Transport>( t, NATS_ELEM_TRANSPORT );
  }
  api_Listener *get_listener( natsEvent e ) {
    return this->get<api_Listener>( e, NATS_ELEM_LISTENER );
  }
  /* push a message for listener l on its queue */
  void deliver( api_Listener &l,  api_Msg *m ) noexcept {
    if ( m == NULL )
      return;
    if ( ! this->queue_push( l.queue, l.id, (void *) l.cb, NULL, l.cl, m ) )
      delete m;
  }
};

struct TportOp : public ApiOp {
  api_Transport & t;
  int             what; /* 0 connect, 1 close */
  TportOp( api_Transport &tp,  int w )
    : ApiOp( &tp.mutex, &tp.cond ), t( tp ), what( w ) {}
  virtual void run( ApiPipe & ) noexcept {
    if ( this->what == 0 )
      this->t.connect();
    else {
      this->t.is_destroyed = true;
      this->t.api.poll.timer.remove_timer_cb( this->t, RECONNECT_TIMER_ID,
                                              this->t.id );
      if ( this->t.client.fd != -1 ) {
        if ( this->t.client.adv_started ) /* STOP, then flush and close */
          this->t.client.do_shutdown();
        else
          this->t.client.idle_push( EV_CLOSE );
      }
    }
  }
};

struct ListenOp : public ApiOp {
  api_Transport & t;
  api_Listener  & l;
  int             what; /* 0 start, 1 stop */
  ListenOp( api_Transport &tp,  api_Listener &ln,  int w )
    : ApiOp( &tp.mutex, &tp.cond ), t( tp ), l( ln ), what( w ) {}
  virtual void run( ApiPipe & ) noexcept {
    if ( this->what == 0 ) {
      this->l.is_inbox = ( this->t.client.session_len != 0 &&
                           this->t.client.is_inbox( this->l.subject,
                                                    this->l.len ) != 0 );
      bool first = ! this->t.ht.other_live( &this->l );
      this->t.ht.push( &this->l );
      if ( this->l.is_wild )
        this->t.add_wild( this->l );
      if ( this->t.connected && first )
        this->t.start_sub( this->l );
    }
    else {
      this->t.ht.remove( &this->l );
      if ( this->l.is_wild )
        this->t.remove_wild( this->l );
      if ( ! this->l.done )
        this->t.stop_sub( this->l );
      this->l.done = true;
    }
  }
};

struct SendOp : public ApiOp {
  api_Transport & t;
  EvPublish     & pub;
  bool            sent;
  SendOp( api_Transport &tp,  EvPublish &p )
    : ApiOp( &tp.mutex, &tp.cond ), t( tp ), pub( p ), sent( false ) {}
  virtual void run( ApiPipe & ) noexcept {
    if ( this->t.connected && this->t.client.fd != -1 ) {
      this->t.client.publish( this->pub );
      this->sent = true;
    }
  }
};

}

#endif
