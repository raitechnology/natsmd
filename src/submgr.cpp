#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <natsmd/ev_nats_client.h>
#include <natsmd/submgr.h>
#include <raikv/ev_publish.h>
#include <raimd/md_msg.h>
#include <raimd/md_field_iter.h>
#include <raimd/rv_msg.h>
#include <raimd/tib_msg.h>

using namespace rai;
using namespace kv;
using namespace natsmd;
using namespace md;

#define SARG( str ) str, sizeof( str )
static const uint64_t NS = 1000 * 1000 * 1000;

namespace {
static const char session_start[]  = "_NATS.START.>",
                  session_status[] = "_NATS.STATUS.>",
                  session_stop[]   = "_NATS.STOP.>",
                  listen_start[]   = "_NATS.LISTEN.START.>",
                  listen_stop[]    = "_NATS.LISTEN.STOP.>",
                  snap[]           = "_SNAP.>",
                  tic_reply[]      = "_TIC.REPLY.>";
enum SubKind {
  IS_SESSION_START  = 0,
  IS_SESSION_STATUS = 1,
  IS_SESSION_STOP   = 2,
  IS_LISTEN_START   = 3,
  IS_LISTEN_STOP    = 4,
  IS_SNAP           = 5,
  IS_TIC_REPLY      = 6,
  MAX_SUB_KIND      = 7
};

struct SubMatch {
  const char * sub;
  uint32_t     len;
  SubKind      kind;
};

static const SubMatch nats_info_sub[ MAX_SUB_KIND ] = {
{ session_start , sizeof( session_start ) - 1 , IS_SESSION_START },
{ session_status, sizeof( session_status ) - 1, IS_SESSION_STATUS },
{ session_stop  , sizeof( session_stop ) - 1  , IS_SESSION_STOP },
{ listen_start  , sizeof( listen_start ) - 1  , IS_LISTEN_START },
{ listen_stop   , sizeof( listen_stop ) - 1   , IS_LISTEN_STOP },
{ snap          , sizeof( snap ) - 1          , IS_SNAP },
{ tic_reply     , sizeof( tic_reply ) - 1     , IS_TIC_REPLY }
};

/* match the prefix without the '>', at least one char must follow */
static const SubMatch *
match_nats_info( const char *sub,  size_t sub_len ) noexcept
{
  for ( int i = 0; i < MAX_SUB_KIND; i++ ) {
    const SubMatch & m = nats_info_sub[ i ];
    if ( sub_len >= m.len && ::memcmp( sub, m.sub, m.len - 1 ) == 0 )
      return &m;
  }
  return NULL;
}

static char * hms( time_t t,  char *buf ) noexcept {
  struct tm tm;
  md_localtime( t, &tm );
  ::snprintf( buf, 32, "%02d:%02d:%02d (%u)",
              tm.tm_hour, tm.tm_min, tm.tm_sec, (uint32_t) ( t % 3600 ) );
  return buf;
}

static const char *session_state_str[] = {
  "unknown", "start", "query", "stop", "self"
};
#if __cplusplus >= 201103L
static_assert( MAX_NATS_SESSION_STATE == ( sizeof( session_state_str ) / sizeof( session_state_str[ 0 ] ) ), "session_state_str" );
#endif

/* strip the nul that rv strings carry */
static inline void
strip_nul( char *s,  size_t &len ) {
  if ( s != NULL && len > 0 && s[ len - 1 ] == '\0' )
    len--;
}
}

const char *rai::natsmd::NatsSessionEntry::get_session_state_str( SessionState s ) noexcept {
  return s < MAX_NATS_SESSION_STATE ? session_state_str[ s ] : "bad session state"; }

NatsSubscriptionDB::NatsSubscriptionDB( EvNatsClient &c,
                                        NatsSubscriptionListener *sl ) noexcept
              : client( c ), cb( sl ), sess_ht( 0 ), cur_mono( 0 ),
                next_session_ctr( 0 ), next_subject_ctr( 0 ), next_gc( 0 ),
                session_inbox_base( 1000 ), is_subscribed( false ),
                is_all_subscribed( false ), is_snap( false ), is_tic( false ),
                mout( 0 )
{
}

void
NatsSubscriptionDB::release( void ) noexcept
{
  RouteLoc loc;
  uint32_t i;
  for ( NatsSessionEntry *entry = this->session_tab.first( loc );
        entry != NULL; entry = this->session_tab.next( loc ) ) {
    if ( entry->state != NatsSessionEntry::NATS_SESSION_STOP )
      entry->stop( 0 );
  }
  for ( i = 0; i < this->filters.count; i++ ) {
    Filter &f = this->filters.ptr[ i ];
    if ( f.wild != NULL ) {
      ::free( f.wild );
      f.wild = NULL;
    }
  }
  this->session_tab.release();
  this->sub_tab.release();
  this->filters.clear();
  if ( this->sess_ht != NULL )
    delete this->sess_ht;

  this->cur_mono          = 0;
  this->next_session_ctr  = 0;
  this->next_subject_ctr  = 0;
  this->next_gc           = 0;
  this->sess_ht           = NULL;
  this->is_subscribed     = false;
  this->is_all_subscribed = false;
  this->is_snap           = false;
  this->is_tic            = false;
  this->subscriptions.reset();
  this->sessions.reset();
}

uint32_t
NatsSubscriptionDB::next_session_id( void ) noexcept
{
  return ++this->next_session_ctr;
}

uint32_t
NatsSubscriptionDB::next_subject_id( void ) noexcept
{
  return kv_hash_uint( ++this->next_subject_ctr );
}

void NatsSubscriptionListener::on_listen_start( Start & ) noexcept {}
void NatsSubscriptionListener::on_listen_stop ( Stop  & ) noexcept {}
void NatsSubscriptionListener::on_snapshot    ( Snap  & ) noexcept {}
void NatsSubscriptionListener::on_tic_reply   ( Tic   & ) noexcept {}

void
NatsSubscriptionDB::add_wildcard( const char *wildcard ) noexcept
{
  size_t len    = ( wildcard == NULL ? 0 : ::strlen( wildcard ) ),
         suflen = ( len == 0 ? 1 :
                    wildcard[ len - 1 ] != '>' ) ? 2 : 0;
  char * s   = (char *) ::malloc( len + suflen + 1 );
  Filter &f = this->filters.push();
  if ( len > 0 )
    ::memcpy( s, wildcard, len );
  if ( suflen > 0 ) {
    if ( suflen == 2 && len > 0 )
      s[ len++ ] = '.';
    s[ len++ ] = '>';
  }
  s[ len ] = '\0';
  f.wild     = s;
  f.wild_len = len;
}

bool
NatsSubscriptionDB::is_matched( const char *sub,  size_t sub_len ) noexcept
{
  if ( this->filters.count == 0 )
    return true;
  for ( size_t i = 0; i < this->filters.count; i++ ) {
    if ( match_nats_wildcard( this->filters[ i ].wild,
                              this->filters[ i ].wild_len,
                              sub, sub_len ) )
      return true;
  }
  return false;
}

void
NatsSubscriptionDB::start_subscriptions( bool all,  bool snap,
                                         bool tic ) noexcept
{
  if ( this->is_subscribed )
    return;
  this->sess_ht           = kv::UIntHashTab::resize( NULL );
  this->is_subscribed     = true;
  this->is_all_subscribed = all;
  this->is_snap           = snap;
  this->is_tic            = tic;
  this->cur_mono          = this->client.poll.mono_ns / NS;
  this->next_gc           = this->cur_mono + 131;
  /* the SUBS replies arrive on _INBOX.<session>.<n> */
  if ( this->client.session_len == 0 )
    this->client.make_session();
  this->do_subscriptions( true );

  /* the monitor publishes advisories too, ignore its own LISTENs */
  if ( this->client.advisory )
    this->session_start( this->client.session, this->client.session_len,
                         true, "self", 4 );
}

void
NatsSubscriptionDB::stop_subscriptions( void ) noexcept
{
  if ( ! this->is_subscribed )
    return;
  this->is_subscribed = false;
  this->do_subscriptions( false );
}

void
NatsSubscriptionDB::do_subscriptions( bool is_subscribe ) noexcept
{
  const char * un = ( is_subscribe ? "" : "un" );

  for ( int i = 0; i < MAX_SUB_KIND; i++ ) {
    const SubMatch & match = nats_info_sub[ i ];

    if ( i == IS_SNAP ) {
      if ( ! this->is_snap )
        continue;
      if ( ! this->is_all_subscribed ) {
        for ( size_t j = 0; j < this->filters.count; j++ )
          this->do_wild_subscription( this->filters.ptr[ j ], is_subscribe, i );
        continue;
      }
    }
    else if ( i == IS_TIC_REPLY ) {
      if ( ! this->is_tic )
        continue;
    }
    /* the session advisories can't be filtered, the subject is in the body */
    if ( this->mout != NULL )
      this->mout->printf( "%ssubscribe (%.*s)\n", un, match.len, match.sub );
    if ( is_subscribe )
      this->client.subscribe( match.sub, match.len, NULL, 0 );
    else
      this->client.unsubscribe( match.sub, match.len );
  }
  this->client.idle_push_write();
}

void
NatsSubscriptionDB::do_wild_subscription( Filter &f,  bool is_subscribe,
                                          int k ) noexcept
{
  const char     * un    = ( is_subscribe ? "" : "un" );
  const SubMatch & match = nats_info_sub[ k ];
  size_t           len   = f.wild_len + match.len;
  CatMalloc        sub( len + 1 );

  /* _SNAP.RSF.> */
  sub.b( match.sub, match.len - 1 ) /* strip '>' */
     .b( f.wild, f.wild_len );
  sub.end();

  if ( this->mout != NULL )
    this->mout->printf( "%ssubscribe (%s)\n", un, sub.start );

  if ( is_subscribe )
    this->client.subscribe( sub.start, sub.len(), NULL, 0 );
  else
    this->client.unsubscribe( sub.start, sub.len() );
}

size_t
NatsSubscriptionDB::sub_hash_count( const char *sub,  size_t sub_len,
                                    uint32_t sub_hash ) noexcept
{
  RouteLoc loc;
  size_t   cnt  = 0;
  bool     is_w = ( is_nats_wildcard( sub, sub_len ) != NULL );

  NatsSubscription * script = this->sub_tab.find_by_hash( sub_hash, loc );
  for (;;) {
    if ( script == NULL )
      return cnt;
    if ( script->refcnt != 0 ) {
      bool w = ( is_nats_wildcard( script->value, script->len ) != NULL );
      if ( w == is_w )
        cnt++;
    }
    script = this->sub_tab.find_next_by_hash( sub_hash, loc );
  }
}

/* drop all of the session's subjects, notify listener, remove from sess_ht */
void
NatsSubscriptionDB::unsub_session( NatsSessionEntry &sess ) noexcept
{
  if ( this->mout != NULL )
    this->mout->printf( "> unsub session %.*s\n", (int) sess.len, sess.value );
  size_t pos;
  for ( NatsSubscription * sub = this->first_subject( sess, pos ); sub != NULL;
        sub = this->next_subject( sess, pos ) ) {
    bool coll = false;
    if ( --sub->refcnt == 0 ) {
      this->subscriptions.active--;
      this->subscriptions.removed++;
      coll = ( this->sub_hash_count( sub->value, sub->len, sub->hash ) > 0 );
    }
    if ( this->cb != NULL ) {
      NatsSubscriptionListener::Stop op( sess, *sub, false, false, coll );
      this->cb->on_listen_stop( op );
    }
  }
  if ( this->sess_ht->find( sess.session_id, pos ) )
    this->sess_ht->remove( pos );
  sess.stop( this->cur_mono );
}

/* _NATS.START.<session>: a new session or the same session reconnected,
 * a reconnect keeps the subjects, session_check() decides on a resync */
NatsSessionEntry &
NatsSubscriptionDB::session_start( const char *session_name,
                                   size_t session_len,  bool is_self,
                                   const char *u,  size_t ulen ) noexcept
{
  uint32_t           hash = kv_crc_c( session_name, session_len, 0 );
  RouteLoc           loc;
  NatsSessionEntry * entry;

  entry = this->session_tab.upsert( hash, session_name, session_len, loc );
  if ( this->mout != NULL )
    this->mout->printf( "> session start %.*s %s\n", (int) session_len,
      session_name, loc.is_new ? "new" :
      entry->state == NatsSessionEntry::NATS_SESSION_STOP ? "restart" :
      "exists" );

  if ( ! loc.is_new && entry->state != NatsSessionEntry::NATS_SESSION_STOP ) {
    entry->ref_mono   = this->cur_mono;
    entry->start_mono = this->cur_mono;
    entry->add_user( u, ulen );
    return *entry;
  }
  entry->start( this->next_session_id(), this->cur_mono, true, u, ulen );
  this->add_session( *entry );
  if ( is_self )
    entry->state = NatsSessionEntry::NATS_SESSION_SELF;
  return *entry;
}

void
NatsSubscriptionDB::session_stop( const char *session_name,
                                  size_t session_len ) noexcept
{
  if ( this->mout != NULL )
    this->mout->printf( "> session stop %.*s\n", (int) session_len,
                        session_name );
  uint32_t           hash = kv_crc_c( session_name, session_len, 0 );
  RouteLoc           loc;
  NatsSessionEntry * entry;

  entry = this->session_tab.find( hash, session_name, session_len, loc );
  if ( entry != NULL && entry->state != NatsSessionEntry::NATS_SESSION_STOP &&
       entry->state != NatsSessionEntry::NATS_SESSION_SELF )
    this->rem_session( *entry );
}

/* any advisory from a session, unknown sessions start in QUERY */
NatsSessionEntry &
NatsSubscriptionDB::session_ref( const char *session_name,
                                 size_t session_len ) noexcept
{
  uint32_t           hash = kv_crc_c( session_name, session_len, 0 );
  RouteLoc           loc;
  NatsSessionEntry * entry;

  entry = this->session_tab.upsert( hash, session_name, session_len, loc );
  if ( loc.is_new || entry->state == NatsSessionEntry::NATS_SESSION_STOP ) {
    if ( this->mout != NULL )
      this->mout->printf( "! query %.*s, unknown session\n",
                          (int) session_len, session_name );
    entry->start( this->next_session_id(), this->cur_mono, false, NULL, 0 );
    this->add_session( *entry );
  }
  entry->ref_mono = this->cur_mono;
  return *entry;
}

/* compare the peer's cn / sc / sx with what is held, resync if differ */
void
NatsSubscriptionDB::session_check( NatsSessionEntry &sess,  const char *what,
                                   bool has_cn,  uint32_t cn,  bool has_sx,
                                   uint32_t sc,  uint32_t sx ) noexcept
{
  if ( sess.state == NatsSessionEntry::NATS_SESSION_SELF ||
       sess.state == NatsSessionEntry::NATS_SESSION_STOP )
    return;
  if ( has_cn ) {
    if ( sess.conn_count != 0 && sess.conn_count != cn ) {
      if ( this->mout != NULL )
        this->mout->printf( "! %s %.*s, cn %u -> %u\n", what,
                            (int) sess.len, sess.value, sess.conn_count, cn );
      this->session_query( sess, "reconnect" );
    }
    sess.conn_count = cn;
  }
  if ( has_sx && ! sess.digest_equals( sc, sx ) ) {
    if ( this->mout != NULL )
      this->mout->printf( "! %s %.*s, sc/sx %u/%08X != %u/%08X\n", what,
                          (int) sess.len, sess.value, sess.sub_count,
                          sess.sub_digest, sc, sx );
    this->session_query( sess, "digest" );
  }
}

void
NatsSubscriptionDB::session_query( NatsSessionEntry &sess,
                                   const char *why ) noexcept
{
  if ( sess.state == NatsSessionEntry::NATS_SESSION_SELF ||
       sess.state == NatsSessionEntry::NATS_SESSION_STOP ||
       sess.state == NatsSessionEntry::NATS_SESSION_QUERY )
    return;
  sess.state = NatsSessionEntry::NATS_SESSION_QUERY;
  if ( this->mout != NULL )
    this->mout->printf( "> query %.*s, %s\n", (int) sess.len, sess.value,
                        why );
}

bool
NatsSubscriptionDB::session_seq( NatsSessionEntry &sess,  const char *what,
                                 bool has_sq,  uint32_t sq ) noexcept
{
  if ( ! has_sq || sess.state == NatsSessionEntry::NATS_SESSION_SELF )
    return true; /* a client without sq: arrival order */
  if ( sess.last_sq != 0 ) {
    if ( sq <= sess.last_sq ) {
      if ( this->mout != NULL )
        this->mout->printf( "! %s %.*s stale sq %u <= %u, dropped\n", what,
                            (int) sess.len, sess.value, sq, sess.last_sq );
      return false;
    }
    if ( sq != sess.last_sq + 1 ) {
      if ( this->mout != NULL )
        this->mout->printf( "! %s %.*s sq gap %u -> %u\n", what,
                            (int) sess.len, sess.value, sess.last_sq, sq );
      this->session_query( sess, "sq gap" );
    }
  }
  sess.last_sq = sq;
  return true;
}

/* _INBOX.<session>.SUBS {op:get, what:subscriptions}, reply to
 * _INBOX.<self>.<session_inbox_base + session_id> */
void
NatsSubscriptionDB::send_session_query( NatsSessionEntry &session ) noexcept
{
  if ( session.query_mono != 0 &&
       session.query_mono + SESSION_QUERY_INTERVAL > this->cur_mono )
    return;
  if ( session.len == this->client.session_len &&
       ::memcmp( session.value, this->client.session, session.len ) == 0 ) {
    session.state = NatsSessionEntry::NATS_SESSION_SELF;
    return;
  }
  char      inbox[ MAX_NATS_INBOX_LEN ];
  size_t    inbox_len;
  CatMalloc subs( 7 + session.len + 6 );

  inbox_len = this->client.make_inbox( inbox, session.session_id +
                                              this->session_inbox_base );
  MDMsgMem    mem;
  RvMsgWriter msg( mem, mem.make( 256 ), 256 );
  msg.append_string( "op", "get" )
     .append_string( "what", "subscriptions" );
  size_t buflen = msg.update_hdr();

  subs.s( "_INBOX." ).b( session.value, session.len ).s( ".SUBS" ).end();
  EvPublish pub( subs.start, subs.len(), inbox, inbox_len,
                 msg.buf, buflen, this->client.sub_route, this->client,
                 kv_crc_c( subs.start, subs.len(), 0 ), RVMSG_TYPE_ID );
  this->client.publish2( pub, subs.start, subs.len(), inbox, inbox_len );
  this->client.idle_push_write();
  session.query_mono = this->cur_mono;

  if ( this->mout != NULL )
    this->mout->printf( "> pub get subscriptions %.*s -> %.*s\n",
                        (int) subs.len(), subs.start, (int) inbox_len, inbox );
}

void
NatsSubscriptionDB::add_session( NatsSessionEntry &sess ) noexcept
{
  this->sess_ht->upsert_rsz( this->sess_ht, sess.session_id, sess.hash );
  this->sessions.active++;
}

void
NatsSubscriptionDB::rem_session( NatsSessionEntry &sess ) noexcept
{
  this->unsub_session( sess );
  this->sessions.active--;
  this->sessions.removed++;
}

NatsSubscription &
NatsSubscriptionDB::listen_start( NatsSessionEntry &session,  const char *sub,
                                  size_t sub_len,  bool &is_added,
                                  bool &coll ) noexcept
{
  if ( this->mout != NULL )
    this->mout->printf( "> listen start %.*s %.*s\n",
                        session.len, session.value, (int) sub_len, sub );
  return this->listen_ref( session, sub, sub_len, is_added, coll );
}

NatsSubscription &
NatsSubscriptionDB::listen_ref( NatsSessionEntry & session,  const char *sub,
                                size_t sub_len,  bool &is_added,
                                bool &coll ) noexcept
{
  if ( sub_len > 0 && sub[ sub_len - 1 ] == '\0' )
    sub_len--;
  RouteLoc           loc;
  uint32_t           subj_hash = kv_crc_c( sub, sub_len, 0 );
  NatsSubscription * script;

  script = this->sub_tab.upsert( subj_hash, sub, sub_len, loc );
  if ( loc.is_new )
    script->start( this->next_subject_id(), this->cur_mono );
  else
    script->ref( this->cur_mono );
  is_added = session.add_subject( *script );
  if ( is_added && script->refcnt == 1 ) {
    this->subscriptions.active++;
    coll = ( this->sub_hash_count( sub, sub_len, subj_hash ) > 1 );
  }
  else {
    coll = false;
  }
  return *script;
}

bool
NatsSubscriptionDB::deref_subscription( NatsSessionEntry &session,
                                        NatsSubscription &script,
                                        bool &coll ) noexcept
{
  if ( ! session.rem_subject( script ) )
    return false;
  if ( script.refcnt == 0 ) {
    this->subscriptions.active--;
    this->subscriptions.removed++;
    coll = ( this->sub_hash_count( script.value, script.len, script.hash ) > 0 );
  }
  return true;
}

NatsSubscription &
NatsSubscriptionDB::listen_stop( NatsSessionEntry &session,  const char *sub,
                                 size_t sub_len,  bool &is_orphan,
                                 bool &coll ) noexcept
{
  if ( sub_len > 0 && sub[ sub_len - 1 ] == '\0' )
    sub_len--;
  if ( this->mout != NULL )
    this->mout->printf( "> listen stop %.*s %.*s\n",
                        session.len, session.value, (int) sub_len, sub );
  RouteLoc           loc;
  uint32_t           subj_hash = kv_crc_c( sub, sub_len, 0 );
  NatsSubscription * script;

  script    = this->sub_tab.find( subj_hash, sub, sub_len, loc );
  is_orphan = ( script == NULL );
  coll      = false;

  if ( script != NULL ) {
    if ( ! this->deref_subscription( session, *script, coll ) )
      is_orphan = true;
  }
  else {
    script = this->sub_tab.insert( subj_hash, sub, sub_len, loc );
    script->start( this->next_subject_id(), this->cur_mono );
  }
  if ( is_orphan ) {
    if ( this->mout != NULL )
      this->mout->printf( "! listen stop without start %.*s %.*s\n",
                        session.len, session.value, (int) sub_len, sub );
    this->session_query( session, "listen stop without start" );
  }
  return *script;
}

NatsSubscription &
NatsSubscriptionDB::get_subscription( const char *sub,  size_t sub_len ) noexcept
{
  RouteLoc           loc;
  uint32_t           subj_hash = kv_crc_c( sub, sub_len, 0 );
  NatsSubscription * script;

  script = this->sub_tab.upsert( subj_hash, sub, sub_len, loc );
  if ( loc.is_new )
    script->start( this->next_subject_id(), this->cur_mono );
  return *script;
}

/* _SNAP.<subject> reply _INBOX.<session>.<n>: the session is looked up,
 * not created, a snapshot does not imply a subscription */
NatsSubscription &
NatsSubscriptionDB::snapshot( const char *sub,  size_t sub_len,
                              const char *sess,  size_t sess_len,
                              NatsSessionEntry *&session ) noexcept
{
  if ( this->mout != NULL )
    this->mout->printf( "> snapshot %.*s\n", (int) sub_len, sub );
  NatsSubscription & script = this->get_subscription( sub, sub_len );
  session = ( sess_len == 0 ? NULL : this->get_session( sess, sess_len ) );
  return script;
}

NatsSubscription &
NatsSubscriptionDB::tic( const char *sub,  size_t sub_len,
                         const char *sess,  size_t sess_len,
                         NatsSessionEntry *&session ) noexcept
{
  if ( this->mout != NULL )
    this->mout->printf( "> tic %.*s\n", (int) sub_len, sub );
  NatsSubscription & script = this->get_subscription( sub, sub_len );
  session = ( sess_len == 0 ? NULL : this->get_session( sess, sess_len ) );
  return script;
}

NatsSessionEntry *
NatsSubscriptionDB::get_session( const char *sess,  size_t sess_len ) noexcept
{
  uint32_t hash = kv_crc_c( sess, sess_len, 0 );
  RouteLoc loc;
  return this->session_tab.find( hash, sess, sess_len, loc );
}

/* iterate the active sessions */
NatsSessionEntry *
NatsSubscriptionDB::first_session( size_t &pos ) noexcept
{
  uint32_t sess_id, sess_hash;
  if ( this->sess_ht == NULL || ! this->sess_ht->first( pos ) )
    return NULL;
  this->sess_ht->get( pos, sess_id, sess_hash );
  return this->get_session( sess_id, sess_hash );
}

NatsSessionEntry *
NatsSubscriptionDB::next_session( size_t &pos ) noexcept
{
  uint32_t sess_id, sess_hash;
  if ( ! this->sess_ht->next( pos ) )
    return NULL;
  this->sess_ht->get( pos, sess_id, sess_hash );
  return this->get_session( sess_id, sess_hash );
}

NatsSessionEntry *
NatsSubscriptionDB::get_session( uint32_t sess_id,  uint32_t sess_hash ) noexcept
{
  RouteLoc           loc;
  NatsSessionEntry * session = this->session_tab.find_by_hash( sess_hash, loc );
  for (;;) {
    if ( session == NULL || session->session_id == sess_id )
      return session;
    session = this->session_tab.find_next_by_hash( sess_hash, loc );
  }
}

NatsSessionEntry *
NatsSubscriptionDB::get_session( uint32_t sess_id ) noexcept
{
  size_t   pos;
  uint32_t sess_hash;
  if ( this->sess_ht != NULL && this->sess_ht->find( sess_id, pos, sess_hash ) )
    return this->get_session( sess_id, sess_hash );
  return NULL;
}

NatsSubscription *
NatsSubscriptionDB::first_subject( NatsSessionEntry &session,
                                   size_t &pos ) noexcept
{
  uint32_t sub_id, sub_hash;
  if ( session.sub_ht == NULL )
    return NULL;
  if ( ! session.sub_ht->first( pos ) )
    return NULL;
  session.sub_ht->get( pos, sub_id, sub_hash );
  return this->get_subject( sub_id, sub_hash );
}

NatsSubscription *
NatsSubscriptionDB::next_subject( NatsSessionEntry &session,
                                  size_t &pos ) noexcept
{
  uint32_t sub_id, sub_hash;
  if ( ! session.sub_ht->next( pos ) )
    return NULL;
  session.sub_ht->get( pos, sub_id, sub_hash );
  return this->get_subject( sub_id, sub_hash );
}

NatsSubscription *
NatsSubscriptionDB::get_subject( uint32_t sub_id,  uint32_t sub_hash ) noexcept
{
  RouteLoc           loc;
  NatsSubscription * sub = this->sub_tab.find_by_hash( sub_hash, loc );
  for (;;) {
    if ( sub == NULL || sub->subject_id == sub_id )
      return sub;
    sub = this->sub_tab.find_next_by_hash( sub_hash, loc );
  }
}

void
NatsSubscriptionDB::mark_subscriptions( NatsSessionEntry &session ) noexcept
{
  NatsSubscription * sub;
  size_t pos;
  if ( (sub = this->first_subject( session, pos )) != NULL ) {
    do {
      if ( sub->start_mono < session.query_mono )
        sub->ref_mono = 0;
    } while ( (sub = this->next_subject( session, pos )) != NULL );
  }
}

void
NatsSubscriptionDB::stop_marked_subscriptions( NatsSessionEntry &session ) noexcept
{
  NatsSubscription * script;
  size_t             pos;
  uint32_t           end_sub_hash[ 256 ],
                     end_sub_id[ 256 ];
  uint32_t           i;

  for (;;) {
    i = 0;
    if ( (script = this->first_subject( session, pos )) != NULL ) {
      do {
        if ( script->ref_mono == 0 ) {
          end_sub_hash[ i ] = script->hash;
          end_sub_id[ i ]   = script->subject_id;
          if ( this->mout != NULL ) {
            this->mout->printf( "! sub %.*s, marked %.*s\n",
                                script->len, script->value,
                                session.len, session.value );
          }
          if ( ++i == 256 )
            break;
        }
      } while ( (script = this->next_subject( session, pos )) != NULL );
    }
    for ( uint32_t j = 0; j < i; j++ ) {
      script = this->get_subject( end_sub_id[ j ], end_sub_hash[ j ] );

      bool coll = false;
      if ( this->deref_subscription( session, *script, coll ) ) {
        script->ref_mono = this->cur_mono;
        if ( this->cb != NULL ) {
          NatsSubscriptionListener::Stop op( session, *script, false, false,
                                             coll );
          this->cb->on_listen_stop( op );
        }
      }
    }
    if ( i < 256 )
      return;
  }
}

void
NatsSubscriptionDB::process_events( void ) noexcept
{
  NatsSessionEntry * entry;
  size_t             pos;
  uint32_t           end_sess_hash[ 256 ],
                     end_sess_id[ 256 ];
  uint32_t           i;

  this->cur_mono = this->client.poll.mono_ns / NS;
  /* timeout sessions not heard from, query those that need it */
  for (;;) {
    i = 0;
    if ( (entry = this->first_session( pos )) != NULL ) {
      do {
        if ( entry->state == NatsSessionEntry::NATS_SESSION_SELF )
          continue;
        if ( entry->ref_mono + SESSION_TIMEOUT_INTERVAL < this->cur_mono ) {
          end_sess_hash[ i ] = entry->hash;
          end_sess_id[ i ]   = entry->session_id;
          if ( ++i == 256 )
            break;
        }
        else if ( entry->state == NatsSessionEntry::NATS_SESSION_QUERY )
          this->send_session_query( *entry );
      } while ( (entry = this->next_session( pos )) != NULL );
    }
    for ( uint32_t j = 0; j < i; j++ ) {
      entry = this->get_session( end_sess_id[ j ], end_sess_hash[ j ] );
      if ( entry == NULL )
        continue;
      if ( this->mout != NULL ) {
        char buf[ 32 ];
        time_t ref = this->client.poll.mono_to_utc_secs( entry->ref_mono );
        this->mout->printf( "! session %.*s timeout, last ref %s\n",
                            (int) entry->len, entry->value, hms( ref, buf ) );
      }
      this->rem_session( *entry );
    }
    if ( i < 256 )
      break;
  }
  if ( this->next_gc < this->cur_mono ) {
    this->next_gc = this->cur_mono + 131;
    this->gc();
  }
  if ( this->mout != NULL )
    this->mout->flush();
}

bool
NatsSubscriptionDB::process_pub( EvPublish &pub ) noexcept
{
  return this->process_pub2( pub, pub.subject, pub.subject_len,
                             (const char *) pub.reply, pub.reply_len );
}

/* _INBOX.<session>.<n> -> length of <session> */
static size_t
inbox_session_len( const char *rep,  size_t replen )
{
  if ( replen > 7 && ::memcmp( rep, "_INBOX.", 7 ) == 0 ) {
    rep = &rep[ 7 ]; /* _INBOX. */
    replen -= 7;
    while ( replen > 0 && rep[ replen - 1 ] != '.' )
      replen--;
    if ( replen > 0 && rep[ replen - 1 ] == '.' ) {
      replen--;
      return replen;
    }
  }
  return 0;
}

bool
NatsSubscriptionDB::process_pub2( EvPublish &pub,  const char *subject,
                                  size_t subject_len,  const char *reply,
                                  size_t reply_len ) noexcept
{
  const SubMatch * match = match_nats_info( subject, subject_len );
  uint64_t         which = 0;

  if ( match == NULL ) {
    which = this->client.is_inbox( subject, subject_len );
    if ( which < this->session_inbox_base )
      return false;
  }
  this->cur_mono = this->client.poll.mono_ns / NS;
  if ( this->mout != NULL ) {
    char buf[ 32 ];
    time_t now = this->client.poll.mono_to_utc_secs( this->cur_mono );
    this->mout->printf( "-- %s\n## %.*s\n", hms( now, buf ),
                        (int) subject_len, subject );
  }
  MDMsgMem mem;
  MDMsg  * m = NULL;
  /* natsmd delivers MD_STRING, the codec is detected from the bytes; a
   * request body that is no message at all (the dictionary request sends
   * "x") is not an error, the subject and reply are what matter */
  if ( pub.msg_len > 0 ) {
    m = MDMsg::unpack( (void *) pub.msg, 0, pub.msg_len, 0, NULL, mem );
    if ( m != NULL ) {
      if ( this->mout != NULL ) {
        m->print( this->mout );
        this->mout->flush();
      }
    }
    else if ( this->mout != NULL ) {
      this->mout->printf( "(no message body, %u bytes)\n",
                          (uint32_t) pub.msg_len );
      this->mout->flush();
    }
  }
  else if ( this->mout != NULL ) {
    this->mout->flush();
  }
  if ( match != NULL ) {
    /* the session is the subject tail:
     *   _NATS.START.<session>
     *   _NATS.STATUS.<session>
     *   _NATS.STOP.<session>
     *   _NATS.LISTEN.START.<session>
     *   _NATS.LISTEN.STOP.<session> */
    const char * x     = &subject[ match->len - 1 ];
    size_t       xlen  = subject_len - ( match->len - 1 );
    char       * s     = NULL,
               * u     = NULL;
    size_t       slen  = 0,
                 ulen  = 0;
    uint32_t     cn    = 0,
                 sc    = 0,
                 sx    = 0,
                 sq    = 0;
    uint16_t     flags = 0;
    bool         has_cn = false,
                 has_sx = false,
                 has_sq = false;

    if ( m != NULL ) {
      MDFieldReader rd( *m );
      switch ( match->kind ) {
        case IS_SNAP:
          if ( rd.find( "flags" ) )
            rd.get_uint( flags );
          break;
        case IS_SESSION_START:
        case IS_SESSION_STATUS:
        case IS_LISTEN_START:
        case IS_LISTEN_STOP:
          if ( rd.find( "user" ) ) {
            rd.get_string( u, ulen );
            strip_nul( u, ulen );
          }
          if ( rd.find( "sub" ) ) {
            rd.get_string( s, slen );
            strip_nul( s, slen );
          }
          if ( rd.find( "cn" ) )
            has_cn = rd.get_uint( cn );
          if ( rd.find( "sc" ) && rd.get_uint( sc ) )
            has_sx = ( rd.find( "sx" ) && rd.get_uint( sx ) );
          if ( rd.find( "sq" ) )
            has_sq = rd.get_uint( sq );
          break;
        default:
          break;
      }
    }
    switch ( match->kind ) {
      case IS_SESSION_START: {
        NatsSessionEntry & session =
          this->session_start( x, xlen, false, u, ulen );
        if ( this->session_seq( session, "start", has_sq, sq ) )
          this->session_check( session, "start", has_cn, cn, has_sx, sc, sx );
        break;
      }
      case IS_SESSION_STATUS: {
        NatsSessionEntry & session = this->session_ref( x, xlen );
        if ( u != NULL && session.state != NatsSessionEntry::NATS_SESSION_SELF )
          session.add_user( u, ulen );
        if ( this->session_seq( session, "status", has_sq, sq ) )
          this->session_check( session, "status", has_cn, cn, has_sx, sc,
                               sx );
        break;
      }
      case IS_SESSION_STOP:
        this->session_stop( x, xlen );
        break;

      case IS_LISTEN_START: {
        if ( s == NULL || slen == 0 )
          break;
        NatsSessionEntry & session = this->session_ref( x, xlen );
        if ( session.state == NatsSessionEntry::NATS_SESSION_SELF ||
             ! this->session_seq( session, "listen start", has_sq, sq ) )
          break;
        if ( this->is_matched( s, slen ) ) {
          bool               is_added = false,
                             coll     = false;
          NatsSubscription & script   = this->listen_start( session, s, slen,
                                                            is_added, coll );
          if ( is_added )
            session.digest_add( s, slen );
          if ( this->cb != NULL ) {
            NatsSubscriptionListener::Start
              op( session, script, reply, reply_len, true, coll );
            this->cb->on_listen_start( op );
          }
        }
        else {
          session.digest_add( s, slen ); /* filtered, only counted */
        }
        this->session_check( session, "listen start", false, 0, has_sx,
                             sc, sx );
        break;
      }
      case IS_LISTEN_STOP: {
        if ( s == NULL || slen == 0 )
          break;
        NatsSessionEntry & session = this->session_ref( x, xlen );
        if ( session.state == NatsSessionEntry::NATS_SESSION_SELF ||
             ! this->session_seq( session, "listen stop", has_sq, sq ) )
          break;
        if ( this->is_matched( s, slen ) ) {
          bool               is_orphan = false,
                             coll      = false;
          NatsSubscription & script    = this->listen_stop( session, s, slen,
                                                            is_orphan, coll );
          if ( ! is_orphan )
            session.digest_rem( s, slen );
          if ( this->cb != NULL ) {
            NatsSubscriptionListener::Stop op( session, script, is_orphan,
                                               true, coll );
            this->cb->on_listen_stop( op );
          }
        }
        else {
          session.digest_rem( s, slen );
        }
        this->session_check( session, "listen stop", false, 0, has_sx,
                             sc, sx );
        break;
      }
      /* _SNAP.<subject> = strip 6 char prefix */
      case IS_SNAP:
        if ( this->cb != NULL && subject_len > 6 &&
             this->is_matched( &subject[ 6 ], subject_len - 6 ) ) {
          NatsSessionEntry * session;
          size_t             sess_len = inbox_session_len( reply, reply_len );
          NatsSubscription & script   =
            this->snapshot( &subject[ 6 ], subject_len - 6, &reply[ 7 ],
                            sess_len, session );
          NatsSubscriptionListener::Snap
            op( script, session, reply, reply_len, flags );
          this->cb->on_snapshot( op );
        }
        break;

      case IS_TIC_REPLY:
        if ( this->cb != NULL ) {
          NatsSessionEntry * session;
          size_t             sess_len = inbox_session_len( reply, reply_len );
          NatsSubscription & script   =
            this->tic( subject, subject_len, &reply[ 7 ], sess_len, session );
          NatsSubscriptionListener::Tic
            op( script, session, reply, reply_len );
          this->cb->on_tic_reply( op );
        }
        break;

      default:
        break;
    }
  }
  /* subscriptions reply, the session's full set:
   * ## _INBOX.Ns6xLhbAWdQ.1001
   * user : string    7 : "nobody"
   * null : subject  13 : RSF.EQITY.9.N
   * null : subject   6 : RSF.>
   * end  : int       4 : 1 */
  else if ( m != NULL ) {
    NatsSessionEntry * session =
      this->get_session( (uint32_t) ( which - this->session_inbox_base ) );
    if ( session != NULL &&
         session->state == NatsSessionEntry::NATS_SESSION_QUERY ) {
      MDName        nm;
      MDFieldReader rd( *m );
      uint32_t      sc  = 0,
                    sx  = 0,
                    rsq = 0;
      bool          has_rsq = ( rd.find( "sq" ) && rd.get_uint( rsq ) );
      /* the reply is older than an advisory already applied: an advisory
       * published after the reply overtook it, applying the reply would
       * undo that advisory -- drop it and ask again */
      if ( has_rsq && session->last_sq != 0 && rsq < session->last_sq ) {
        if ( this->mout != NULL )
          this->mout->printf( "! stale subs reply %.*s sq %u < %u, requery\n",
                              (int) session->len, session->value, rsq,
                              session->last_sq );
        session->query_mono = 0; /* resend on the next process_events() */
        return true;
      }
      this->mark_subscriptions( *session );
      for ( bool b = rd.first( nm ); b; b = rd.next( nm ) ) {
        if ( nm.fnamelen > 1 ) {
          if ( nm.equals( "user", 4 ) ) {
            char * u    = NULL;
            size_t ulen = 0;
            if ( rd.get_string( u, ulen ) )
              session->add_user( u, ulen );
          }
        }
        else {
          char * sub     = NULL;
          size_t sub_len = 0;
          if ( ! rd.get_string( sub, sub_len ) )
            continue;
          strip_nul( sub, sub_len );
          if ( sub_len == 0 )
            continue;
          sc++;
          sx ^= kv_crc_c( sub, sub_len, 0 );
          if ( this->is_matched( sub, sub_len ) ) {
            bool is_added, coll;
            NatsSubscription & script =
              this->listen_ref( *session, sub, sub_len, is_added, coll );
            if ( is_added && this->cb != NULL ) {
              NatsSubscriptionListener::Start
                op( *session, script, NULL, 0, false, coll );
              this->cb->on_listen_start( op );
            }
          }
        }
      }
      session->sub_count  = sc;
      session->sub_digest = sx;
      session->state      = NatsSessionEntry::NATS_SESSION_START;
      if ( has_rsq )
        session->last_sq = rsq;
      this->stop_marked_subscriptions( *session );
      if ( this->mout != NULL )
        this->mout->printf( "> synced %.*s sc/sx %u/%08X\n",
                            (int) session->len, session->value, sc, sx );
    }
  }
  return true;
}

/* sessions : { <session> : { subject, ... } | 0, ... } */
void
NatsSubscriptionDB::make_sync( RvMsgWriter &w ) noexcept
{
  RvMsgWriter        sess_sub( w.mem(), NULL, 0 ),
                     subs_sub( w.mem(), NULL, 0 );
  NatsSessionEntry * session;
  NatsSubscription * script;
  size_t             pos, pos2;

  w.append_msg( SARG( "sessions" ), sess_sub );
  for ( session = this->first_session( pos ); session != NULL;
        session = this->next_session( pos ) ) {
    if ( session->state == NatsSessionEntry::NATS_SESSION_SELF )
      continue;
    if ( (script = this->first_subject( *session, pos2 )) != NULL ) {
      sess_sub.append_msg( session->value, session->len, subs_sub );
      do {
        subs_sub.append_string( NULL, 0, script->value, script->len );
      } while ( (script = this->next_subject( *session, pos2 )) != NULL );
      sess_sub.update_hdr( subs_sub );
    }
    else {
      sess_sub.append_uint( session->value, session->len, (uint8_t) 0 );
    }
  }
  w.update_hdr( sess_sub );
}

/* seed from a make_sync() message, the sessions are queried for the rest */
void
NatsSubscriptionDB::update_sync( RvMsg &msg ) noexcept
{
  MDName        nm, snm;
  MDFieldReader rd( msg );
  MDMsg       * sess_sub,
              * subs_sub;

  for ( bool b = rd.first( nm ); b; b = rd.next( nm ) ) {
    if ( ! nm.equals( SARG( "sessions" ) ) || ! rd.get_sub_msg( sess_sub ) )
      continue;
    MDFieldReader srd( *sess_sub );

    for ( bool d = srd.first( snm ); d; d = srd.next( snm ) ) {
      if ( snm.fnamelen <= 1 )
        continue;
      NatsSessionEntry & session =
        this->session_ref( snm.fname, snm.fnamelen - 1 );
      if ( session.state == NatsSessionEntry::NATS_SESSION_SELF )
        continue;

      if ( srd.type() == MD_MESSAGE && srd.get_sub_msg( subs_sub ) ) {
        MDFieldReader xrd( *subs_sub );

        for ( bool e = xrd.first( nm ); e; e = xrd.next( nm ) ) {
          char * sub    = NULL;
          size_t sublen = 0;

          if ( xrd.get_string( sub, sublen ) ) {
            strip_nul( sub, sublen );
            bool is_added, coll;
            NatsSubscription & script =
              this->listen_ref( session, sub, sublen, is_added, coll );
            if ( is_added ) {
              session.digest_add( sub, sublen );
              if ( this->cb != NULL ) {
                NatsSubscriptionListener::Start
                  op( session, script, NULL, 0, false, coll );
                this->cb->on_listen_start( op );
              }
            }
          }
        }
      }
    }
  }
}

void
NatsSubscriptionDB::gc( void ) noexcept
{
  RouteLoc loc;
  uint32_t sub_rem = 0, sess_rem = 0;
  if ( this->subscriptions.removed > this->subscriptions.active ) {
    this->subscriptions.removed = 0;
    for ( NatsSubscription *sub = this->sub_tab.first( loc ); sub != NULL; ) {
      if ( sub->refcnt == 0 ) {
        sub = this->sub_tab.remove_and_next( sub, loc );
        sub_rem++;
      }
      else
        sub = this->sub_tab.next( loc );
    }
  }
  if ( this->sessions.removed > this->sessions.active ) {
    this->sessions.removed = 0;
    for ( NatsSessionEntry *entry = this->session_tab.first( loc );
          entry != NULL; ) {
      if ( entry->state == NatsSessionEntry::NATS_SESSION_STOP ) {
        entry = this->session_tab.remove_and_next( entry, loc );
        sess_rem++;
      }
      else
        entry = this->session_tab.next( loc );
    }
  }
  if ( this->mout != NULL ) {
    if ( sub_rem + sess_rem != 0 ) {
      size_t sz = 0;
      for ( NatsSessionEntry *entry = this->session_tab.first( loc );
            entry != NULL; entry = this->session_tab.next( loc ) ) {
        if ( entry->sub_ht != NULL )
          sz += entry->sub_ht->mem_size();
      }
      this->mout->printf( "gc, rem %u subscriptions : %" PRIu64 " bytes used, "
                          "%u sessions : %" PRIu64 " bytes used, "
                          "other %" PRIu64 " bytes used\n",
                          sub_rem, (uint64_t) this->sub_tab.mem_size(),
                          sess_rem, (uint64_t) this->session_tab.mem_size(),
                          (uint64_t) ( this->sess_ht->mem_size() + sz ) );
    }
  }
}

void
NatsSubscriptionDB::unsub_all( void ) noexcept
{
  NatsSessionEntry * entry;
  size_t             pos;
  uint32_t           end_sess_hash[ 256 ],
                     end_sess_id[ 256 ];
  uint32_t           i;

  for (;;) {
    i = 0;
    if ( (entry = this->first_session( pos )) != NULL ) {
      do {
        if ( entry->state == NatsSessionEntry::NATS_SESSION_SELF )
          continue;
        end_sess_hash[ i ] = entry->hash;
        end_sess_id[ i ]   = entry->session_id;
        if ( ++i == 256 )
          break;
      } while ( (entry = this->next_session( pos )) != NULL );
    }
    for ( uint32_t j = 0; j < i; j++ ) {
      entry = this->get_session( end_sess_id[ j ], end_sess_hash[ j ] );
      if ( entry != NULL )
        this->rem_session( *entry );
    }
    if ( i < 256 )
      return;
  }
}
