#ifndef __rai_natsmd__submgr_h__
#define __rai_natsmd__submgr_h__

#include <stdlib.h>
#include <string.h>
#include <raikv/key_hash.h>
#include <raikv/route_ht.h>
#include <raikv/uint_ht.h>
#include <raikv/array_space.h>

namespace rai {
namespace kv {
struct EvPublish;
}
namespace md {
struct MDOutput;
struct RvMsgWriter;
struct RvMsg;
}
namespace natsmd {

/* The NATS counterpart of sassrv RvSubscriptionDB: tracks the sessions on
 * a NATS network and what each one subscribes, from the advisories that an
 * EvNatsClient publishes with EvNatsClientParameters::advisory != 0:
 *
 *   _NATS.START.<session>        id, user, cn, sc, sx, time
 *   _NATS.STATUS.<session>       id, user, cn, sc, sx, time, up, ...
 *   _NATS.STOP.<session>         id, time
 *   _NATS.LISTEN.START.<session> id, sub, refcnt=1, sc, sx
 *   _NATS.LISTEN.STOP.<session>  id, sub, refcnt=0, sc, sx
 *
 * There is no host and no host query: a session is learned from any of its
 * advisories and queried directly on _INBOX.<session>.SUBS {op:get,
 * what:subscriptions}, reply = user, unnamed subject fields, end=1.  The
 * subscribed subject is in the body, not the advisory subject, so a
 * wildcard filter can't narrow the LISTEN subscriptions as it does for rv
 * (_RV.INFO.SYSTEM.LISTEN.START.<wild>); _NATS.LISTEN.START.> is always
 * subscribed and filtered by is_matched().  NATS has no data loss
 * advisory, a session resyncs (state QUERY) when:
 *   - cn (connection count) changes: a reconnect re-subscribes silently
 *   - sc / sx (subject count / xor of kv_crc_c( sub ) over the set) differ
 *     from the count / digest held here after a LISTEN, START or STATUS
 *   - an advisory arrives from an unknown session (subtop started late)
 * The count and digest are kept over all of the session's subjects,
 * including those dropped by the filters, so they compare with the peer's.
 * A session that is not heard from for SESSION_TIMEOUT_INTERVAL (missed
 * two 90 second STATUS) is stopped.
 * The advisories and the SUBS reply travel on different subjects, so each
 * carries sq, the session's advisory sequence (the reply carries the
 * current value without incrementing): an advisory with sq <= last_sq is
 * already reflected and dropped, a gap re-queries, and a SUBS reply older
 * than an advisory already applied is discarded and re-sent. */
struct NatsSubscription {
  uint32_t subject_id, /* unique id, session sub_ht key */
           refcnt,     /* count of sessions with subject */
           start_mono, /* first time seen */
           ref_mono,   /* last time referenced, 0 = marked for removal */
           hash;       /* kv_crc_c( value, len, 0 ) */
  uint16_t len;        /* strlen( value ) */
  char     value[ 2 ]; /* subject or pattern */

  void start( uint32_t sub_id,  uint32_t cur_mono ) {
    this->subject_id = sub_id;
    this->refcnt     = 0;
    this->start_mono = cur_mono;
    this->ref_mono   = cur_mono;
  }
  void ref( uint32_t cur_mono ) {
    this->ref_mono = cur_mono;
  }
};

struct NatsSessionEntry {
  enum SessionState {
    NATS_SESSION_UNKNOWN = 0,
    NATS_SESSION_START   = 1, /* in sync: START seen or query answered */
    NATS_SESSION_QUERY   = 2, /* subscriptions need _INBOX.<session>.SUBS */
    NATS_SESSION_STOP    = 3, /* STOP seen or timed out */
    NATS_SESSION_SELF    = 4  /* the monitor's own session */
  };
  #define MAX_NATS_SESSION_STATE 5
  static const char *get_session_state_str( SessionState s ) noexcept;

  kv::UIntHashTab * sub_ht;     /* subject_id -> subj_hash */
  char            * user_id;    /* user from START/STATUS or SUBS reply */
  uint32_t          session_id, /* unique id, sess_ht key, query inbox */
                    start_mono, /* START time, 0 if learned otherwise */
                    ref_mono,   /* last advisory */
                    stop_mono,  /* STOP time */
                    query_mono, /* last SUBS query sent */
                    conn_count, /* cn: connections made by the session */
                    sub_count,  /* subjects held, unfiltered, cmp to sc */
                    sub_digest, /* xor kv_crc_c( sub ) held, cmp to sx */
                    last_sq;    /* sq of the last advisory / SUBS reply
                                 * applied, 0 = none or client without sq */
  SessionState      state;
  uint32_t          hash;       /* kv_crc_c( value, len, 0 ) */
  uint16_t          len;        /* strlen( value ) */
  char              value[ 2 ]; /* session name */

  void start( uint32_t sess_id,  uint32_t cur_mono,  bool is_start,
              const char *user,  size_t user_len ) {
    this->sub_ht     = kv::UIntHashTab::resize( NULL );
    this->user_id    = NULL;
    this->session_id = sess_id;
    this->start_mono = is_start ? cur_mono : 0;
    this->ref_mono   = cur_mono;
    this->stop_mono  = 0;
    this->query_mono = 0;
    this->conn_count = 0;
    this->sub_count  = 0;
    this->sub_digest = 0;
    this->last_sq    = 0;
    this->state      = is_start ? NATS_SESSION_START : NATS_SESSION_QUERY;
    this->add_user( user, user_len );
  }
  void add_user( const char *user,  size_t user_len ) {
    if ( user_len > 0 && user[ user_len - 1 ] == '\0' )
      user_len--;
    if ( this->user_id != NULL ) {
      if ( user != NULL && ::strlen( this->user_id ) == user_len &&
           ::memcmp( this->user_id, user, user_len ) == 0 )
        return;
      ::free( this->user_id );
      this->user_id = NULL;
    }
    if ( user != NULL ) {
      this->user_id = (char *) ::malloc( user_len + 1 );
      ::memcpy( this->user_id, user, user_len );
      this->user_id[ user_len ] = '\0';
    }
  }
  void stop( uint32_t cur_mono ) {
    this->state     = NATS_SESSION_STOP;
    this->stop_mono = cur_mono;
    if ( this->sub_ht != NULL ) {
      delete this->sub_ht;
      this->sub_ht = NULL;
    }
    if ( this->user_id != NULL ) {
      ::free( this->user_id );
      this->user_id = NULL;
    }
  }
  /* a subject joined / left the session's full set, maintain sc / sx */
  void digest_add( const char *sub,  size_t sub_len ) {
    this->sub_count++;
    this->sub_digest ^= kv_crc_c( sub, sub_len, 0 );
  }
  void digest_rem( const char *sub,  size_t sub_len ) {
    if ( this->sub_count > 0 )
      this->sub_count--;
    this->sub_digest ^= kv_crc_c( sub, sub_len, 0 );
  }
  /* true if peer's sc / sx match what is held */
  bool digest_equals( uint32_t sc,  uint32_t sx ) const {
    return this->sub_count == sc && this->sub_digest == sx;
  }
  bool has_subject( NatsSubscription &script ) {
    size_t pos;
    return this->sub_ht != NULL &&
           this->sub_ht->find( script.subject_id, pos );
  }
  bool add_subject( NatsSubscription &script ) {
    size_t pos;
    if ( ! this->sub_ht->find( script.subject_id, pos ) ) {
      this->sub_ht->set_rsz( this->sub_ht, script.subject_id, pos,
                             script.hash );
      script.refcnt++;
      return true;
    }
    return false;
  }
  bool rem_subject( NatsSubscription &script ) {
    if ( script.refcnt > 0 && this->sub_ht != NULL ) {
      size_t pos;
      if ( this->sub_ht->find( script.subject_id, pos ) ) {
        this->sub_ht->remove( pos );
        script.refcnt--;
        return true;
      }
    }
    return false;
  }
};

struct NatsSubscriptionListener {
  struct Start {
    NatsSessionEntry & session;
    NatsSubscription & sub;
    const char       * reply;
    uint16_t           reply_len;
    bool               is_listen_start, /* LISTEN.START, else SUBS reply */
                       coll;            /* another subject has same hash */

    Start( NatsSessionEntry &sess,  NatsSubscription &script,  const char *rep,
           size_t len,  bool is_listen,  bool col )
      : session( sess ), sub( script ), reply( rep ), reply_len( len ),
        is_listen_start( is_listen ), coll( col ) {}
  };

  struct Stop {
    NatsSessionEntry & session;
    NatsSubscription & sub;
    bool               is_orphan,      /* LISTEN.STOP without a start */
                       is_listen_stop, /* LISTEN.STOP, else stop / resync */
                       coll;

    Stop( NatsSessionEntry &sess,  NatsSubscription &script,  bool is_orph,
          bool is_listen,  bool col )
      : session( sess ), sub( script ), is_orphan( is_orph ),
        is_listen_stop( is_listen ), coll( col ) {}
  };

  struct Snap {
    NatsSubscription & sub;
    NatsSessionEntry * session; /* NULL if the reply session is unknown */
    const char       * reply;
    uint16_t           reply_len,
                       flags;

    Snap( NatsSubscription &script,  NatsSessionEntry *sess,
          const char *rep,  size_t len,  uint16_t fl )
      : sub( script ), session( sess ), reply( rep ), reply_len( len ),
        flags( fl ) {}
  };

  struct Tic {
    NatsSubscription & sub;
    NatsSessionEntry * session;
    const char       * reply;
    uint16_t           reply_len;

    Tic( NatsSubscription &script,  NatsSessionEntry *sess,
         const char *rep,  size_t len )
      : sub( script ), session( sess ), reply( rep ), reply_len( len ) {}
  };

  virtual void on_listen_start( Start &add ) noexcept;
  virtual void on_listen_stop ( Stop  &rem ) noexcept;
  virtual void on_snapshot    ( Snap  &snp ) noexcept;
  virtual void on_tic_reply   ( Tic   &tic ) noexcept;
};

struct EvNatsClient;
struct NatsSubscriptionDB {
  static const uint32_t SESSION_QUERY_INTERVAL   = 30,  /* min between SUBS */
                        SESSION_TIMEOUT_INTERVAL = 270; /* 3 * STATUS ival */
  struct GCCounters {
    uint32_t active,
             removed;
    GCCounters() : active( 0 ), removed( 0 ) {}
    void reset( void ) {
      this->active  = 0;
      this->removed = 0;
    }
  };

  struct Filter {
    char * wild;     /* match LISTEN.START sub field, subscribe _SNAP.wild */
    size_t wild_len;
  };

  typedef kv::RouteVec< NatsSessionEntry > SessionTab;
  typedef kv::RouteVec< NatsSubscription > SubscriptionTab;
  typedef kv::ArrayCount< Filter, 4 >      ListenFilterTab;

  EvNatsClient             & client;   /* monitor this network */
  NatsSubscriptionListener * cb;       /* on_listen_start() */
  kv::UIntHashTab          * sess_ht;  /* session_id -> session_tab[ hash ] */
  SessionTab                 session_tab; /* hash, session -> NatsSessionEntry */
  SubscriptionTab            sub_tab;     /* hash, subject -> NatsSubscription */
  ListenFilterTab            filters;     /* listen wildcards, eg: RSF.> */
  uint32_t                   cur_mono,    /* monotonic time in seconds */
                             next_session_ctr, /* unique counter for sessions */
                             next_subject_ctr; /* unique counter for subjects */
  GCCounters                 subscriptions, /* track how many active/removed */
                             sessions;
  uint32_t                   next_gc,
                             session_inbox_base; /* _INBOX.<self>.<base+id> */
  bool                       is_subscribed, /* start_subscriptions() called */
                             is_all_subscribed, /* no filtering */
                             is_snap,       /* _SNAP.> */
                             is_tic;        /* _TIC.REPLY.> */
  md::MDOutput             * mout; /* debug log output */

  NatsSubscriptionDB( EvNatsClient &c,  NatsSubscriptionListener *sl ) noexcept;

  void release( void ) noexcept;
  void add_wildcard( const char *wildcard ) noexcept;
  bool is_matched( const char *sub,  size_t sub_len ) noexcept;
  void start_subscriptions( bool all,  bool snap,  bool tic ) noexcept;
  void stop_subscriptions( void ) noexcept;
  void do_subscriptions( bool is_subscribe ) noexcept;
  void do_wild_subscription( Filter &f,  bool is_subscribe,  int k ) noexcept;
  uint32_t next_session_id( void ) noexcept;
  uint32_t next_subject_id( void ) noexcept;

  void process_events( void ) noexcept;
  bool process_pub( kv::EvPublish &pub ) noexcept;
  bool process_pub2( kv::EvPublish &pub,  const char *subject,
                     size_t subject_len,  const char *reply,
                     size_t reply_len ) noexcept;
  void gc( void ) noexcept;
  void make_sync( md::RvMsgWriter &w ) noexcept;
  void update_sync( md::RvMsg &msg ) noexcept;

  NatsSessionEntry * first_session( size_t &pos ) noexcept;
  NatsSessionEntry * next_session( size_t &pos ) noexcept;
  NatsSessionEntry * get_session( const char *sess,  size_t sess_len ) noexcept;
  NatsSessionEntry * get_session( uint32_t sess_id, uint32_t sess_hash ) noexcept;
  NatsSessionEntry * get_session( uint32_t sess_id ) noexcept;

  void unsub_session( NatsSessionEntry &sess ) noexcept;
  void unsub_all( void ) noexcept;

  NatsSessionEntry & session_start( const char *session_name,
                                    size_t session_len,  bool is_self,
                                    const char *u,  size_t ulen ) noexcept;
  void session_stop( const char *session_name,  size_t session_len ) noexcept;
  NatsSessionEntry & session_ref( const char *session_name,
                                  size_t session_len ) noexcept;
  void session_check( NatsSessionEntry &sess,  const char *what,
                      bool has_cn,  uint32_t cn,  bool has_sx,
                      uint32_t sc,  uint32_t sx ) noexcept;
  void session_query( NatsSessionEntry &sess,  const char *why ) noexcept;
  /* order the session's advisories by sq: false = older than what was
   * applied (drop it), a gap sends the session to QUERY */
  bool session_seq( NatsSessionEntry &sess,  const char *what,  bool has_sq,
                    uint32_t sq ) noexcept;
  void send_session_query( NatsSessionEntry &sess ) noexcept;
  void add_session( NatsSessionEntry &sess ) noexcept;
  void rem_session( NatsSessionEntry &sess ) noexcept;

  void mark_subscriptions( NatsSessionEntry &session ) noexcept;
  void stop_marked_subscriptions( NatsSessionEntry &session ) noexcept;

  NatsSubscription & get_subscription( const char *sub,
                                       size_t sub_len ) noexcept;
  NatsSubscription * first_subject( NatsSessionEntry &session,
                                    size_t &pos ) noexcept;
  NatsSubscription * next_subject( NatsSessionEntry &session,
                                   size_t &pos ) noexcept;
  NatsSubscription * get_subject( uint32_t sub_id,  uint32_t sub_hash ) noexcept;

  NatsSubscription & listen_start( NatsSessionEntry &session,  const char *sub,
                                   size_t sub_len, bool &is_added,
                                   bool &coll ) noexcept;
  NatsSubscription & listen_ref( NatsSessionEntry &session,  const char *sub,
                                 size_t sub_len,  bool &is_added,
                                 bool &coll ) noexcept;
  bool deref_subscription( NatsSessionEntry &session,  NatsSubscription &script,
                           bool &coll ) noexcept;
  NatsSubscription & listen_stop( NatsSessionEntry &session,  const char *sub,
                                  size_t sub_len,  bool &is_orphan,
                                  bool &coll ) noexcept;
  NatsSubscription & snapshot( const char *sub,  size_t sub_len,
                               const char *sess,  size_t sess_len,
                               NatsSessionEntry *&session ) noexcept;
  NatsSubscription & tic( const char *sub,  size_t sub_len,
                          const char *sess,  size_t sess_len,
                          NatsSessionEntry *&session ) noexcept;
  size_t sub_hash_count( const char *sub,  size_t sub_len,
                         uint32_t sub_hash ) noexcept;
};

/* NATS wildcards, * matches a token, > matches the tail */
static inline bool
match_nats_wildcard( const char *wild,  size_t wild_len,
                     const char *sub,  size_t sub_len ) noexcept
{
  const char * w   = wild,
             * end = &wild[ wild_len ];
  size_t       k   = 0;

  for (;;) {
    if ( k == sub_len || w == end ) {
      if ( k == sub_len && w == end )
        return true;
      return false; /* no match */
    }
    if ( *w == '>' &&
         ( ( w == wild || *(w-1) == '.' ) && w+1 == end ) )
      return true;
    else if ( *w == '*' &&
              ( ( w   == wild || *(w-1) == '.' ) && /* * || *. || .* || .*. */
                ( w+1 == end  || *(w+1) == '.' ) ) ) {
      for (;;) {
        if ( k == sub_len || sub[ k ] == '.' )
          break;
        k++;
      }
      w++;
      continue;
    }
    if ( *w != sub[ k ] )
      return false; /* no match */
    w++;
    k++;
  }
}

static inline const char *
is_nats_wildcard( const char *wild,  size_t wild_len ) noexcept
{
  const char * w   = wild,
             * end = &wild[ wild_len ];

  for ( ; ; w++ ) {
    if ( w == end )
      return NULL;
    if ( *w == '>' &&
         ( ( w == wild || *(w-1) == '.' ) && w+1 == end ) )
      return w;
    else if ( *w == '*' &&
              ( ( w   == wild || *(w-1) == '.' ) && /* * || *. || .* || .*. */
                ( w+1 == end  || *(w+1) == '.' ) ) ) {
      return w;
    }
  }
}

}
}
#endif
