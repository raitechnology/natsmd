#ifndef __rai_natsmd__ev_nats_client_h__
#define __rai_natsmd__ev_nats_client_h__

#include <natsmd/ev_nats.h>
#include <raikv/dlinklist.h>
#include <raikv/key_hash.h>

extern "C" {
/* factory used by raims (dlsym / built in table) for the ipc transport */
rai::kv::EvConnection *nats_create_connection( rai::kv::EvPoll *p,  rai::kv::RoutePublish *sr,
                           rai::kv::EvConnectionNotify *n );
}
namespace rai {
namespace natsmd {

/* a fragment is marked at the end of a publish with these fields */
static const uint32_t TRAILER_MARK = 0xff44aa99U; /* spells frag, hah */
struct NatsTrailer { /* trailer bytes */
  uint64_t src_id,   /* source of the fragment */
           src_time; /* time that the mssage was published */
  uint32_t off,      /* offset of the fragment */
           msg_len,  /* total size of the message */
           hash,     /* hash of the subject */
           mark;     /* TRAILER_MARK */
  /* create new trailer on publish */
  NatsTrailer( uint64_t src,  uint64_t t,  uint32_t h,  uint32_t len )
    : src_id( src ), src_time( t ), off( 0 ), msg_len( len ),
      hash( h ), mark( TRAILER_MARK ) {}
  /* create from message buffer on recv */
  NatsTrailer( void *msg,  size_t mlen ) : mark( 0 ) {
    if ( mlen > sizeof( *this ) )
      ::memcpy( this, &((char *) msg)[ mlen - sizeof( *this ) ],
                sizeof( *this ) );
  }
  /* these must match to be considered for de-fragmenting */
  bool is_fragment( uint32_t h,  size_t max_payload ) const {
    return this->mark == TRAILER_MARK && h == this->hash &&
           this->off < this->msg_len && this->msg_len > max_payload;
  }
};

/* messages larger than max_payload are fragmented */
struct NatsFragment {
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  NatsFragment * next,     /* list links of message fragments pending */
               * back;
  uint64_t       src_id,   /* the source that created the frags */
                 src_time; /* the time that the message was published */
  uint32_t       hash,     /* hash of the subject envelope */
                 off,      /* offset of the fragments recvd */
                 msg_len,  /* total length of fragment */
                 pad;      /* alignment */
  /* data follows */
  NatsFragment( uint64_t src,  uint64_t t,  uint32_t h, uint32_t len )
    : next( 0 ), back( 0 ), src_id( src ), src_time( t ), hash( h ),
      off( 0 ), msg_len( len ), pad( 0 ) {}
  void *msg_ptr( void ) {
    return &this[ 1 ];
  }
};

/* wildcards subscribed by prefix */
struct NatsPrefix {
  uint32_t hash;        /* hash of wildcard prefix */
  uint32_t sid;         /* sid forwarded to NATS is -sid */
  uint16_t len;         /* length of prefix */
  char     value[ 2 ];  /* the prefix */
};

struct SidHash {
  uint32_t hash[ 4 ];
  SidHash() {}
  SidHash( const SidHash &h1 ) {
    for ( size_t i = 0; i < 4; i++ )
      this->hash[ i ] = h1.hash[ i ];
  }
  SidHash( uint32_t h,  const char *sub,  size_t sublen ) {
    uint64_t m = kv_hash_murmur64( sub, sublen, 0 );
    this->hash[ 0 ] = h;
    this->hash[ 1 ] = (uint32_t) m;
    this->hash[ 2 ] = (uint32_t) ( m >> 32 );
    this->hash[ 3 ] = kv_djb( sub, sublen );
  }
  bool operator==( const SidHash &h1 ) const {
    for ( size_t i = 0; i < 4; i++ )
      if ( this->hash[ i ] != h1.hash[ i ] )
        return false;
    return true;
  }
  SidHash &operator=( const SidHash &h1 ) {
    for ( size_t i = 0; i < 4; i++ )
      this->hash[ i ] = h1.hash[ i ];
    return *this;
  }
  size_t operator&( size_t mod ) const {
    size_t h = (uint64_t) this->hash[ 0 ] | ((uint64_t) this->hash[ 1 ] << 32 );
    return h & mod;
  }
};

typedef kv::IntHashTabT<SidHash,uint32_t> SidHashTab;

struct EvNatsClientParameters {
  const char * host,
             * name,
             * lang,
             * version,
             * user,
             * pass,
             * auth_token;
  int          port,
               opts;
  const struct addrinfo *ai;
  const char * k;
  uint32_t     rte_id;
  EvNatsClientParameters( const char *h = NULL,  const char *n = NULL,
                          const char *u = NULL,  const char *x = NULL,
                          const char *t = NULL,  int p = 4222,
                          int o = kv::DEFAULT_TCP_CONNECT_OPTS )
    : host( h ), name( n ), lang( "C" ), version( NULL ), user( u ), pass( x ),
      auth_token( t ), port( p ), opts( o ), ai( 0 ), k( 0 ), rte_id( 0 ) {}
};

struct NatsClientCB {
  NatsClientCB() {}
  virtual bool on_nats_msg( kv::EvPublish &pub ) noexcept;
};

static const size_t MAX_NATS_INBOX_LEN = 88; /* _INBOX.<session>.<number> */

/* a connection to a NATS server */
struct EvNatsClient : public kv::EvConnection, public kv::RouteNotify {
  void * operator new( size_t, void *ptr ) { return ptr; }
  kv::RoutePublish & sub_route;
  NatsClientCB * cb;
  char         * err;          /* if -ERR, then err points to end of buffer */
  size_t         err_len;      /* length of err */
  uint32_t       next_sid;     /* first is 1 max is 1 << 30 */
  uint8_t        protocol,     /* from INFO */
                 fwd_all_msgs, /* send publishes */
                 fwd_all_subs; /* send subscriptons */
  uint32_t       wild_prefix_char[ 3 ]; /* first char of wildcard [ '!' -> 127 ]*/
  size_t         max_payload;  /* 1024 * 1024 */

  kv::DLinkList<NatsFragment> frags_pending;  /* large message fragments */
  SidHashTab                * sid_ht;         /* sub to sid */
  kv::RouteVec<NatsPrefix>    pat_tab;        /* wildcard patterns */

  uint32_t        wild_prefix_char_cnt[ 96 ];  /* count of all wildcard[ 0 ] */
  char            prefix[ MAX_PREFIX_LEN ],
                  session[ MAX_SESSION_LEN ];
  uint16_t        prefix_len,
                  session_len;

  kv::StrArray<1> inter_subs, bcast_subs, listen_subs;
  const char    * name,         /* CONNECT parm:  name="service" */
                * lang,                        /* lang="C" */
                * version,                     /* version="1.0" */
                * user,                        /* user="network" */
                * pass,                        /* pass="xxx" */
                * auth_token;                  /* auth_token="xxx" */
  void          * param_buf;

  EvNatsClient( kv::EvPoll &p,  kv::RoutePublish &sr,
                kv::EvConnectionNotify *n ) noexcept;
  EvNatsClient( kv::EvPoll &p ) noexcept;

  virtual int connect( kv::EvConnectParam &param ) noexcept;
  bool nats_connect( EvNatsClientParameters &p,
                     kv::EvConnectionNotify *n = NULL,
                     NatsClientCB *c = NULL ) noexcept;
  bool is_connected( void ) const {
    return this->EvSocket::fd != -1;
  }
  void make_session( void ) noexcept;
  uint16_t make_inbox( char *inbox, uint64_t num ) noexcept;
  uint64_t is_inbox( const char *sub,  size_t sub_len ) noexcept;
  void initialize_state( void ) noexcept;
  /* track which subjects are wildcards by first char */
  void set_wildcard_match( uint8_t c ) { /* 0 = all subjects */
    uint8_t bit = ( c > ' ' ? ( ( c - ' ' ) & 0x5fU ) : 0 );
    this->wild_prefix_char[ bit >> 5 ] |= 1U << ( bit & 31 );
    this->wild_prefix_char_cnt[ bit ]++;
  }
  /* when a wildcard unsubscribed */
  void clear_wildcard_match( uint8_t c ) {
    uint8_t bit = ( c > ' ' ? ( ( c - ' ' ) & 0x5fU ) : 0 );
    if ( --this->wild_prefix_char_cnt[ bit ] == 0 )
      this->wild_prefix_char[ bit >> 5 ] &= ~( 1U << ( bit & 31 ) );
  }
  /* how many possible wildcard matches for a subject */
  uint32_t possible_matches( uint8_t c ) const {
    uint8_t bit = ( c - ' ' ) & 0x5fU;
    return this->wild_prefix_char_cnt[ 0 ] +
           this->wild_prefix_char_cnt[ bit ];
  }
  /* if a subject may have a wildcard match */
  bool test_wildcard_match( uint8_t c ) const {
    if ( ( this->wild_prefix_char[ 0 ] & 1 ) != 0 ) /* all subjects */
      return true;
    uint8_t bit = ( c - ' ' ) & 0x5fU;
    return ( this->wild_prefix_char[ bit >> 5 ] & ( 1U << ( bit & 31 ) ) ) != 0;
  }
  /* forward NATS MSG to subscribers */
  bool fwd_pub( NatsMsg &msg ) noexcept;
  /* only forward one sid per message, if overlapping wildcards are subscribed */
  bool deduplicate_wildcard( NatsMsg &msg,  kv::EvPublish &pub ) noexcept;
  /* parse the NATS INFO message */
  void parse_info( const char *info,  size_t infolen ) noexcept;
  /* when no subscribers left, NATS connection can be shutdown */
  void do_shutdown( void ) noexcept;
  /* merge a NATS MSG into a larger than max_payload message*/
  NatsFragment *merge_fragment( NatsTrailer &trail,  const void *msg,
                                size_t msg_len ) noexcept;
  /* release all frags on shutdown */
  void release_fragments( void ) noexcept;
  /* save error strings that occur while processing */
  void save_error( const char *buf,  size_t len ) noexcept;

  /* EvSocket */
  virtual void set_prefix( const char *pref,  size_t preflen ) noexcept;
  virtual void process( void ) noexcept; /* decode read buffer */
  virtual void process_close( void ) noexcept;
  virtual void release( void ) noexcept; /* after shutdown release mem */
  virtual bool on_msg( kv::EvPublish &pub ) noexcept; /* fwd to NATS network */
  bool publish( kv::EvPublish &pub ) noexcept;
  bool publish2( kv::EvPublish &pub,  const char *sub,  size_t sublen,
                 const char *reply,  size_t replen ) noexcept;
  /* track the sid of subjects for UNSUB */
  uint32_t create_sid( uint32_t h,  const char *sub,  size_t sublen,
                       bool &is_new ) noexcept;
  /* find the subject sid and remove it */
  uint32_t remove_sid( uint32_t h,  const char *sub,  size_t sublen ) noexcept;
  /* RouteNotify */
  /* a new subscription */
  void do_sub( uint32_t h,  const char *sub,  size_t sublen,
               const char *queue,  size_t queue_len ) noexcept;
  virtual void on_sub( kv::NotifySub &sub ) noexcept;
  const char * is_wildcard( const char *subject,  size_t subject_len ) noexcept;
  void subscribe( const char *subject,  size_t subject_len,
                  const char *queue,  size_t queue_len ) noexcept;
  bool match_filter( const char *sub,  size_t sublen ) noexcept;
  bool get_nsub( kv::NotifySub &nsub,  const char *&sub,  size_t &sublen,
                 const char *&rep,  size_t replen ) noexcept;
  /* an unsubscribed sub */
  void do_unsub( uint32_t h,  const char *sub,  size_t sublen ) noexcept;
  virtual void on_unsub( kv::NotifySub &sub ) noexcept;
  void unsubscribe( const char *subject,  size_t subject_len ) noexcept;
  /* a new pattern subscription */
  void do_psub( uint32_t h,  const char *prefix,  size_t prefix_len,
                const char *queue,  size_t queue_len ) noexcept;
  virtual void on_psub( kv::NotifyPattern &pat ) noexcept;
  /* an unsubscribed pattern sub */
  void do_punsub( uint32_t h, const char *prefix, size_t prefix_len ) noexcept;
  virtual void on_punsub( kv::NotifyPattern &pat ) noexcept;
  void fwd_pat( kv::NotifyPattern &pat,  bool is_psub ) noexcept;
  /* reassert subs after reconnect */
  virtual void on_reassert( uint32_t fd,  kv::RouteVec<kv::RouteSub> &sub_db,
                            kv::RouteVec<kv::RouteSub> &pat_db ) noexcept;
};

}
}
#endif
