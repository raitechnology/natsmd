#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#else
#include <raikv/win.h>
#endif
#include <natsmd/ev_nats.h>
#include <raikv/key_hash.h>
#include <raikv/util.h>
#include <raikv/ev_publish.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <raikv/pattern_cvt.h>
#include <raimd/json_msg.h>

uint32_t rai::natsmd::nats_debug = 0;

using namespace rai;
using namespace natsmd;
using namespace kv;
using namespace md;

extern "C" {

const char *
natsmd_get_version( void )
{
  return kv_stringify( NATSMD_VER );
}

EvTcpListen *
nats_create_listener( rai::kv::EvPoll *p,  rai::kv::RoutePublish *sr,  
                      rai::kv::EvConnectionNotify *n ) noexcept
{
  EvNatsListen *l = new ( aligned_malloc( sizeof( EvNatsListen ) ) )
    EvNatsListen( *p, *sr );
  l->notify = n;
  return l;
}

}

EvNatsListen::EvNatsListen( EvPoll &p ) noexcept
  : EvTcpListen( p, "nats_listen", "nats_sock" ), sub_route( p.sub_route ),
    host( 0 ), prefix_len( 0 ), svc( 0 ) {}

EvNatsListen::EvNatsListen( EvPoll &p,  RoutePublish &sr ) noexcept
  : EvTcpListen( p, "nats_listen", "nats_sock" ), sub_route( sr ),
    host( 0 ), prefix_len( 0 ), svc( 0 ) {}

int
EvNatsListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  return this->kv::EvTcpListen::listen2( ip, port, opts, "nats_listen",
                                         this->sub_route.route_id );
}

void
EvNatsListen::set_service( void *host,  uint16_t svc ) noexcept
{
  this->host = host;
  this->svc  = svc;
}

bool
EvNatsListen::get_service( void *host,  uint16_t &svc ) const noexcept
{
  svc = this->svc;
  if ( host != NULL )
    *(void **) host = (void *) &this->host;
  return this->svc != 0;
}

void
EvNatsListen::set_prefix( const char *pref,  size_t preflen ) noexcept
{
  this->prefix_len = cpyb<MAX_PREFIX_LEN>( this->prefix, pref, preflen );
}
/*
 * NATS protocol:
 *
 * 1. session init
 * server -> INFO { (below) } \r\n
 * (optional)
 * client -> CONNECT { verbose, pedantic, tls_required, auth_token, user,
 *                     pass, name, lang, protocol, echo } \r\n
 * 2. subscribe
 * client -> SUB <subject> [queue group] <sid> \r\n
 *        -> UNSUB <sid> [max-msgs] \r\n
 *
 * ping/pong, pong responds to ping, used for keepalive:
 * client/server -> PING \r\n
 *               -> PONG \r\n
 *
 * 3. publish
 * client -> PUB <subject> [reply-to] <#bytes> \r\n [payload] \r\n
 * server -> MSG <subject> <sid> [reply-to] <#bytes> \r\n [payload] \r\n
 *
 * 4. error / ok status (ok turned off by verbose=false)
 * server -> +OK \r\n
 * server -> -ERR (opt msg) \r\n
 */

/* ID = 22 chars base62 string dependent on the hash of the database = 255 */
static char nats_server_info[] =
"INFO {\"server_id\":\"______________________\","
      "\"version\":\"2\","
      "\"proto\":1,"
      "\"host\":\"255.255.255.255\","
      "\"port\":65535,"
      "\"auth_required\":false,\"ssl_required\":false,"
      "\"tls_required\":false,\"tls_verify\":false,"
      "\"max_payload\":1048576}\r\n";
bool is_server_info_init;

static void
init_server_info( uint64_t h1,  uint64_t h2,  uint16_t port )
{
  char host[ 256 ];
  struct addrinfo *res = NULL, *p;
  uint64_t r = 0;
  int i;
  rand::xorshift1024star prng;
  uint64_t svid[ 2 ] = { h1, h2 };

  prng.init( svid, sizeof( svid ) ); /* same server id until shm destroyed */

  for ( i = 0; i < 22; i++ ) {
    if ( ( i % 10 ) == 0 )
      r = prng.next();
    char c = r % 62;
    c = ( c < 10 ) ? ( c + '0' ) : (
        ( c < 36 ) ? ( ( c - 10 ) + 'A' ) : ( ( c - 36 ) + 'a' ) );
    nats_server_info[ 19 + i ] = c;
    r >>= 6;
  }

  char * ip, * s;
  size_t len;
  if ( ::gethostname( host, sizeof( host ) ) == 0 &&
       ::getaddrinfo( host, NULL, NULL, &res ) == 0 ) {
    for ( p = res; p != NULL; p = p->ai_next ) {
      if ( p->ai_family == AF_INET && p->ai_addr != NULL ) {
        ip  = ::inet_ntoa( ((struct sockaddr_in *) p->ai_addr)->sin_addr );
        len = ::strlen( ip );
        s   = ::strstr( nats_server_info, "255.255.255.255" );
        ::memcpy( s, ip, len );
        s[ len++ ] = '\"';
        s[ len++ ] = ',';
        while ( len < 17 )
          s[ len++ ] = ' ';
        break;
      }
    }
    ::freeaddrinfo( res );
  }

  s = ::strstr( nats_server_info, "65535" );
  for ( i = 5; port > 0; port /= 10 ) 
    s[ --i ] = ( port % 10 ) + '0';
  while ( i > 0 )
    s[ --i ] = ' ';
  is_server_info_init = true;
}

EvSocket *
EvNatsListen::accept( void ) noexcept
{
  EvNatsService *c =
    this->poll.get_free_list<EvNatsService, EvNatsListen &,
                             EvConnectionNotify *>(
      this->accept_sock_type, *this, this->notify );

  if ( c == NULL )
    return NULL;
  if ( ! this->accept2( *c, "nats" ) )
    return NULL;

  if ( ! is_server_info_init ) {
    uint16_t port = 42222;
    uint64_t h1, h2;
    struct sockaddr_storage myaddr;
    socklen_t myaddrlen = sizeof( myaddr );
    int status;
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
    status = ::getsockname( c->fd, (sockaddr *) &myaddr, &myaddrlen );
#else
    SOCKET sock;
    status = ::wp_get_socket( c->fd, &sock );
    if ( status == 0 )
      status = ::getsockname( sock, (sockaddr *) &myaddr, &myaddrlen );
#endif
    if ( status == 0 ) {
      if ( myaddr.ss_family == AF_INET )
        port = ntohs( ((sockaddr_in *) &myaddr)->sin_port );
      else if ( myaddr.ss_family == AF_INET6 )
        port = ntohs( ((sockaddr_in6 *) &myaddr)->sin6_port );
    }
    h1 = this->poll.create_ns();
    h2 = /*this->poll.map->hdr.seed[ 0 ].hash2;*/ 0;
    init_server_info( h1, h2, port );
  }
  c->initialize_state( NULL, 0, ++this->timer_id );
  c->set_prefix( this->prefix, this->prefix_len );
  c->append_iov( nats_server_info, sizeof( nats_server_info ) - 1 );
  c->idle_push( EV_WRITE_HI );
  return c;
}
#if 0
  if ( this->user.stamp == 0 ) {
    switch ( kw ) {
      case NATS_KW_SUB1:
      case NATS_KW_SUB2:
      case NATS_KW_PUB1:
      case NATS_KW_PUB2:
      case NATS_KW_UNSUB:
      case NATS_KW_PING: /* setup user if none specified */
        return IS_CONNECT;
        break;
      default:
        break;
    }
  }
#endif
void
EvNatsService::process( void ) noexcept
{
  static const char ok[]   = "+OK\r\n",
                    err[]  = "-ERR\r\n",
                    pong[] = "PONG\r\n";
  const int verb_ok = ( this->user.verbose ? DO_OK : 0 );
  int flow;

  if ( this->len - this->off > this->recv_highwater )
    this->nats_state |= NATS_BUFFERSIZE;
  else
    this->nats_state &= ~NATS_BUFFERSIZE;
  for (;;) {
    if ( this->off == this->len )
      break;

    NatsMsg msg;
    int fl = msg.parse_msg( &this->recv[ this->off ], &this->recv[ this->len ]);
    if ( fl == NEED_MORE ) {
      if ( msg.size > 0 )
        this->recv_need( msg.size );
      break;
    }
    if ( this->user.stamp == 0 && fl <= REM_SID )
      this->parse_connect( NULL, 0 );

    switch ( fl ) {
      case IS_CONNECT:
        this->parse_connect( msg.line, msg.size );
        break;

      case ADD_SUB:
        this->add_sub( msg );
        fl |= verb_ok;
        break;

      case PUB_MSG:
      case HPUB_MSG:
        flow = this->fwd_pub( msg );
        if ( flow == NATS_FLOW_GOOD )
          this->nats_state &= ~NATS_BACKPRESSURE;
        else {
          this->nats_state |= NATS_BACKPRESSURE;
          if ( flow == NATS_FLOW_STALLED ) {
            this->pop( EV_PROCESS );
            this->pop3( EV_READ, EV_READ_LO, EV_READ_HI );
            if ( ! this->push_write_high() )
              this->clear_write_buffers();
            return;
          }
        }
        this->msgs_recv++;
        fl |= verb_ok;
        break;

      case IS_PING:
        this->append( pong, sizeof( pong ) - 1 );
        this->off += msg.size;
        this->push( EV_WRITE_HI );
        return;

      case REM_SID:
        this->rem_sid( msg );
        fl |= verb_ok;
        break;

      default:
        break;
    }
    this->off += msg.size;

    if ( ( fl & DO_OK ) != 0 )
      this->append( ok, sizeof( ok ) - 1 );
    if ( ( fl & DO_ERR ) != 0 )
      this->append( err, sizeof( err ) - 1 );
  }
  this->pop( EV_PROCESS );
  if ( ! this->push_write() )
    this->clear_write_buffers();
}

int
NatsMsg::parse_msg( char *start,  char *end ) noexcept
{
  char * eol    = (char *) ::memchr( start, '\n', end - start );
  char * size_start, * p;
  size_t linesz, nargs, size_len;
  int    pub_type;

  if ( eol == NULL ) {
    this->size = 0;
    return NEED_MORE;
  }
  linesz     = &eol[ 1 ] - start; /* 1 char after \n */
  this->line = start;
  this->size = linesz;
  p          = &start[ linesz ];

  if ( linesz < 4 ) /* skip over empty lines */
    return SKIP_SPACE;

  NatsArgs args;
  this->kw = unaligned<uint32_t>( start ) & 0xdfdfdfdf; /* 4 toupper */

  switch ( this->kw ) {
    case NATS_KW_OK1:
    case NATS_KW_OK2:
      return IS_OK;

    case NATS_KW_ERR:
      return IS_ERR;

    case NATS_KW_SUB1:   /* SUB <subject> [queue group] <sid> */
    case NATS_KW_SUB2:
      nargs = args.parse( &start[ 4 ], eol );
      if ( nargs < 2 || nargs > 3 )
        return DO_ERR;

      /* SUB <subject> <queue> <sid> | SUB <subject> <sid> */
      this->subject     = args.ptr[ 0 ];
      this->subject_len = args.len[ 0 ];
      this->sid         = args.ptr[ nargs - 1 ];
      this->sid_len     = args.len[ nargs - 1 ];

      if ( nargs == 3 ) {
        this->queue     = args.ptr[ 1 ];
        this->queue_len = args.len[ 1 ];
      }
      return ADD_SUB;

    case NATS_KW_MSG1:   /* MSG <subject> <sid> [reply] <size> */
    case NATS_KW_MSG2:
      pub_type = RCV_MSG;
      if ( 0 ) {
      /* FALLTHRU */
    case NATS_KW_PUB1:   /* PUB <subject> [reply] <size> */
    case NATS_KW_PUB2:
        pub_type = PUB_MSG;
        if ( 0 ) {
      /* FALLTHRU */
    case NATS_KW_HPUB:   /* HPUB <subject> [reply] <hsize> <size> */
          pub_type = HPUB_MSG;
          if ( 0 ) {
      /* FALLTHRU */
    case NATS_KW_HMSG:   /* HMSG <subject> <sid> [reply] <hsize> <size> */
            pub_type = HRCV_MSG;
          }
        }
      }
      size_start = args.parse_end_size( start, eol - 1, this->msg_len,
                                        size_len );
      if ( size_start == NULL )
        return DO_ERR;
      if ( pub_type == HPUB_MSG || pub_type == HRCV_MSG ) {
        size_start = args.parse_end_size( start, size_start, this->hdr_len,
                                          size_len );
        if ( size_start == NULL || this->hdr_len > this->msg_len )
          return DO_ERR;
      }
      this->msg_ptr = p;
      p = &p[ this->msg_len ];
      if ( p > end ) {
        this->size += this->msg_len;
        return NEED_MORE;
      }
      nargs = args.parse( &start[ 4 ], size_start );
      if ( nargs < 1 || nargs > 3 )
        return DO_ERR;
      /* PUB <subject> [reply] | MSG <subject> <sid> [reply] */
      this->subject     = args.ptr[ 0 ];
      this->subject_len = args.len[ 0 ];
      if ( pub_type == PUB_MSG || pub_type == HPUB_MSG ) {
        if ( nargs > 1 ) {
          this->reply     = args.ptr[ 1 ];
          this->reply_len = args.len[ 1 ];
        }
      }
      else {
        if ( nargs == 1 ) /* must have sid */
          return DO_ERR;
        this->sid     = args.ptr[ 1 ];
        this->sid_len = args.len[ 1 ];
        if ( nargs > 2 ) {
          this->reply     = args.ptr[ 2 ];
          this->reply_len = args.len[ 2 ];
        }
      }
      this->size += this->msg_len;
      while ( p < end && ( *p == '\r' || *p == '\n' ) ) {
        p++;
        this->size++;
      }
      return pub_type;

    case NATS_KW_PING:
      return IS_PING;

    case NATS_KW_PONG:
      return IS_PONG;

    case NATS_KW_INFO:
      return IS_INFO;

    case NATS_KW_UNSUB: /* UNSUB <sid> [max-msgs] */
      nargs = args.parse( &start[ 6 ], eol - 1 );
      if ( nargs != 1 ) {
        if ( nargs != 2 )
          return DO_ERR;
        /* max-msgs */
        args.parse_end_size( args.ptr[ 1 ], &args.ptr[ 1 ][ args.len[ 1 ] ],
                             this->max_msgs, size_len );
      }
      this->sid     = args.ptr[ 0 ];
      this->sid_len = args.len[ 0 ];
      return REM_SID;

    case NATS_KW_CONNECT:
      return IS_CONNECT;

    default:
      return DO_ERR;
  }
}

uint8_t
EvNatsService::is_subscribed( const NotifySub &sub ) noexcept
{
  uint8_t v    = 0;
  bool    coll = false;
  if ( ! sub.is_notify_queue() ) {
    if ( this->map.sub_tab.find3( sub.subj_hash, sub.subject, sub.subject_len,
                                  coll ) == NATS_OK )
      v |= EV_SUBSCRIBED;
  }
  else {
    if ( this->map.qsub_tab.find3( sub.subj_hash, sub.subject, sub.subject_len,
                                   coll ) == NATS_OK )
      v |= EV_SUBSCRIBED;
  }
  if ( v == 0 )
    v |= EV_NOT_SUBSCRIBED;
  if ( coll )
    v |= EV_COLLISION;
  return v;
}

uint8_t
EvNatsService::is_psubscribed( const NotifyPattern &pat ) noexcept
{
  uint8_t v    = 0;
  bool    coll = false;
  const PatternCvt & cvt = pat.cvt;
  NatsPatternRoute * rt;
  int status;
  if ( ! pat.is_notify_queue() ) {
    status = this->map.pat_tab.find3( pat.prefix_hash, pat.pattern,
                                      cvt.prefixlen, rt, coll );
  }
  else {
    status = this->map.qpat_tab.find3( pat.prefix_hash, pat.pattern,
                                       cvt.prefixlen, rt, coll );
  }
  if ( status == NATS_OK ) {
    NatsWildMatch *m;
    for ( m = rt->list.hd; m != NULL; m = m->next ) {
      if ( m->len == pat.pattern_len &&
           ::memcmp( pat.pattern, m->value, m->len ) == 0 ) {
        v |= EV_SUBSCRIBED;
        break;
      }
    }
    if ( m == NULL )
      v |= EV_NOT_SUBSCRIBED | EV_COLLISION;
    else if ( rt->count > 1 )
      v |= EV_COLLISION;
  }
  else {
    v |= EV_NOT_SUBSCRIBED;
  }
  if ( coll )
    v |= EV_COLLISION;
  return v;
}

void
EvNatsService::add_sub( NatsMsg &msg ) noexcept
{
  const char * sub       = msg.subject;
  size_t       sublen    = msg.subject_len,
               preflen   = this->prefix_len;
  char       * inbox     = NULL;
  size_t       inbox_len = 0;
  const char * que       = msg.queue;
  size_t       quelen    = msg.queue_len;
  uint32_t     quehash   = 0;

  if ( preflen > 0 ) {
    CatPtr tmp( this->alloc_temp( sublen + preflen + 1 ) );
    tmp.x( this->prefix, preflen ).x( sub, sublen ).end();
    sub     = tmp.start;
    sublen += preflen;
    if ( quelen > 0 ) {
      CatPtr tmp( this->alloc_temp( quelen + preflen + 1 ) );
      tmp.x( this->prefix, preflen ).x( que, quelen ).end();
      que     = tmp.start;
      quelen += preflen;
    }
  }
  if ( quelen > 0 )
    quehash = kv_crc_c( que, quelen, 0 );

  NatsStr sid( msg.sid, msg.sid_len );
  NatsStr subj( sub, sublen );
  bool    coll = false;
  NatsSubStatus status;

  if ( is_nats_debug )
    printf( "add_sub %.*s sid %.*s\n", (int) sublen, sub,
            (int) msg.sid_len, msg.sid );

  if ( subj.is_wild() ) {
    PatternCvt cvt;
    if ( cvt.convert_rv( subj.str, subj.len ) != 0 )
      status = NATS_BAD_PATTERN;
    else {
      uint32_t h = kv_crc_c( subj.str, cvt.prefixlen,
                             this->sub_route.prefix_seed( cvt.prefixlen ) );
      NatsStr pre( subj.str, cvt.prefixlen, h );
      NatsWildMatch * sub_m = NULL;
      if ( quelen == 0 )
        status = this->map.put_wild( subj, cvt, pre, sid, coll, sub_m );
      else
        status = this->map.put_wild_que( subj, cvt, pre, sid, coll, sub_m,
                                         quehash );
      if ( status == NATS_IS_NEW || status == NATS_OK ||
           ( status == NATS_EXISTS && sub_m != NULL ) ) {
        NotifyPatternQueue npat( cvt, subj.str, subj.len, h,
                                 coll, 'N', *this, que, quelen, quehash );
        if ( status == NATS_IS_NEW ) {
          if ( quelen == 0 )
            this->sub_route.add_pat( npat );
          else
            this->sub_route.add_pat_queue( npat );
        }
        else {
          npat.sub_count = sub_m->refcnt;
          if ( quelen == 0 )
            this->sub_route.notify_pat( npat );
          else
            this->sub_route.notify_pat_queue( npat );
        }
      }
    }
  }
  else {
    if ( this->session_len > 0 ) {
      CatPtr ibx( this->alloc_temp( preflen + 7 + this->session_len + 1 +
                                    msg.sid_len + 1 ) );
      ibx.x( this->prefix, preflen ).s( "_INBOX." )
         .x( this->session, this->session_len ).c( '.' )
         .x( msg.sid, msg.sid_len ).end();

      inbox     = ibx.start;
      inbox_len = ibx.len();
    }

    NatsSubRoute * sub_rt = NULL;
    if ( quelen == 0 )
      status = this->map.put( subj, sid, coll, sub_rt );
    else
      status = this->map.put_que( subj, sid, coll, sub_rt, quehash );
    if ( status == NATS_IS_NEW || status == NATS_OK ||
         ( status == NATS_EXISTS && sub_rt != NULL ) ) {
      NotifyQueue nsub( subj.str, subj.len, inbox, inbox_len, subj.hash(),
                        coll, 'N', *this, que, quelen, quehash );
      if ( status == NATS_IS_NEW ) {
        if ( quelen == 0 )
          this->sub_route.add_sub( nsub );
        else
          this->sub_route.add_sub_queue( nsub );
      }
      else {
        nsub.sub_count = sub_rt->refcnt;
        if ( quelen == 0 )
          this->sub_route.notify_sub( nsub );
        else
          this->sub_route.notify_sub_queue( nsub );
      }
    }
  }
  if ( status > NATS_EXISTS ) {
    fprintf( stderr, "add_sub( %.*s, %.*s ) = %s\n",
             subj.len, subj.str, sid.len, sid.str, nats_status_str( status ) );
  }
}

void
EvNatsService::rem_sid( NatsMsg &msg ) noexcept
{
  NatsStr       sid( msg.sid, msg.sid_len );
  NatsLookup    look;
  NatsSubStatus status;
  bool          coll = false;

  status = this->map.unsub( sid, msg.max_msgs, look, coll );
  if ( status != NATS_NOT_FOUND ) {
    if ( look.rt != NULL ) {
      NotifyQueue nsub( look.rt->value, look.rt->subj_len, NULL, 0, look.hash,
                        coll, 'N', *this, NULL, 0, look.que_hash );
      if ( status == NATS_EXPIRED ) {
        if ( look.que_hash == 0 )
          this->sub_route.del_sub( nsub );
        else
          this->sub_route.del_sub_queue( nsub );
        map.unsub_remove( look );
      }
      else {
        nsub.sub_count = look.rt->refcnt;
        if ( look.que_hash == 0 )
          this->sub_route.notify_unsub( nsub );
        else
          this->sub_route.notify_unsub_queue( nsub );
      }
    }
    else {
      PatternCvt cvt;
      if ( cvt.convert_rv( look.match->value, look.match->subj_len ) == 0 ) {
        NotifyPatternQueue npat( cvt, look.match->value, look.match->subj_len,
                          look.hash, coll, 'N', *this, NULL, 0, look.que_hash );
        if ( status == NATS_EXPIRED ) {
          if ( look.que_hash == 0 )
            this->sub_route.del_pat( npat );
          else
            this->sub_route.del_pat_queue( npat );
          map.unsub_remove( look );
        }
        else {
          npat.sub_count = look.match->refcnt;
          if ( look.que_hash == 0 )
            this->sub_route.notify_unpat( npat );
          else
            this->sub_route.notify_unpat_queue( npat );
        }
      }
    }
  }
}

void
EvNatsService::rem_all_sub( void ) noexcept
{
  RouteLoc           loc;
  NatsStr            sid;
  NatsSubRoute     * r;
  NatsPatternRoute * p;
  SidEntry         * entry;

  for ( r = this->map.sub_tab.first( loc ); r != NULL;
        r = this->map.sub_tab.next( loc ) ) {
    bool coll = this->map.sub_tab.rem_collision( r );
    NotifySub nsub( r->value, r->subj_len, r->hash, coll, 'N', *this );
    this->sub_route.del_sub( nsub );
  }
  for ( r = this->map.qsub_tab.first( loc ); r != NULL;
        r = this->map.qsub_tab.next( loc ) ) {
    bool coll = this->map.qsub_tab.rem_collision( r );
    for ( bool b = r->first_sid( sid ); b; b = r->next_sid( sid ) ) {
      entry = this->map.sid_tab.find( sid.hash(), sid.str, sid.len );
      if ( entry != NULL && entry->que_hash != 0 ) {
        NotifyQueue nsub( r->value, r->subj_len, NULL, 0, r->hash, coll,
                          'N', *this, NULL, 0, entry->que_hash );
        this->sub_route.del_sub_queue( nsub );
      }
    }
  }
  for ( p = this->map.pat_tab.first( loc ); p != NULL;
        p = this->map.pat_tab.next( loc ) ) {
    for ( NatsWildMatch *m = p->list.hd; m != NULL; m = m->next ) {
      PatternCvt cvt;
      if ( cvt.convert_rv( m->value, m->subj_len ) == 0 ) {
        bool coll = this->map.pat_tab.rem_collision( p, m );
        NotifyPattern npat( cvt, m->value, m->subj_len, p->hash,
                            coll, 'N', *this );
        this->sub_route.del_pat( npat );
      }
    }
  }
  for ( p = this->map.qpat_tab.first( loc ); p != NULL;
        p = this->map.qpat_tab.next( loc ) ) {
    for ( NatsWildMatch *m = p->list.hd; m != NULL; m = m->next ) {
      PatternCvt cvt;
      if ( cvt.convert_rv( m->value, m->subj_len ) == 0 ) {
        bool coll = this->map.qpat_tab.rem_collision( p, m );
        for ( bool b = m->first_sid( sid ); b; b = m->next_sid( sid ) ) {
          entry = this->map.sid_tab.find( sid.hash(), sid.str, sid.len );
          if ( entry != NULL && entry->que_hash != 0 ) {
            NotifyPatternQueue npat( cvt, m->value, m->subj_len, p->hash,
                                  coll, 'N', *this, NULL, 0, entry->que_hash );
            this->sub_route.del_pat_queue( npat );
          }
        }
      }
    }
  }
}

int
EvNatsService::fwd_pub( NatsMsg &msg ) noexcept
{
  size_t   preflen = this->prefix_len;
  const char * sub = msg.subject,
             * rep = msg.reply;
  size_t    sublen = msg.subject_len,
            replen = msg.reply_len;
  if ( preflen > 0 ) {
    CatPtr tmp( this->alloc_temp( sublen + preflen + 1 ) );
    tmp.x( this->prefix, preflen ).x( sub, sublen ).end();
    sub     = tmp.start;
    sublen += preflen;
    if ( replen > 0 ) {
      CatPtr tmp( this->alloc_temp( replen + preflen + 1 ) );
      tmp.x( this->prefix, preflen ).x( rep, replen ).end();
      rep     = tmp.start;
      replen += preflen;
    }
  }
  if ( is_nats_debug )
    printf( "fwd_pub sub=%.*s, rep=%.*s msg_len=%u\n",
            (int) sublen, sub, (int) replen, rep, (uint32_t) msg.msg_len );

  uint32_t  h = kv_crc_c( sub, sublen, 0 );
  EvPublish pub( sub, sublen, rep, replen, msg.msg_ptr, msg.msg_len,
                 this->sub_route, *this, h, MD_STRING );
  pub.hdr_len = msg.hdr_len;
  BPData * data = NULL;
  if ( ( this->nats_state & ( NATS_BACKPRESSURE | NATS_BUFFERSIZE ) ) != 0 )
    data = this;
  if ( this->sub_route.forward_msg( pub, data ) )
    return NATS_FLOW_GOOD;
  if ( ! this->bp_in_list() )
    return NATS_FLOW_BACKPRESSURE;
  return NATS_FLOW_STALLED;
}

bool
EvNatsService::on_msg( EvPublish &pub ) noexcept
{
  NatsStr          subj, sid, pre;
  NatsLookup       look;
  NatsMsgTransform xf( pub, sid );
  NatsSubStatus    status;
  bool             b, coll, flow_good = true;

  /* if client does not want to see the msgs it published */
  if ( ! this->user.echo && this->equals( pub.src_route ) )
    return true;

  for ( uint8_t cnt = 0; cnt < pub.prefix_cnt; cnt++ ) {
    uint32_t h = pub.hash[ cnt ];
    if ( pub.subj_hash == h ) {
      subj.set( pub.subject, pub.subject_len, h );
      status = this->map.lookup_publish( subj, look );
      if ( status != NATS_NOT_FOUND ) { /* OK or EXPIRED */
        for ( b = look.rt->first_sid( sid ); b; b = look.rt->next_sid( sid ) ) {
          flow_good &= this->fwd_msg( pub, xf );
        }
        if ( status == NATS_EXPIRED ) {
          status = this->map.expired( look, coll );
          NotifyQueue nsub( subj.str, subj.len, NULL, 0, h, coll, 'N', *this,
                            NULL, 0, look.que_hash );
          if ( status == NATS_EXPIRED ) {
            if ( look.que_hash == 0 )
              this->sub_route.del_sub( nsub );
            else
              this->sub_route.del_sub_queue( nsub );
            this->map.unsub_remove( look );
          }
          else {
            nsub.sub_count = look.rt->refcnt;
            if ( look.que_hash == 0 )
              this->sub_route.notify_unsub( nsub );
            else
              this->sub_route.notify_unsub_queue( nsub );
          }
        }
      }
    }
    else {
      pre.set( pub.subject, pub.prefix[ cnt ], h );
      subj.set( pub.subject, pub.subject_len );
      status = this->map.lookup_pattern( pre, subj, look );

      for (;;) {
        if ( status == NATS_NOT_FOUND )
          break;
        for ( b = look.match->first_sid( sid ); b;
              b = look.match->next_sid( sid ) ) {
          if ( sid.len == 1 && sid.str[ 0 ] == 'I' )
            return this->on_inbox_reply( pub );
          flow_good &= this->fwd_msg( pub, xf );
        }
        if ( status == NATS_EXPIRED ) {
          status = this->map.expired_pattern( look, coll );
          PatternCvt cvt;
          NotifyPatternQueue npat( cvt, look.match->value, look.match->subj_len,
                                  h, coll, 'N', *this, NULL, 0, look.que_hash );
          if ( cvt.convert_rv( look.match->value,
                               look.match->subj_len ) == 0 ) {
            if ( status == NATS_EXPIRED ) {
              if ( look.que_hash == 0 )
                this->sub_route.del_pat( npat );
              else
                this->sub_route.del_pat_queue( npat );
              this->map.unsub_remove( look );
            }
            else {
              npat.sub_count = look.match->refcnt;
              if ( look.que_hash == 0 )
                this->sub_route.notify_unpat( npat );
              else
                this->sub_route.notify_unpat_queue( npat );
            }
          }
          break;
        }
        status = this->map.lookup_next( subj, look );
      }
    }
  }
  return flow_good;
}

bool
EvNatsService::on_inbox_reply( EvPublish &pub ) noexcept
{
  /* if inbox reply */
  const char * sub = pub.subject;
  size_t       off = pub.subject_len;
  while ( off > 0 && sub[ off - 1 ] != '.' )
    off--;
  const char * sid     = &sub[ off ];
  size_t       sid_len = pub.subject_len - off;
  NatsStr sid2( sid, sid_len );
  NatsLookup look;
  if ( this->map.find_by_sid( sid2, look ) == NATS_OK &&
       look.rt != NULL ) {
    EvPublish pub2( pub );
    MDMsgMem  tmp;
    uint32_t  tmp_hash[ 1 ];
    size_t    len = look.rt->subj_len;
    char    * sub = tmp.str_make( len  );

    ::memcpy( sub, look.rt->value, len );
    pub2.subject_len = len;
    pub2.subject     = sub;
    pub2.subj_hash   = look.rt->hash;
    pub2.hash        = tmp_hash;
    pub2.prefix_cnt  = 1;
    tmp_hash[ 0 ]    = pub2.subj_hash;
    return this->on_msg( pub2 );
  }
  return true;
}

bool
EvNatsService::hash_to_sub( uint32_t h,  char *key,  size_t &keylen ) noexcept
{
  NatsSubRoute * rt;
  if ( (rt = this->map.sub_tab.find_by_hash( h )) != NULL ) {
    ::memcpy( key, rt->value, rt->subj_len );
    keylen = rt->subj_len;
    return true;
  }
  return false;
}

bool
EvNatsService::fwd_msg( EvPublish &pub,  NatsMsgTransform &xf ) noexcept
{
  const char  * sid  = xf.sid.str;
  size_t    sid_len  = xf.sid.len;
  const char  * sub  = pub.subject,
              * rep  = (const char *) pub.reply;
  size_t     sublen  = pub.subject_len,
             replen  = pub.reply_len,
             preflen = this->prefix_len;

  if ( sublen < preflen ) {
    fprintf( stderr, "sub %.*s is less than prefix (%u)\n",
             (int) sublen, sub, (int) preflen );
    return true;
  }
  if ( replen != 0 && replen < preflen ) {
    fprintf( stderr, "rep %.*s is less than prefix (%u)\n",
             (int) replen, rep, (int) preflen );
    return true;
  }
  if ( is_nats_debug )
    printf( "fwd_msg sub=%.*s, rep=%.*s msg_len=%u\n",
            (int) sublen, sub, (int) replen, rep, (uint32_t) pub.msg_len );
  sublen -= preflen;
  sub     = &sub[ preflen ];
  if ( replen > 0 ) {
    replen -= preflen;
    rep     = &rep[ preflen ];
  }
  if ( ! xf.is_ready ) {
    xf.is_ready = true;
    if ( pub.pub_status != EV_PUB_NORMAL ) {
      /* start and cycle are normal events */
      if ( pub.pub_status <= EV_MAX_LOSS || pub.pub_status == EV_PUB_RESTART ) {
        if ( this->notify != NULL )
          this->notify->on_data_loss( *this, pub );
      }
    }
    xf.check_transform( this->user.binary );
  }
  size_t msg_len_digits = uint64_digits( xf.msg_len + xf.hdr_len ),
         hdr_len_digits = 0,
         len;

  len = sublen + 1 +           /* <subject> */
        sid_len + 1 +          /* <sid> */
        ( replen > 0 ? replen + 1 : 0 ) + /* [reply] */
        msg_len_digits + 2;    /* <size> \r\n */

  if ( ! xf.is_converted && xf.msg_len + xf.hdr_len > this->recv_highwater ) {
    if ( xf.idx_ref == 0 )
      xf.idx_ref = this->poll.zero_copy_ref( pub.src_route.fd, xf.msg, xf.msg_len );
  }
  if ( xf.idx_ref == 0 )
    len += xf.msg_len + 2;        /* <blob> \r\n */

  if ( xf.hdr_len == 0 ) {
    len += 4; /* MSG */
  }
  else {
    hdr_len_digits = uint64_digits( xf.hdr_len );
    len += 5 +                  /* HMSG */
           hdr_len_digits + 1 + /* <hsize> */
           xf.hdr_len;
  }
  CatPtr p( this->alloc_temp( len ) );

  if ( xf.hdr_len == 0 )
    p.s( "MSG " );
  else
    p.s( "HMSG " );
  p.x( sub, sublen ).c( ' ' )
   .x( sid, sid_len ).c( ' ' );
  if ( replen > 0 )
    p.x( rep, replen ).c( ' ' );
  if ( xf.hdr_len > 0 )
    p.u( xf.hdr_len, hdr_len_digits ).s( " " );
  p.u( xf.msg_len + xf.hdr_len, msg_len_digits ).s( "\r\n" );
  if ( xf.hdr_len > 0 )
    p.b( xf.hdr, xf.hdr_len );

  if ( xf.idx_ref == 0 ) {
    p.b( xf.msg, xf.msg_len ).s( "\r\n" );
    this->append_iov( p.start, len );
  }
  else {
    this->append_ref_iov( p.start, len, xf.msg, xf.msg_len, xf.idx_ref, 2 );
  }
  this->msgs_sent++;
  return this->idle_push_write();
}

void
NatsMsgTransform::transform( void ) noexcept
{
  MDMsg * m = MDMsg::unpack( (void *) this->msg, 0, this->msg_len, 0,
                             NULL, this->spc );
  if ( m == NULL )
    return;

  size_t max_len = ( ( this->msg_len | 15 ) + 1 ) * 16;
  char * start = this->spc.str_make( max_len );
  JsonMsgWriter jmsg( this->spc, start, max_len );
  if ( jmsg.convert_msg( *m ) == 0 && jmsg.finish() ) {
    this->msg     = jmsg.buf;
    this->msg_len = jmsg.off;
    this->is_converted = true;
  }
}

void
EvNatsService::process_close( void ) noexcept
{
  this->client_stats( this->sub_route.peer_stats );
  this->EvSocket::process_close();
}

void
EvNatsService::release( void ) noexcept
{
  if ( ( this->nats_state & NATS_HAS_TIMER ) != 0 )
    this->poll.timer.remove_timer( this->fd, this->timer_id, 0 );
  if ( this->bp_in_list() )
    this->bp_retire( *this );
  this->rem_all_sub();
  this->map.release();
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
  this->EvConnection::release_buffers();
  this->user.release();
  this->timer_id = 0;
}

bool
EvNatsService::timer_expire( uint64_t tid, uint64_t ) noexcept
{
  if ( tid == this->timer_id ) {
    this->nats_state &= ~NATS_HAS_TIMER;
    this->push( EV_PROCESS );
    this->idle_push( EV_READ_LO );
  }
  return false;
}

void
EvNatsService::on_write_ready( void ) noexcept
{
  this->push( EV_PROCESS );
  this->idle_push( EV_READ_LO );
}

void
EvNatsService::read( void ) noexcept
{
  if ( ! this->bp_in_list() ) {
    this->EvConnection::read();
    return;
  }
  this->pop3( EV_READ, EV_READ_HI, EV_READ_LO );
}

void
EvNatsService::set_prefix( const char *pref,  size_t preflen ) noexcept
{
  this->prefix_len = cpyb<MAX_PREFIX_LEN>( this->prefix, pref, preflen );
}

void
EvNatsService::set_service( void *host,  uint16_t svc ) noexcept
{
  this->listen.set_service( host, svc );
}

bool
EvNatsService::get_service( void *host,  uint16_t &svc ) const noexcept
{
  return this->listen.get_service( host, svc );
}

size_t
EvNatsService::get_userid( char userid[ MAX_USERID_LEN ] ) const noexcept
{
  size_t len = 0;
  if ( this->user.user != NULL ) {
    len = min_int( MAX_USERID_LEN - 1, ::strlen( this->user.user ) );
    ::memcpy( userid, this->user.user, len );
  }
  userid[ len ] = '\0';
  return len;
}

bool
EvNatsService::set_session( const char session[ MAX_SESSION_LEN ] ) noexcept
{
  size_t len = ::strlen( session );
  if ( len >= sizeof( this->session ) ) {
    return false;
  }
  this->session_len = len;
  ::memcpy( this->session, session, this->session_len );
  this->session[ this->session_len ] = '\0';

  static char inbox_sid[] = "I";
  CatBuf< 7 + sizeof( this->session ) + 3 > inbox;

  inbox.s( "_INBOX." ).x( session, this->session_len ).s( ".>" ).end();

  NatsMsg msg;
  msg.subject     = inbox.buf;
  msg.subject_len = inbox.len();
  msg.sid         = inbox_sid;
  msg.sid_len     = 1;

  this->add_sub( msg );
  return true;
}

size_t
EvNatsService::get_session( uint16_t svc,
                            char session[ MAX_SESSION_LEN ] ) const noexcept
{
  if ( this->session_len > 0 ) {
    uint16_t tmp = 0;
    if ( this->listen.get_service( NULL, tmp ) && svc == tmp ) {
      ::memcpy( session, this->session, this->session_len );
      session[ this->session_len ] = '\0';
      return this->session_len;
    }
  }
  session[ 0 ] = '\0';
  return 0;
}

size_t
EvNatsService::get_subscriptions( uint16_t svc,  SubRouteDB &subs ) noexcept
{
  RouteLoc       pos,
                 loc;
  NatsSubRoute * r;
  size_t         prelen = this->prefix_len,
                 cnt    = 0;
  uint16_t       tmp    = 0;
  if ( ! this->listen.get_service( NULL, tmp ) || svc != tmp )
    return 0;
  for ( r = this->map.sub_tab.first( pos ); r != NULL;
        r = this->map.sub_tab.next( pos ) ) {
    if ( r->subj_len > prelen ) {
      const char * val = &r->value[ prelen ];
      size_t       len = r->subj_len - prelen;
      uint32_t     h   = kv_crc_c( val, len, 0 );
      subs.upsert( h, val, len, loc );
      if ( loc.is_new )
        cnt++;
    }
  }
  return cnt;
}

size_t
EvNatsService::get_patterns( uint16_t svc,  int pat_fmt,
                             SubRouteDB &pats ) noexcept
{
  RouteLoc           pos,
                     loc;
  NatsPatternRoute * p;
  size_t             prelen = this->prefix_len,
                     cnt    = 0;
  uint16_t           tmp    = 0;
  if ( ! this->listen.get_service( NULL, tmp ) || svc != tmp )
    return 0;
  if ( pat_fmt != RV_PATTERN_FMT )
    return 0;
  for ( p = this->map.pat_tab.first( pos ); p != NULL;
        p = this->map.pat_tab.next( pos ) ) {
    for ( NatsWildMatch *m = p->list.hd; m != NULL; m = m->next ) {
      if ( m->subj_len > prelen ) {
        const char * val = &m->value[ prelen ];
        size_t       len = m->subj_len - prelen;
        uint32_t     h   = kv_crc_c( val, len, 0 );
        pats.upsert( h, val, len, loc );
        if ( loc.is_new )
          cnt++;
      }
    }
  }
  return cnt;
}

void
EvNatsService::parse_connect( const char *buf,  size_t bufsz ) noexcept
{
  const char  * start,
              * end;
  MDMsgMem      mem;
  JsonMsg     * msg;
  MDFieldIter * iter;
  MDName        name;
  MDReference   mref;

  if ( bufsz == 0 )
    goto do_notify;
  else if ( is_nats_debug )
    printf( "%.*s", (int) bufsz, buf );

  if ( (start = (const char *) ::memchr( buf, '{', bufsz )) == NULL )
    goto do_notify;
  bufsz -= start - buf;
  for ( end = &start[ bufsz ]; end > start; )
    if ( *--end == '}' )
      break;

  if ( end <= start )
    goto do_notify;

  msg = JsonMsg::unpack( (void *) start, 0, &end[ 1 ] - start, 0, NULL, mem );
  if ( msg == NULL )
    goto do_notify;
  if ( msg->get_field_iter( iter ) != 0 )
    goto do_notify;
  if ( iter->first() != 0 )
    goto do_notify;

  do {
    if ( iter->get_name( name ) == 0 ) {
      if ( name.fnamelen <= 4 ) /* go:"str" */
        continue;

      switch ( ( unaligned<uint32_t>( name.fname ) ) & 0xdfdfdfdf ) {
        case NATS_JS_VERBOSE: /* verbose:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.verbose = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_PEDANTIC: /* pedantic:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.pedantic = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_TLS_REQUIRE: /* tls_require:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.tls_require = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_ECHO: /* echo:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.echo = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_HEADERS: /* headers:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.headers = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_NO_RESPOND: /* no_responders:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.no_responders = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_BINARY: /* nary:false */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_BOOLEAN )
            this->user.binary = ( mref.fptr[ 0 ] != 0 );
          break;
        case NATS_JS_PROTOCOL: /* proto:1 */
          if ( iter->get_reference( mref ) == 0 )
            cvt_number( mref, this->user.protocol );
          break;
        case NATS_JS_NAME: /* name:"str" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING ) {
            this->user.save_string( this->user.name, mref.fptr, mref.fsize );
            if ( ! this->user.binary ) {
              if ( ( mref.fsize >= sizeof( "_bin" ) &&
                     ::memcmp( &((char *) mref.fptr)[ mref.fsize - 4 ], "_bin", 4 ) == 0 ) ||

                   ( mref.fsize >= sizeof( "_binary" ) &&
                     ::memcmp( &((char *) mref.fptr)[ mref.fsize - 7 ], "_binary", 7 ) == 0 ) ) {
                this->user.binary = true;
              }
            }
          }
          break;
        case NATS_JS_LANG: /* lang:"C" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING )
            this->user.save_string( this->user.lang, mref.fptr, mref.fsize );
          break;
        case NATS_JS_VERSION: /* version:"str" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING )
            this->user.save_string( this->user.version, mref.fptr, mref.fsize );
          break;
        case NATS_JS_USER: /* user:"str" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING )
            this->user.save_string( this->user.user, mref.fptr, mref.fsize );
          break;
        case NATS_JS_PASS: /* pass:"str" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING )
            this->user.save_string( this->user.pass, mref.fptr, mref.fsize );
          break;
        case NATS_JS_AUTH_TOKEN: /* auth_token:"str" */
          if ( iter->get_reference( mref ) == 0 && mref.ftype == MD_STRING )
            this->user.save_string( this->user.auth_token, mref.fptr,
                                    mref.fsize );
          break;
        default:
          break;
      }
    }
  } while ( iter->next() == 0 );
do_notify:;
  if ( this->user.user == NULL || ::strlen( this->user.user ) == 0 )
    this->user.save_string( this->user.user, "nobody", 6 );
  if ( this->user.stamp == 0 ) {
    this->user.stamp = this->active_ns;
    if ( this->notify != NULL )
      this->notify->on_connect( *this );
  }
}

NatsWildMatch *
NatsWildMatch::create( NatsStr &subj,  NatsStr &sid,
                       kv::PatternCvt &cvt ) noexcept
{
  pcre2_real_code_8       * re = NULL;
  pcre2_real_match_data_8 * md = NULL;
  size_t erroff;
  int    error;
  bool   pattern_success = false;
  /* if prefix matches, no need for pcre2 */
  if ( cvt.prefixlen + 1 == subj.len && subj.str[ cvt.prefixlen ] == '>' )
    pattern_success = true;
  else {
    re = pcre2_compile( (uint8_t *) cvt.out, cvt.off, 0, &error,
                        &erroff, 0 );
    if ( re == NULL ) {
      fprintf( stderr, "re failed\n" );
    }
    else {
      md = pcre2_match_data_create_from_pattern( re, NULL );
      if ( md == NULL )
        fprintf( stderr, "md failed\n" );
      else
        pattern_success = true;
    }
  }
  if ( pattern_success ) {
    size_t sz = sizeof( NatsWildMatch ) + subj.len + sid.len + 2 - 2;
    void * p  = ::malloc( sz );
    if ( p != NULL )
      return new ( p ) NatsWildMatch( subj, sid, re, md );
  }
  if ( md != NULL )
    pcre2_match_data_free( md );
  if ( re != NULL )
    pcre2_code_free( re );
  return NULL;
}

NatsWildMatch::~NatsWildMatch()
{
  if ( this->md != NULL )
    pcre2_match_data_free( this->md );
  if ( this->re != NULL )
    pcre2_code_free( this->re );
}

NatsWildMatch *
NatsWildMatch::resize_sid( NatsWildMatch *m,  NatsStr &sid ) noexcept
{
  size_t sz = (size_t) m->sid_off + (size_t) sid.len + 2;
  if ( sz > 0xffffU )
    return NULL;
  void * p = ::realloc( (void *) m, sizeof( NatsWildMatch ) + sz - 2 );
  if ( p == NULL )
    return NULL;
  m = (NatsWildMatch *) p;
  m->len += sid.len + 2;
  m->add_sid( sid );
  return m;
}

bool
NatsWildMatch::match( NatsStr &subj ) noexcept
{
  return ( pcre2_match( this->re, (const uint8_t *) subj.str,
                        subj.len, 0, 0, this->md, 0 ) == 1 );
}

void
SidEntry::print( void ) noexcept
{
  printf( "%.*s", this->len, this->value );
  if ( this->max_msgs != 0 )
    printf( "[cnt=%" PRIu64 ",max=%" PRIu64 "]", this->msg_cnt, this->max_msgs);
  if ( this->pref_hash != 0 )
    printf( "[pattern]" );
  printf( "\n" );
}

void
NatsSubData::print_sids( void ) noexcept
{
  NatsStr sid;
  bool b;
  printf( "[refs=%u][cnt=%" PRIu64 "]", this->refcnt, this->msg_cnt );
  if ( this->max_msgs != 0 )
    printf( "[max=%" PRIu64 "]", this->max_msgs );
  printf( ":" );
  for ( b = this->first_sid( sid ); b; b = this->next_sid( sid ) ) {
    printf( " %.*s", sid.len, sid.str );
  }
  printf( "\n" );
}

void
NatsSubRoute::print( void ) noexcept
{
  printf( "%.*s", this->len, this->value );
  this->print_sids();
}

void
NatsPatternRoute::print( void ) noexcept
{
  NatsWildMatch * w;
  for ( w = this->list.hd; w; w = w->next ) {
    w->print();
    w->print_sids();
  }
}

void
NatsWildMatch::print( void ) noexcept
{
  printf( "%.*s", this->len, this->value );
}

void
NatsSubMap::print( void ) noexcept
{
  RouteLoc           loc;
  SidEntry         * s;
  NatsSubRoute     * r;
  NatsPatternRoute * p;

  printf( "-- sids:\n" );
  for ( s = this->sid_tab.first( loc ); s; s = this->sid_tab.next( loc ) ) {
    s->print();
  }
  printf( "-- subs:\n" );
  for ( r = this->sub_tab.first( loc ); r; r = this->sub_tab.next( loc ) ) {
    r->print();
  }
  printf( "-- patterns:\n" );
  for ( p = this->pat_tab.first( loc ); p; p = this->pat_tab.next( loc ) ) {
    p->print();
  }
}

const char *
rai::natsmd::nats_status_str( NatsSubStatus status )
{
  switch ( status ) {
    case NATS_OK          : return "nats_ok";
    case NATS_IS_NEW      : return "nats_is_new";
    case NATS_EXPIRED     : return "nats_expired";
    case NATS_NOT_FOUND   : return "nats_not_found";
    case NATS_EXISTS      : return "nats_exists";
    case NATS_TOO_MANY    : return "nats_too_many";
    case NATS_BAD_PATTERN : return "nats_bad_pattern";
    default: return "??";
  }
}

