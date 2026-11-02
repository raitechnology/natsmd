#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <natsmd/ev_nats_client.h>
#include <natsmd/submgr.h>
#include <raimd/md_msg.h>
#include <raikv/ev_publish.h>

using namespace rai;
using namespace kv;
using namespace natsmd;
using namespace md;

/* nats client callback closure */
struct NatsDataCallback : public EvConnectionNotify, public NatsClientCB,
                          public EvTimerCallback, public NatsSubscriptionListener {
  EvPoll           & poll;            /* poll loop data */
  EvNatsClient     & client;          /* connection to nats */
  NatsSubscriptionDB sub_db;
  const char      ** sub;             /* subject strings */
  size_t             sub_count;       /* count of sub[] */
  bool               top,
                     snap,
                     tic;

  NatsDataCallback( EvPoll &p,  EvNatsClient &c,  const char **s,  size_t cnt,
                    bool t,  bool sn,  bool x )
    : poll( p ), client( c ), sub_db( c, this ), sub( s ), sub_count( cnt ),
      top( t ), snap( sn ), tic( x ) {}

  /* after CONNECT is sent */
  virtual void on_connect( EvSocket &conn ) noexcept;
  /* subscribe _NATS.<KIND>.> */
  void start_subscriptions( void ) noexcept;
  /* when signalled, unsubscribe */
  void on_unsubscribe( void ) noexcept;
  /* when disconnected */
  virtual void on_shutdown( EvSocket &conn,  const char *err,
                            size_t err_len ) noexcept;
  /* process events timer */
  virtual bool timer_cb( uint64_t timer_id,  uint64_t event_id ) noexcept;
  /* message from network */
  virtual bool on_nats_msg( EvPublish &pub ) noexcept;
  /* new listen start */
  virtual void on_listen_start( Start &add ) noexcept;
  virtual void on_listen_stop ( Stop  &rem ) noexcept;
  virtual void on_snapshot    ( Snap  &snp ) noexcept;
  virtual void on_tic_reply   ( Tic   &tic ) noexcept;
  const char * ts( uint32_t mono,  const char *str,  char *buf ) noexcept;
};

/* called after the connection is established */
void
NatsDataCallback::on_connect( EvSocket &conn ) noexcept
{
  int len = (int) conn.get_peer_address_strlen();
  printf( "Connected: %.*s\n", len, conn.peer_address.buf );
  fflush( stdout );
  for ( size_t i = 0; i < this->sub_count; i++ )
    this->sub_db.add_wildcard( this->sub[ i ] );
  this->start_subscriptions();
}

/* start the advisory subscriptions, filtered by the command line wildcards */
void
NatsDataCallback::start_subscriptions( void ) noexcept
{
  this->sub_db.start_subscriptions( this->sub_count == 0, this->snap,
                                    this->tic );
  this->poll.timer.add_timer_seconds( *this, 3, 1, 0 );
}

/* if ctrl-c, program signalled, unsubscribe the subs */
void
NatsDataCallback::on_unsubscribe( void ) noexcept
{
  this->sub_db.stop_subscriptions();
}

const char *
NatsDataCallback::ts( uint32_t mono,  const char *str,  char *buf ) noexcept
{
  if ( mono == 0 ) {
    buf[ 0 ] = '\0';
    return buf;
  }
  time_t t = this->client.poll.mono_to_utc_secs( mono );
  struct tm tm;
  localtime_r( &t, &tm );
  ::snprintf( buf, 32, "%02d:%02d:%02d",
    tm.tm_hour, tm.tm_min, tm.tm_sec );
  return str;
}

/* process events timer, every 3 seconds */
bool
NatsDataCallback::timer_cb( uint64_t ,  uint64_t ) noexcept
{
  NatsSubscriptionDB & db = this->sub_db;
  db.process_events();

  if ( this->top ) {
    printf( "\033[H\033[J" );
    printf( "sessions %u, subscriptions %u\n", db.sessions.active,
            db.subscriptions.active );
    NatsSessionEntry * entry;
    NatsSubscription * script;
    size_t             pos, pos2;

    if ( (entry = db.first_session( pos )) != NULL ) {
      do {
        char b1[ 32 ], b2[ 32 ], b3[ 32 ];
        const char * ref_str   = this->ts( entry->ref_mono   , ", ref: "  , b1 ),
                   * start_str = this->ts( entry->start_mono , ", start: ", b2 ),
                   * query_str = this->ts( entry->query_mono , ", query: ", b3 );
        printf( "  id %.*s user %s state:%s cn:%u sc:%u sx:%08X%s%s%s%s%s%s, "
                "age:%u\n",
            entry->len, entry->value,
            entry->user_id != NULL ? entry->user_id : "",
            NatsSessionEntry::get_session_state_str( entry->state ),
            entry->conn_count, entry->sub_count, entry->sub_digest,
            ref_str, b1, start_str, b2, query_str, b3,
            db.cur_mono - entry->ref_mono );
        if ( (script = db.first_subject( *entry, pos2 )) != NULL ) {
          do {
            printf( "    - %.*s (%u)\n", script->len, script->value,
                    script->refcnt );
          } while ( (script = db.next_subject( *entry, pos2 )) != NULL );
        }
      } while ( (entry = db.next_session( pos )) != NULL );
    }
    fflush( stdout );
  }
  return true; /* return false to disable recurrent timer */
}

void
NatsDataCallback::on_listen_start( Start &add ) noexcept
{
  if ( this->top )
    return;
  const char *u = add.session.user_id != NULL ? add.session.user_id : "";
  if ( add.reply_len == 0 ) {
    printf( "%sstart %.*s refs %u from %.*s %s\n",
      add.is_listen_start ? "listen_" : "assert_",
      add.sub.len, add.sub.value, add.sub.refcnt,
      add.session.len, add.session.value, u );
  }
  else {
    printf( "%sstart %.*s reply %.*s refs %u from %.*s %s\n",
      add.is_listen_start ? "listen_" : "assert_",
      add.sub.len, add.sub.value, add.reply_len, add.reply, add.sub.refcnt,
      add.session.len, add.session.value, u );
  }
  fflush( stdout );
}

void
NatsDataCallback::on_listen_stop( Stop &rem ) noexcept
{
  if ( this->top )
    return;
  printf( "%sstop %.*s refs %u from %.*s%s %s\n",
    rem.is_listen_stop ? "listen_" : "assert_",
    rem.sub.len, rem.sub.value, rem.sub.refcnt,
    rem.session.len, rem.session.value, rem.is_orphan ? " orphan" : "",
    rem.session.user_id != NULL ? rem.session.user_id : "" );
  fflush( stdout );
}

void
NatsDataCallback::on_snapshot( Snap &snp ) noexcept
{
  if ( this->top )
    return;
  NatsSessionEntry * sess = snp.session;
  printf( "snap %.*s reply %.*s refs %u flags %u from %.*s %s\n",
    snp.sub.len, snp.sub.value, snp.reply_len, snp.reply, snp.sub.refcnt,
    snp.flags,
    sess != NULL ? sess->len : 0, sess != NULL ? sess->value : "",
    sess != NULL && sess->user_id != NULL ? sess->user_id : "" );
  fflush( stdout );
}

void
NatsDataCallback::on_tic_reply( Tic &tic ) noexcept
{
  if ( this->top )
    return;
  printf( "tic %.*s reply %.*s\n",
    tic.sub.len, tic.sub.value, tic.reply_len, tic.reply );
  fflush( stdout );
}

/* when client connection stops */
void
NatsDataCallback::on_shutdown( EvSocket &conn,  const char *err,
                               size_t errlen ) noexcept
{
  int len = (int) conn.get_peer_address_strlen();
  printf( "Shutdown: %.*s %.*s\n",
          len, conn.peer_address.buf, (int) errlen, err );
  /* if disconnected by tcp, usually a reconnect protocol, but this just exits*/
  if ( this->poll.quit == 0 )
    this->poll.quit = 1; /* causes poll loop to exit */
}

bool
NatsDataCallback::on_nats_msg( EvPublish &pub ) noexcept
{
  this->sub_db.process_pub( pub );
  return true;
}

static const char *
get_arg( int &x, int argc, const char *argv[], int b, const char *f,
         const char *g, const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ ) {
    if ( ::strcmp( f, argv[ i ] ) == 0 || ::strcmp( g, argv[ i ] ) == 0 ) {
      if ( x < i + b + 1 )
        x = i + b + 1;
      return argv[ i + b ];
    }
  }
  return def; /* default value */
}

int
main( int argc, const char *argv[] )
{
  SignalHandler sighndl;
  int x = 1;
  const char * host    = get_arg( x, argc, argv, 1, "-d", "-host", "tcp:4222" ),
             * name    = get_arg( x, argc, argv, 1, "-n", "-name", "natsmd_subtop"),
             * user    = get_arg( x, argc, argv, 1, "-u", "-user", "nobody" ),
             * pass    = get_arg( x, argc, argv, 1, "-z", "-pass", NULL ),
             * token   = get_arg( x, argc, argv, 1, "-k", "-token", NULL ),
             * log     = get_arg( x, argc, argv, 1, "-l", "-log", NULL ),
             * top     = get_arg( x, argc, argv, 0, "-t", "-top", NULL ),
             * snap    = get_arg( x, argc, argv, 0, "-s", "-snap", NULL ),
             * tic     = get_arg( x, argc, argv, 0, "-x", "-tic", NULL ),
             * adv     = get_arg( x, argc, argv, 0, "-a", "-advisory", NULL ),
             * help    = get_arg( x, argc, argv, 0, "-h", "-help", 0 );
  int first_sub = x, idle_count = 0;

  if ( help != NULL ) {
    fprintf( stderr,
 "%s [-d host] [-n name] [-u user] [-z pass] [-k token] [-l log] [-t] [-s] "
                                                   "[-x] [-a] subject ...\n"
             "  -d host    = nats server to connect\n"
             "  -n name    = connect name\n"
             "  -u user    = user name\n"
             "  -z pass    = user pass\n"
             "  -k token   = auth token\n"
             "  -l log     = write to debug log, - = no file\n"
             "  -t         = update with top format\n"
             "  -s         = monitor _SNAP.<subject> requests\n"
             "  -x         = monitor _TIC.REPLY.> replies\n"
             "  -a         = publish this session's advisories too\n"
             "  subject    = subject wildcards to monitor\n"
             "Monitors _NATS.START/STATUS/STOP.<session> and\n"
             "_NATS.LISTEN.START/STOP.<session> from clients with advisories\n"
             "enabled, queries _INBOX.<session>.SUBS to resync\n", argv[ 0 ] );
    return 1;
  }

  EvPoll poll;
  poll.init( 5, false );

  EvNatsClientParameters parm( host, name, user, pass, token );
  EvNatsClient           conn( poll );
  NatsDataCallback       data( poll, conn, &argv[ first_sub ], argc - first_sub,
                               top != NULL, snap != NULL, tic != NULL );
  MDOutput               mout;

  if ( adv != NULL )
    parm.advisory = 1;
  if ( log != NULL ) {
    if ( log[ 0 ] != '-' )
      mout.open( log, "w" );
    data.sub_db.mout = &mout;
  }
  /* connect to server */
  if ( ! conn.nats_connect( parm, &data, &data ) ) {
    fprintf( stderr, "Failed to connect to nats server\n" );
    return 1;
  }
  /* handle ctrl-c */
  sighndl.install();
  for (;;) {
    /* loop 5 times before quiting, time to flush writes */
    if ( poll.quit >= 5 && idle_count > 0 )
      break;
    /* dispatch network events */
    int idle = poll.dispatch();
    if ( idle == EvPoll::DISPATCH_IDLE )
      idle_count++;
    else
      idle_count = 0;
    /* wait for network events */
    poll.wait( idle_count > 255 ? 100 : 0 );
    if ( sighndl.signaled ) {
      if ( poll.quit == 0 )
        data.on_unsubscribe();
      poll.quit++;
    }
  }
  return 0;
}
