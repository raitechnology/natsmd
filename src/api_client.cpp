/* Copyright (c) 2026 Rai Technology.  All rights reserved.
 *  http://www.raitechnology.com
 *
 * natsmd_api_client -- sample / test for the natsapi: connect, subscribe
 * subjects (or wildcards), print what arrives; optionally publish a
 * message (-p) and / or a request with an inbox reply (-i).  Messages are
 * decoded with a sass dictionary: from cfiles (-c path or $cfile_path), or
 * requested on _TIC.REPLY.SASS.DATA.DICTIONARY before subscribing, the way
 * natsmd_client and sassrv subrv7test do; -x skips it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <raimd/md_msg.h>
#include <raimd/rv_msg.h>
#include <raimd/md_dict.h>
#include <raimd/cfile.h>
#include <raimd/app_a.h>
#include <raimd/enum_def.h>
#include <natsmd/natsapi.h>

using namespace rai;
using namespace md;

static volatile int quit;
static int          quiet;
static uint32_t     msg_count, max_msgs;
static MDDict     * dict;          /* decodes messages, NULL = no dict */
static int          have_dict;     /* network dictionary arrived */

static const char   DICT_SUBJ[]     = "_TIC.REPLY.SASS.DATA.DICTIONARY";
static const double DICT_WAIT_SECS  = 3.0;  /* per request */
static const int    DICT_TRIES      = 2;    /* requests before giving up */
static const int    MAX_SUBJECTS    = 64;   /* ev[] */

static void
sig_handler( int )
{
  quit = 1;
}

static const char *
class_str( natsMsgClass c )
{
  switch ( c ) {
    case NATS_MSG_DATA:           return "DATA";
    case NATS_MSG_TRANSPORT_UP:   return "TRANSPORT_UP";
    case NATS_MSG_TRANSPORT_DOWN: return "TRANSPORT_DOWN";
    default:                      return "?";
  }
}

static void
on_msg( natsEvent,  natsMsg msg,  void *closure )
{
  const char   * subject = "", * reply = "", * text = "";
  natsMsgClass   cls = NATS_MSG_DATA;
  const void   * data = NULL;
  uint32_t       len = 0, enc = 0;

  natsMsg_GetSubject( msg, &subject );
  natsMsg_GetMsgClass( msg, &cls );
  natsMsg_GetStatusText( msg, &text );

  if ( cls != NATS_MSG_DATA ) {
    printf( "## %s: %s\n", class_str( cls ), text );
    fflush( stdout );
    return;
  }
  msg_count++;
  if ( quiet )
    return;
  natsMsg_GetReplySubject( msg, &reply );
  natsMsg_GetData( msg, &data, &len );
  natsMsg_GetMsgEnc( msg, &enc );
  printf( "## %s%s%s%s len=%u enc=0x%x%s\n", subject,
          reply[ 0 ] != '\0' ? " (reply: " : "", reply,
          reply[ 0 ] != '\0' ? ")" : "", len, enc,
          closure != NULL ? " [inbox]" : "" );
  if ( len == 0 ) {
    fflush( stdout );
    return;
  }
  MDMsgMem mem;
  MDMsg  * m = MDMsg::unpack( (void *) data, 0, len, 0, dict, mem );
  MDOutput out;
  if ( m == NULL )
    out.print_hex( data, len );
  else
    m->print( &out );
  fflush( stdout );
}

/* the reply to the _TIC.REPLY.SASS.DATA.DICTIONARY request */
static void
on_dict( natsEvent,  natsMsg msg,  void * )
{
  natsMsgClass cls  = NATS_MSG_DATA;
  const void * data = NULL;
  uint32_t     len  = 0;

  natsMsg_GetMsgClass( msg, &cls );
  if ( cls != NATS_MSG_DATA || have_dict )
    return;
  natsMsg_GetData( msg, &data, &len );
  MDMsgMem mem;
  MDMsg  * m = MDMsg::unpack( (void *) data, 0, len, 0, NULL, mem );
  if ( m == NULL ) {
    fprintf( stderr, "dict unpack error, len %u\n", len );
    return;
  }
  MDDictBuild dict_build;
  if ( CFile::unpack_sass( dict_build, m ) != 0 ) {
    fprintf( stderr, "dict index error\n" );
    return;
  }
  dict_build.index_dict( "cfile", dict );
  have_dict = 1;
  printf( "received dictionary, len %u\n", len );
  fflush( stdout );
}

/* load cfile (and app_a for marketfeed) dictionaries from path */
static void
load_cfile_dict( const char *path )
{
  MDDictBuild dict_build;
  if ( AppA::parse_path( dict_build, path, "RDMFieldDictionary" ) == 0 ) {
    EnumDef::parse_path( dict_build, path, "enumtype.def" );
    dict_build.index_dict( "app_a", dict );
  }
  dict_build.clear_build();
  if ( CFile::parse_path( dict_build, path, "tss_fields.cf" ) == 0 ) {
    CFile::parse_path( dict_build, path, "tss_records.cf" );
    dict_build.index_dict( "cfile", dict );
  }
  if ( dict != NULL && dict->dict_type[ 0 ] == 'c' )
    printf( "loaded dictionary from cfiles in %s\n", path );
  else
    printf( "no cfile dictionary in %s\n", path );
}

/* request the sass dictionary, dispatch until it arrives or times out */
static void
request_dict( natsTransport t,  natsQueue q )
{
  char        inbox[ NATS_MAX_INBOX_LEN ];
  natsEvent   dict_ev = 0;
  nats_status st;

  natsTransport_CreateInbox( t, inbox, sizeof( inbox ) );
  st = natsEvent_CreateListener( &dict_ev, q, t, inbox, NATS_LISTEN_DEFAULT,
                                 on_dict, NULL );
  if ( st != NATS_OK ) {
    fprintf( stderr, "dict inbox %s: %s\n", inbox, natsStatus_GetText( st ) );
    return;
  }
  for ( int i = 0; i < DICT_TRIES && ! have_dict && ! quit; i++ ) {
    st = natsTransport_Send( t, DICT_SUBJ, inbox, "x", 1, 0 );
    printf( "request %s reply %s: %s\n", DICT_SUBJ, inbox,
            natsStatus_GetText( st ) );
    fflush( stdout );
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    double t0 = ts.tv_sec + ts.tv_nsec / 1e9, now = t0;
    while ( ! have_dict && ! quit && now - t0 < DICT_WAIT_SECS ) {
      natsQueue_TimedDispatch( q, 0.1 );
      clock_gettime( CLOCK_MONOTONIC, &ts );
      now = ts.tv_sec + ts.tv_nsec / 1e9;
    }
    if ( ! have_dict )
      printf( "dict request timeout%s\n",
              i + 1 < DICT_TRIES ? ", trying again" : ", starting subs" );
  }
  natsEvent_Destroy( dict_ev );
}

static void
on_timer( natsEvent,  natsMsg,  void * )
{
  printf( "## timer\n" );
  fflush( stdout );
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
main( int argc,  const char *argv[] )
{
  natsTransportParams parms;
  nats_InitTransportParams( &parms );

  int x = 1;
  const char * host        = get_arg( x, argc, argv, 1, "-d", "-host", "tcp:4222" ),
             * name        = get_arg( x, argc, argv, 1, "-N", "-name", "api_client"),
             * user        = get_arg( x, argc, argv, 1, "-u", "-user", "nobody" ),
             * pass        = get_arg( x, argc, argv, 1, "-z", "-pass", NULL ),
             * token       = get_arg( x, argc, argv, 1, "-a", "-token", NULL ),
             * path        = get_arg( x, argc, argv, 1, "-c", "-cfile", NULL ),
             * nodict      = get_arg( x, argc, argv, 0, "-x", "-nodict", NULL ),
             * advisory    = get_arg( x, argc, argv, 0, "-A", "-advisory", NULL ),
             * pub_subject = get_arg( x, argc, argv, 1, "-p", "-pub_subject", NULL ),
             * pub_text    = get_arg( x, argc, argv, 1, "-m", "-pub_text", "hello" ),
             * req_subject = get_arg( x, argc, argv, 1, "-i", "-req_subject", NULL ),
             * queue_group = get_arg( x, argc, argv, 1, "-g", "-queue_group", NULL ),
             * max_msgs_s  = get_arg( x, argc, argv, 1, "-n", "-max_msgs", NULL ),
             * secs_s      = get_arg( x, argc, argv, 1, "-t", "-secs", NULL ),
             * timer_secs_s= get_arg( x, argc, argv, 1, "-T", "-timer_secs", NULL ),
             * quiet_s     = get_arg( x, argc, argv, 0, "-q", "-quiet", NULL ),
             * help        = get_arg( x, argc, argv, 0, "-h", "-help", 0 );

  const char ** subjects   = NULL;
  int           nsubj = 0;
  double        secs  = 0, timer_secs = 0;

  if ( help != NULL ) {
    fprintf( stderr,
      "%s [-d host:port] [-u user] [-z pass] [-a token] [-N name] [-g group]\n"
      "   [-c cfile_path] [-x] [-p subject [-m text]] [-i subject] [-q]\n"
      "   [-n msgs] [-t secs] [-T secs] [-A [secs]] subject ...\n"
      "  -d  server, default 127.0.0.1:4222\n"
      "  -N  CONNECT name\n"
      "  -c  load the dictionary from cfiles in path ($cfile_path)\n"
      "  -x  don't load a dictionary, otherwise request one on\n"
      "      _TIC.REPLY.SASS.DATA.DICTIONARY before subscribing\n"
      "  -A  session advisories _NATS.<KIND>.<session> and the _INBOX.<session>.SUBS\n"
      "      rpc, STATUS every secs (90)\n"
      "  -g  subscribe as a member of NATS queue group\n"
      "  -p  publish an RVMSG { text } on subject once connected\n"
      "  -m  the text to publish (hello)\n"
      "  -i  send a request on subject with an inbox reply, print replies\n"
      "  -q  count only\n"
      "  -n  quit after msgs messages\n"
      "  -t  quit after secs\n"
      "  -T  a timer event every secs\n"
      "  subject  subscribe (wildcards A.*.C, A.> allowed)\n", argv[ 0 ] );
    return 1;
  }
  subjects = &argv[ x ];
  nsubj    = argc - x;
  if ( nsubj > MAX_SUBJECTS ) {
    fprintf( stderr, "too many subjects, max %d\n", MAX_SUBJECTS );
    return 1;
  }
  parms.daemon     = host;
  parms.user       = user;
  parms.password   = pass;
  parms.auth_token = token;
  parms.name       = name;
  parms.advisory   = ( advisory ? 1 : 0 );

  quiet      = ( quiet_s ? 1 : 0 );
  max_msgs   = ( max_msgs_s ? (uint32_t) atoi( max_msgs_s ) : 0 );
  secs       = ( secs_s ? atof( secs_s ) : 0 );
  timer_secs = ( timer_secs_s ? atof( timer_secs_s ) : 0 );

  signal( SIGINT, sig_handler );
  signal( SIGTERM, sig_handler );

  nats_status st = nats_Open();
  if ( st != NATS_OK ) {
    fprintf( stderr, "nats_Open: %s\n", natsStatus_GetText( st ) );
    return 1;
  }
  natsTransport t;
  natsQueue     q = 0;
  natsEvent     state_ev = 0, timer_ev = 0, inbox_ev = 0, ev[ 64 ];
  st = natsTransport_Create( &t, &parms );
  if ( st != NATS_OK ) {
    fprintf( stderr, "natsTransport_Create: %s\n", natsStatus_GetText( st ) );
    return 1;
  }
  natsQueue_Create( &q );
  natsTransport_SetStateListener( t, q, on_msg, NULL, &state_ev );

  if ( nodict == NULL &&
       ( path != NULL || (path = ::getenv( "cfile_path" )) != NULL ) )
    load_cfile_dict( path );
  if ( timer_secs > 0 )
    natsEvent_CreateTimer( &timer_ev, q, on_timer, timer_secs, NULL );

  printf( "natsapi %s: connecting to %s\n", nats_Version(),
          parms.daemon != NULL ? parms.daemon : "127.0.0.1:4222" );
  st = natsTransport_WaitConnected( t, 10.0 );
  if ( st != NATS_OK ) {
    fprintf( stderr, "connect: %s\n", natsStatus_GetText( st ) );
    return 1;
  }
  uint32_t max_payload = 0;
  natsTransport_GetMaxPayload( t, &max_payload );
  printf( "connected, max_payload %u\n", max_payload );

  /* without a cfile dict, ask the network for one before subscribing, so
   * the initial values decode */
  if ( nodict == NULL && ( dict == NULL || dict->dict_type[ 0 ] != 'c' ) )
    request_dict( t, q );

  for ( int i = 0; i < nsubj; i++ ) {
    st = natsEvent_CreateQueueListener( &ev[ i ], q, t, subjects[ i ],
                                        queue_group, NATS_LISTEN_DEFAULT,
                                        on_msg, NULL );
    if ( st != NATS_OK )
      printf( "listen %s: %s\n", subjects[ i ], natsStatus_GetText( st ) );
    else
      printf( "listen %s\n", subjects[ i ] );
  }

  /* an RVMSG { text : "..." } payload */
  MDMsgMem    mem;
  char        buf[ 1024 ];
  RvMsgWriter w( mem, buf, sizeof( buf ) );
  w.append_string( "text", 5, pub_text, ::strlen( pub_text ) + 1 );
  size_t len = w.update_hdr();

  if ( req_subject != NULL ) {
    char inbox[ NATS_MAX_INBOX_LEN ];
    natsTransport_CreateInbox( t, inbox, sizeof( inbox ) );
    natsEvent_CreateListener( &inbox_ev, q, t, inbox, NATS_LISTEN_DEFAULT,
                              on_msg, (void *) inbox );
    st = natsTransport_Send( t, req_subject, inbox, w.buf, (uint32_t) len,
                             RVMSG_TYPE_ID );
    printf( "request %s reply %s: %s\n", req_subject, inbox,
            natsStatus_GetText( st ) );
  }
  if ( pub_subject != NULL ) {
    natsMsg m;
    natsMsg_Create( &m );
    natsMsg_SetSendSubject( m, pub_subject );
    natsMsg_SetData( m, w.buf, (uint32_t) len, RVMSG_TYPE_ID );
    st = natsTransport_SendMsg( t, m );
    natsMsg_Destroy( m );
    printf( "publish %s: %s\n", pub_subject, natsStatus_GetText( st ) );
  }
  fflush( stdout );

  double t0 = 0;
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  t0 = ts.tv_sec + ts.tv_nsec / 1e9;
  while ( ! quit ) {
    natsQueue_TimedDispatch( q, 0.1 );
    if ( max_msgs != 0 && msg_count >= max_msgs )
      break;
    if ( secs > 0 ) {
      clock_gettime( CLOCK_MONOTONIC, &ts );
      if ( ts.tv_sec + ts.tv_nsec / 1e9 - t0 >= secs )
        break;
    }
  }
  printf( "%u messages\n", msg_count );
  for ( int i = 0; i < nsubj; i++ )
    natsEvent_Destroy( ev[ i ] );
  if ( inbox_ev != 0 )
    natsEvent_Destroy( inbox_ev );
  if ( timer_ev != 0 )
    natsEvent_Destroy( timer_ev );
  natsEvent_Destroy( state_ev );
  natsTransport_Destroy( t );
  natsQueue_Destroy( q );
  return 0;
}
