/* Copyright (c) 2026 Rai Technology.  All rights reserved.
 *  http://www.raitechnology.com
 *
 * natsmd_api_client -- sample / test for the natsapi: connect, subscribe
 * subjects (or wildcards), print what arrives; optionally publish a
 * message (-p) and / or a request with an inbox reply (-i). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <raimd/md_msg.h>
#include <raimd/rv_msg.h>
#include <natsmd/natsapi.h>

using namespace rai;
using namespace md;

static volatile int quit;
static int          quiet;
static uint32_t     msg_count, max_msgs;

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
  natsMsg_Print( msg, stdout );
  fflush( stdout );
}

static void
on_timer( natsEvent,  natsMsg,  void * )
{
  printf( "## timer\n" );
  fflush( stdout );
}

int
main( int argc,  char *argv[] )
{
  natsTransportParams parms;
  nats_InitTransportParams( &parms );
  const char * subjects[ 64 ],
             * pub_subject = NULL,
             * pub_text    = "hello",
             * req_subject = NULL,
             * queue_group = NULL;
  int          nsubj = 0;
  double       secs  = 0, timer_secs = 0;

  for ( int i = 1; i < argc; i++ ) {
    if ( ::strcmp( argv[ i ], "-d" ) == 0 && i + 1 < argc )
      parms.daemon = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-u" ) == 0 && i + 1 < argc )
      parms.user = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-z" ) == 0 && i + 1 < argc )
      parms.password = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-a" ) == 0 && i + 1 < argc )
      parms.auth_token = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-N" ) == 0 && i + 1 < argc )
      parms.name = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-p" ) == 0 && i + 1 < argc )
      pub_subject = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-m" ) == 0 && i + 1 < argc )
      pub_text = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-i" ) == 0 && i + 1 < argc )
      req_subject = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-g" ) == 0 && i + 1 < argc )
      queue_group = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-q" ) == 0 )
      quiet = 1;
    else if ( ::strcmp( argv[ i ], "-n" ) == 0 && i + 1 < argc )
      max_msgs = (uint32_t) atoi( argv[ ++i ] );
    else if ( ::strcmp( argv[ i ], "-t" ) == 0 && i + 1 < argc )
      secs = atof( argv[ ++i ] );
    else if ( ::strcmp( argv[ i ], "-T" ) == 0 && i + 1 < argc )
      timer_secs = atof( argv[ ++i ] );
    else if ( ::strcmp( argv[ i ], "-A" ) == 0 ) {
      parms.advisory = 1;
      if ( i + 1 < argc && argv[ i + 1 ][ 0 ] >= '0' && argv[ i + 1 ][ 0 ] <= '9' )
        parms.advisory = atoi( argv[ ++i ] );
    }
    else if ( ::strcmp( argv[ i ], "-h" ) == 0 || argv[ i ][ 0 ] == '-' ) {
      fprintf( stderr,
        "%s [-d host:port] [-u user] [-z pass] [-a token] [-N name] [-g group]\n"
        "   [-p subject [-m text]] [-i subject] [-q] [-n msgs] [-t secs]\n"
        "   [-T secs] [-A [secs]] subject ...\n"
        "  -d  server, default 127.0.0.1:4222\n"
        "  -N  CONNECT name\n"
        "  -A  session advisories _NATS.<session>.* and the _INBOX.<session>.SUBS\n"
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
    else if ( nsubj < 64 )
      subjects[ nsubj++ ] = argv[ i ];
  }
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

  /* listeners may be created before the connect, they are subscribed
   * when it completes */
  for ( int i = 0; i < nsubj; i++ ) {
    st = natsEvent_CreateQueueListener( &ev[ i ], q, t, subjects[ i ],
                                        queue_group, NATS_LISTEN_DEFAULT,
                                        on_msg, NULL );
    if ( st != NATS_OK )
      printf( "listen %s: %s\n", subjects[ i ], natsStatus_GetText( st ) );
    else
      printf( "listen %s\n", subjects[ i ] );
  }
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
