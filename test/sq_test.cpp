/* natsmd_sq_test: delivers a fake session's advisories and SUBS replies out
 * of order so a NatsSubscriptionDB monitor (natsmd_subtop -l log) shows the
 * sq handling:
 *   START sq 1, LISTEN.START A sq 2, C sq 4  -> "sq gap 2 -> 4", query
 *   LISTEN.START B sq 3 (late)                -> "stale sq 3 <= 4, dropped"
 *   1st SUBS reply sq 2 { A }                 -> "stale subs reply", requery
 *   2nd SUBS reply sq 4 { A, B, C }           -> "synced ... sc/sx 3/..."
 *   STATUS sq 5 sc 3                          -> no gap, no digest mismatch
 * usage: natsmd_sq_test [host:port] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <raimd/md_msg.h>
#include <raimd/rv_msg.h>
#include <raikv/key_hash.h>
#include <natsmd/natsapi.h>

using namespace rai;
using namespace md;

#define SARG( str ) str, sizeof( str )

static const char    SESS[] = "SQTEST01";
static natsTransport tport;
static int           nreq;

static uint32_t
hash( const char *s )
{
  return kv_crc_c( s, ::strlen( s ), 0 );
}

static void
send_adv( const char *kind,  const char *sub,  uint32_t sq,  uint32_t sc,
          uint32_t sx )
{
  char subject[ 128 ];
  ::snprintf( subject, sizeof( subject ), "_NATS.%s.%s", kind, SESS );
  MDMsgMem    mem;
  RvMsgWriter w( mem, mem.make( 1024 ), 1024 );
  w.append_string( SARG( "id" ), SESS, sizeof( SESS ) );
  w.append_uint( SARG( "sq" ), sq );
  if ( sub != NULL ) {
    w.append_string( SARG( "sub" ), sub, ::strlen( sub ) + 1 );
    w.append_uint( SARG( "refcnt" ), (uint32_t) 1 );
  }
  else {
    w.append_string( SARG( "user" ), SARG( "sqtest" ) );
    w.append_uint( SARG( "cn" ), (uint32_t) 1 );
  }
  w.append_uint( SARG( "sc" ), sc );
  w.append_uint( SARG( "sx" ), sx );
  size_t len = w.update_hdr();
  natsTransport_Send( tport, subject, NULL, w.buf, (uint32_t) len,
                      RVMSG_TYPE_ID );
  printf( "pub %s %s sq %u sc %u sx %08X\n", subject, sub != NULL ? sub : "",
          sq, sc, sx );
  fflush( stdout );
}

/* _INBOX.SQTEST01.SUBS: the 1st reply is stale (sq 2), the 2nd current */
static void
on_subs( natsEvent,  natsMsg msg,  void * )
{
  const char * reply = NULL;
  natsMsg_GetReplySubject( msg, &reply );
  if ( reply == NULL || reply[ 0 ] == '\0' )
    return;
  nreq++;
  static const char * subs1[] = { "A", NULL },
                    * subs2[] = { "A", "B", "C", NULL };
  const char ** subs = ( nreq == 1 ? subs1 : subs2 );
  uint32_t      sq   = ( nreq == 1 ? 2 : 4 );
  MDMsgMem    mem;
  RvMsgWriter w( mem, mem.make( 1024 ), 1024 );
  w.append_string( SARG( "user" ), SARG( "sqtest" ) );
  w.append_uint( SARG( "sq" ), sq );
  for ( int i = 0; subs[ i ] != NULL; i++ )
    w.append_string( NULL, 0, subs[ i ], ::strlen( subs[ i ] ) + 1 );
  w.append_int<int32_t>( SARG( "end" ), 1 );
  size_t len = w.update_hdr();
  natsTransport_Send( tport, reply, NULL, w.buf, (uint32_t) len,
                      RVMSG_TYPE_ID );
  printf( "subs request %d -> reply %s sq %u (%s)\n", nreq, reply, sq,
          nreq == 1 ? "stale" : "current" );
  fflush( stdout );
}

static double
now_secs( void )
{
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void
pump( natsQueue q,  double secs,  int until_nreq = 0 )
{
  double t0 = now_secs();
  while ( now_secs() - t0 < secs ) {
    natsQueue_TimedDispatch( q, 0.1 );
    if ( until_nreq != 0 && nreq >= until_nreq )
      break;
  }
}

int
main( int argc,  char *argv[] )
{
  natsTransportParams parms;
  nats_InitTransportParams( &parms );
  parms.daemon = ( argc > 1 ? argv[ 1 ] : "127.0.0.1:4222" );
  parms.name   = "natsmd_sq_test";
  if ( nats_Open() != NATS_OK ||
       natsTransport_Create( &tport, &parms ) != NATS_OK ) {
    fprintf( stderr, "create failed\n" );
    return 1;
  }
  natsQueue q = 0;
  natsEvent ev = 0;
  natsQueue_Create( &q );
  if ( natsTransport_WaitConnected( tport, 10.0 ) != NATS_OK ) {
    fprintf( stderr, "connect failed\n" );
    return 1;
  }
  char inbox[ 64 ];
  ::snprintf( inbox, sizeof( inbox ), "_INBOX.%s.SUBS", SESS );
  natsEvent_CreateListener( &ev, q, tport, inbox, NATS_LISTEN_DEFAULT,
                            on_subs, NULL );
  pump( q, 0.5 );

  uint32_t a = hash( "A" ), b = hash( "B" ), c = hash( "C" );
  send_adv( "START", NULL, 1, 0, 0 );
  send_adv( "LISTEN.START", "A", 2, 1, a );
  /* sq 3 (B) is held back: C arrives first -> gap */
  send_adv( "LISTEN.START", "C", 4, 3, a ^ b ^ c );
  pump( q, 0.3 );
  send_adv( "LISTEN.START", "B", 3, 2, a ^ b );  /* late, stale */
  /* the monitor queries on its timer: answer stale, then current */
  pump( q, 15.0, 2 );
  pump( q, 1.0 );
  send_adv( "STATUS", NULL, 5, 3, a ^ b ^ c );
  pump( q, 1.0 );
  printf( "subs requests answered: %d\n", nreq );
  natsTransport_Destroy( tport );
  return nreq >= 2 ? 0 : 1;
}
