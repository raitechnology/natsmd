#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#else
#include <raikv/win.h>
#endif
#include <natsmd/ev_nats.h>
#include <raikv/mainloop.h>

using namespace rai;
using namespace natsmd;
using namespace kv;

struct Args : public MainLoopVars { /* argv[] parsed args */
  int nats_port;
  Args() : nats_port( 0 ) {}
};

struct Loop : public MainLoop<Args> {
  Loop( EvShm &m,  Args &args,  size_t num ) :
    MainLoop<Args>( m, args, num ) {}

  EvNatsListen * nats_sv;
  bool nats_init( void ) {
    return Listen<EvNatsListen>( 0, this->r.nats_port, this->nats_sv,
                                 this->r.tcp_opts ); }
  virtual bool initialize( void ) noexcept {
    if ( this->thr_num == 0 )
      printf( "nats:                 %d\n", this->r.nats_port );
    int cnt = this->nats_init();
    if ( this->thr_num == 0 )
      fflush( stdout );
    return cnt > 0;
  }
  virtual bool finish( void ) noexcept {
    return true;
  }
};

int
main( int argc, const char *argv[] )
{
  EvShm shm( "natsmd_server" );
  Args  r;

  r.no_threads   = true;
  r.no_reuseport = true;
  r.no_map       = true;
  r.no_default   = true;
  r.all          = true;
  r.add_desc( "  -c nats  = listen nats port      (42222)\n" );
  if ( ! r.parse_args( argc, argv ) )
    return 1;
  if ( shm.open( r.map_name, r.db_num ) != 0 )
    return 1;
  printf( "nats_version:         " kv_stringify( NATSMD_VER ) "\n" );
  shm.print();
  r.nats_port = r.parse_port( argc, argv, "-c", "42222" );
  Runner<Args, Loop> runner( r, shm );
  if ( r.thr_error == 0 )
    return 0;
  return 1;
}
