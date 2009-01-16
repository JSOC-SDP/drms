/* sum_adv.c
 * This returns an exit(1) if it is now safe to shutdown the sum_svc
 * via a sum_stop.
 * Returns an exit(0) if a user is still opened in SUMS and you
 * should wait for it to close before you shut down SUMS.
 * Normal call will turn off new SUM_open() calls in sum_svc.
 * Call with -q to not turn off new SUM_open().
*/
#include <SUM.h>
#include <soi_key.h>
#include <rpc/rpc.h>
#include <sum_rpc.h>

/* Before running this you must have the sum_svc running on d00 like so:
 * sum_svc hmidb &
 * The log file will be at /usr/local/logs/SUM/sum_svc_PID.log
*/
int main(int argc, char *argv[])
{
  int shutmode, c;
  int queryonly = 0;

  while((--argc > 0) && ((*++argv)[0] == '-')) {
    while((c = *++argv[0])) {
      switch(c) {
      case 'q':
        queryonly=1;	//don't turn off new SUM_open() in sum_svc
        break;
      default:
        break;
      }
    }
  }
  if((shutmode = SUM_shutdown(queryonly, printf)) == 0) {
    if(queryonly) 
      printf("Don't shutdown. A SUM_open() is still active. New opens still allowed\n");
    else
      printf("Don't shutdown. A SUM_open() is still active. New opens not allowed\n");
    exit(0);
  }
  else {
    if(queryonly)
      printf("No active opens in SUMS, New opens still allowed\n");
    else
      printf("Ok to shutdown SUMS, New opens in sum_svc not allowed\n");
    exit(1);		// ok to shutdown
  }
}
