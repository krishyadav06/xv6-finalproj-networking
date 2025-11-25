#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

static uint64 time_to_msec(uint64 time_diff) {
  return time_diff / 10000;  // 10MHz = 10000 ticks per millisecond
}

static void
usage(void)
{
  printf("usage: netloop [port] [report_ms]\n");
  exit(1);
}

int
main(int argc, char *argv[])
{
  int port = 2000;
  int report_ms = 1000; // how often to print stats

  if(argc > 3)
    usage();
  if(argc >= 2)
    port = atoi(argv[1]);
  if(argc == 3)
    report_ms = atoi(argv[2]);
  if(port <= 0 || report_ms <= 0)
    usage();

  if(bind(port) < 0){
    printf("netloop: bind %d failed\n", port);
    exit(1);
  }

  uint64 total_pkts = 0;
  uint64 total_bytes = 0;
  uint64 time_prev = gettime();
  uint64 prev_pkts = 0;
  uint64 prev_bytes = 0;

  printf("netloop: bound to %d, reporting every %d ms\n", port, report_ms);

  for(;;){
    char buf[1500];
    uint32 src;
    uint16 sport;
    int cc = recv(port, &src, &sport, buf, sizeof(buf));
    if(cc < 0){
      printf("netloop: recv failed\n");
      exit(1);
    }
    total_pkts++;
    total_bytes += cc;

    uint64 time_now = gettime();
    uint64 elapsed_ms = time_to_msec(time_now - time_prev);
    if(elapsed_ms >= (uint64)report_ms){
      uint64 dpkts = total_pkts - prev_pkts;
      uint64 dbytes = total_bytes - prev_bytes;
      uint64 pps = (elapsed_ms > 0) ? (dpkts * 1000 / elapsed_ms) : 0;
      uint64 bps = (elapsed_ms > 0) ? (dbytes * 1000 / elapsed_ms) : 0;
      uint64 total_ms = time_to_msec(time_now);
      printf("t=%lu ms pkts=%lu bytes=%lu (+%lu, +%luB) pps~%lu Bps~%lu\n",
             total_ms, total_pkts, total_bytes, dpkts, dbytes, pps, bps);
      time_prev = time_now;
      prev_pkts = total_pkts;
      prev_bytes = total_bytes;
    }
  }
}
