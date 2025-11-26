#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

static uint64 get_time(void) {
  return gettime();
}

static uint64 time_to_usec(uint64 time_diff) {
  return time_diff / 10;  // 10MHz = 10 ticks per microsecond
}

static uint64 time_to_msec(uint64 time_diff) {
  return time_diff / 10000;  // 10MHz = 10000 ticks per millisecond
}

static void
usage(void)
{
  printf("usage: netmon [interval_ms] [count]\n");
  exit(1);
}

int
main(int argc, char *argv[])
{
  int interval = 1000; // default 1s between samples
  
  if(argc > 2)
    usage();
  if(argc >= 2)
    interval = atoi(argv[1]);
  if(interval <= 0)
    interval = 1000;

  if(netreset() < 0){
    printf("netmon: netreset failed\n");
    exit(1);
  }

  uint64 start_time = get_time();

  printf("t(ms) rx_pkts rx_bytes udp_q udp_drop_full udp_drop_unbound udp_ret irq ttq_avg ttq_min ttq_max ttr_avg ttr_min ttr_max k_samples\n");

  int iter = 0;
  for (;;){
    struct netstats s;
    if(netstats(&s) < 0){
      printf("netmon: netstats failed\n");
      exit(1);
    }

    uint64 now = get_time();
    uint64 elapsed_ms = time_to_msec(now - start_time);

    uint64 avg_ttr = 0;
    if(s.ttr_count > 0)
      avg_ttr = s.ttr_sum / s.ttr_count;

    uint64 avg_ttq = 0;
    if(s.ttq_count > 0)
      avg_ttq = s.ttq_sum / s.ttq_count;

    // convert timing units
    uint64 ttr_avg = time_to_usec(avg_ttr);
    uint64 ttr_min = time_to_usec(s.min_ttr);
    uint64 ttr_max = time_to_usec(s.max_ttr);
    uint64 ttq_avg = time_to_usec(avg_ttq);
    uint64 ttq_min = time_to_usec(s.min_ttq);
    uint64 ttq_max = time_to_usec(s.max_ttq);

    printf("%lu %d %d %d %d %d %d %d %lu %lu %lu %lu %lu %lu %d\n",
           elapsed_ms,
           (int)s.rx_packets,
           (int)s.rx_bytes,
           (int)s.udp_queued,
           (int)s.udp_dropped_full,
           (int)s.udp_dropped_unbound,
           (int)s.udp_returned,
           (int)s.rx_interrupts,
           ttq_avg,
           ttq_min,
           ttq_max,
           ttr_avg,
           ttr_min,
           ttr_max,
           (int)s.ttr_count);

    iter++;
    
    // wait before next monitor call
    int sleep_ticks = interval / 100; 
    if(sleep_ticks < 1) sleep_ticks = 1;
    pause(sleep_ticks);
  }

  exit(0);
}
