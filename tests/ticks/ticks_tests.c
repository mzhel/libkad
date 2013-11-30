#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include <netdb.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <tag.h>
#include <protocols.h>
#include <packet.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadhlp.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <kad.h>
#include <random.h>
#include <ticks.h>
#include <cipher.h>
#include <comprs.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_ticks(
           void** state
          )
{
  uint32_t now = ticks_now_ms();
  uint32_t cntr = 0;
  uint32_t itvl;
  
  do {

    itvl = now + MIN2MS(1);

    do {

      if (cntr == 5) break;

      now = ticks_now_ms();

      usleep(5);

      if (now >= itvl){

        LOG_DEBUG("tick");

        cntr++;

        itvl = now + SEC2MS(1);

      }

    } while (true);

  } while (false);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_ticks)
  };

  return run_tests(tests);
}
