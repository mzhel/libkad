#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <mem.h>
#include <random.h>
#include <list.h>
#include <queue.h>
#include <uint128.h>
#include <node.h>
#include <nodelist.h>
#include <pktasm.h>
#include <tag.h>
#include <packet.h>
#include <kadpkt.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success)
  };

  return run_tests(tests);
}
