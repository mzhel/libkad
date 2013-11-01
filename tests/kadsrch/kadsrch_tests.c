#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadses.h>
#include <kadsrch.h>
#include <ticks.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>
#include <random.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_kad_search_create_destroy(void** status)
{
  KAD_SEARCH* kse = NULL;

  assert_true(kad_search_create(SEARCH_NODE, &kse));

  assert_true(kad_search_destroy(kse));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kad_search_create_destroy)
  };

  return run_tests(tests);
}

