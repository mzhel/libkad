#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <mem.h>
#include <list.h>
#include <queue.h>
#include <pktasm.h>
#include <tag.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void test_pktasm_create_destroy(void** state)
{
  PKT_ASM* pa = NULL;

  assert_true(pktasm_create(&pa));

  assert_true(pktasm_destroy(pa));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_pktasm_create_destroy)
  };

  return run_tests(tests);
}
