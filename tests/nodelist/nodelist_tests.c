#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <node.h>
#include <list.h>
#include <mem.h>
#include <nodelist.h>
#include <ticks.h>
#include <cmockery.h>

#include <log.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

#define TEST_NODES_COUNT 256

void
test_nodelist_add_entry(void** state)
{
  NODE_LIST_ENTRY* nle = NULL;
  LIST* nl = NULL;
  UINT128 ui128;

  uint128_zero_init(&ui128);

  random_init();

  for (uint32_t i = 0; i < TEST_NODES_COUNT; i++){

    nle = mem_alloc(sizeof(NODE_LIST_ENTRY));

    uint128_generate(&nle->dist);
    
    assert_true(nodelist_add_entry(&nl, nle));

  }

  for (uint32_t i = 0; i < TEST_NODES_COUNT; i++){

    list_entry_at_idx(nl, i, (void**)&nle);

    assert_int_equal(0xff, uint128_compare(&ui128, &nle->dist));

    uint128_copy(&nle->dist, &ui128);

    LOG_DEBUG_UINT128("dist", ((UINT128*)&ui128));

  }

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_nodelist_add_entry)
  };

  return run_tests(tests);
}
