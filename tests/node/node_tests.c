#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <node.h>
#include <ticks.h>
#include <cmockery.h>

#include <log.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

void test_node_create_destroy(void** state)
{
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;

  assert_int_equal(1, node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

  assert_int_equal(1, node_destroy(kn));

}

void
test_node_update_expired(void** state)
{

  KAD_NODE* kn = NULL;
  UINT128 id;
  UINT128 dist;

  assert_int_equal(1, node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

  kn->last_type_set = ticks_now_ms();

  assert_true(node_update_expired(kn));

  kn->last_type_set = ticks_now_ms() - SEC2MS(15);

  assert_false(node_update_expired(kn));

  assert_true(node_destroy(kn));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_node_create_destroy),
    unit_test(test_node_update_expired)
  };

  return run_tests(tests);
}
