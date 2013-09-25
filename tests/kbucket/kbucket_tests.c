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
#include <kbucket.h>
#include <ticks.h>
#include <cmockery.h>
#include <log.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_kbucket_create_destroy(void **state)
{
  KBUCKET* kb;

  assert_true(kbucket_create(&kb));

  assert_true(kbucket_destroy(kb, false));

}

void
test_kbucket_node_by_id(void** state)
{
  KAD_NODE* kn;
  KAD_NODE* kn2;
  KBUCKET* kb;
  UINT128 id;

  uint128_zero_init(&id);

  id.data.byteData[15] = 1;

  assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, false, &id, &kn));

  assert_true(kbucket_create(&kb));

  assert_true(kbucket_add_node(kb, kn));

  assert_true(kbucket_node_by_id(kb, &id, &kn2));

  assert_int_equal((int)kn, (int)kn2);

  assert_true(kbucket_destroy(kb, true));

  assert_true(node_destroy(kn));

}

#define TEST_NODES_COUNT  16

void
test_kbucket_remove_node_by_idx(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;

  uint128_zero_init(&id);

  uint128_zero_init(&dist);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  assert_true(kbucket_remove_node_by_idx(kb, 5, &kn));

  assert_int_equal(kn->id.data.byteData[UINT128_BYTES_COUNT - 1], 5);

  assert_int_equal(kb->nodes_count, K - 1);

  assert_true(kbucket_destroy(kb, false));

}

void
test_kbucket_remove_node_by_node(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  KAD_NODE* kn2;
  UINT128 id;
  UINT128 dist;

  uint128_zero_init(&id);

  uint128_zero_init(&dist);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  kn2 = kb->nodes[5];

  assert_true(kbucket_remove_node_by_node(kb, kn2, &kn));

  assert_int_equal(kn->id.data.byteData[UINT128_BYTES_COUNT - 1], 5);

  assert_int_equal(kb->nodes_count, K - 1);

  assert_int_equal((int)kb->nodes[K - 1], 0);

  assert_true(kbucket_destroy(kb, false));

}

void
test_kbucket_get_oldest_node(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  KAD_NODE* kn2;
  UINT128 id;
  UINT128 dist;

  uint128_zero_init(&id);

  uint128_zero_init(&dist);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  assert_true(kbucket_get_oldest_node(kb, &kn2));

  assert_int_equal(kn2->id.data.byteData[UINT128_BYTES_COUNT - 1], 0);

  assert_true(kbucket_destroy(kb, false));

}

void
test_kbucket_push_node_up(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;

  uint128_zero_init(&id);

  uint128_zero_init(&dist);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, false, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  kn = kb->nodes[5];

  assert_true(kbucket_push_node_up(kb, kn));

  assert_int_equal(5, kb->nodes[K - 1]->id.data.byteData[UINT128_BYTES_COUNT - 1]);

  assert_true(kbucket_destroy(kb, false));

}

#define MAX_SELECTED_NODES K

void
test_kbucket_get_closest_to(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;
  UINT128 trgt;
  UINT128 zero;
  LIST* l = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  random_init();

  uint128_zero_init(&id);

  uint128_zero_init(&zero);

  uint128_generate(&trgt);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    uint128_generate(&dist);

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, true, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  assert_true(kbucket_get_closest_to(kb, 3, MAX_SELECTED_NODES, &trgt, true, &l));

  assert_int_equal(1, list_entries_count(l, &cnt));

  assert_int_equal(MAX_SELECTED_NODES, cnt);

  for (uint32_t i = 0; i < MAX_SELECTED_NODES; i++) {

    list_entry_at_idx(l, i, (void**)&nle);

    assert_int_equal(0xff, uint128_compare(&zero, &nle->dist));

    LOG_DEBUG_UINT128("dist", ((UINT128*)&nle->dist));

    assert_true(uint128_copy(&nle->dist, &zero));

  }

  list_destroy(l, true);
  
  assert_true(kbucket_destroy(kb, false));

}

void
test_kbucket_get_random_node(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;
  UINT128 trgt;
  UINT128 zero;
  LIST* l = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  random_init();

  uint128_zero_init(&id);

  uint128_zero_init(&zero);

  uint128_generate(&trgt);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    uint128_generate(&dist);

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, true, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  assert_true(kbucket_get_random_node(kb, 3, 0, &kn));
 
}

void
test_kbucket_set_node_alive(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;
  UINT128 trgt;
  UINT128 zero;
  LIST* l = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  random_init();

  uint128_zero_init(&id);

  uint128_zero_init(&zero);

  uint128_generate(&trgt);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    uint128_generate(&dist);

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, true, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  kn = kb->nodes[0];

  assert_true(kbucket_set_node_alive(kb, kn));

  assert_int_equal((int)kn, (int)kb->nodes[K - 1]);

}

void
test_kbucket_get_nodes(void** state)
{
  KBUCKET* kb; 
  KAD_NODE* kn;
  UINT128 id;
  UINT128 dist;
  UINT128 trgt;
  UINT128 zero;
  LIST* l = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  random_init();

  uint128_zero_init(&id);

  uint128_zero_init(&zero);

  uint128_generate(&trgt);

  assert_true(kbucket_create(&kb));

  for (uint32_t i = 0; i < K; i++) {

    uint128_generate(&dist);

    id.data.byteData[UINT128_BYTES_COUNT - 1] = i;

    assert_true(node_create(&id, 0, 0, 0, 0, 0, 0, true, &dist, &kn));

    assert_true(kbucket_add_node(kb, kn));

  }

  assert_true(kbucket_get_nodes(kb, &l));

  for (uint32_t i = 0; i < K; i++){

    assert_int_equal(1, list_entry_at_idx(l, i, &kn));

    assert_int_equal((int)kn, (int)kb->nodes[i]);

  }

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kbucket_create_destroy),
    unit_test(test_kbucket_node_by_id),
    unit_test(test_kbucket_remove_node_by_idx),
    unit_test(test_kbucket_remove_node_by_node),
    unit_test(test_kbucket_get_oldest_node),
    unit_test(test_kbucket_push_node_up),
    unit_test(test_kbucket_get_closest_to),
    unit_test(test_kbucket_get_random_node),
    unit_test(test_kbucket_set_node_alive),
    unit_test(test_kbucket_get_nodes)
  };

  return run_tests(tests);
}
