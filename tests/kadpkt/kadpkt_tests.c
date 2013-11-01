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

void
test_kadpkt_create_bootstrap(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_bootstrap(&raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

void
test_kadpkt_create_search(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  UINT128 search_id;
  UINT128 node_id;

  assert_true(kadpkt_create_search(5, &search_id, &node_id, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);
}

void
test_kadpkt_create_ping(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_ping(&raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

void
test_kadpkt_create_pong(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_pong(0, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

#define BS_NODES_COUNT 10

void
test_kadpkt_create_bootstrap_res(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  UINT128 kad_id;
  UINT128 kn_id;
  UINT128 dist;
  LIST* kn_lst = NULL;
  KAD_NODE* kn = NULL;

  uint128_generate(&kad_id);

  for (uint32_t i = 0; i < BS_NODES_COUNT; i++){

    uint128_generate(&kn_id);

    uint128_xor(&kad_id, &kn_id, &dist);

    assert_true(node_create(&kn_id, 0, 0, 0, 0, 8, 0, true, &dist, &kn));

    list_add_entry(&kn_lst, (void*)kn);

  }

  assert_true(kadpkt_create_bootstrap_res(&kad_id, 0, kn_lst, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

  list_destroy(kn_lst, true);
  
}

void
test_kadpkt_create_hello(void** state)
{
  UINT128 kad_id;
  UINT128 target_id;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_hello(&kad_id, 0, 0, 0, 8, 0, &target_id, true, true, true, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

  assert_true(kadpkt_create_hello_req(&kad_id, 0, 0, 8, 0, &target_id, true, true, true, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

  assert_true(kadpkt_create_hello_res(&kad_id, 0, 0, 8, 0, &target_id, true, true, true, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

void
test_kadpkt_create_hello_ack(void** state)
{
  UINT128 kad_id;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_hello_ack(&kad_id, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

void
test_kadpkt_create_search_response(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  UINT128 kad_id;
  UINT128 kn_id;
  UINT128 dist;
  LIST* kn_lst = NULL;
  KAD_NODE* kn = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  
  uint128_generate(&kad_id);

  for (uint32_t i = 0; i < BS_NODES_COUNT; i++){

    uint128_generate(&kn_id);

    uint128_xor(&kad_id, &kn_id, &dist);

    assert_true(node_create(&kn_id, 0, 0, 0, 0, 8, 0, true, &dist, &kn));

    nle = (NODE_LIST_ENTRY*)mem_alloc(sizeof(NODE_LIST_ENTRY));

    uint128_generate(&nle->dist);

    nle->node = kn;

    list_add_entry(&kn_lst, (void*)nle);

  }

  assert_true(kadpkt_create_search_response(&kad_id, kn_lst, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

  LIST_EACH_ENTRY_WITH_DATA_BEGIN(kn_lst, e, nle);

    node_destroy(nle->node);

  LIST_EACH_ENTRY_WITH_DATA_END(e);

  list_destroy(kn_lst, true);

}

void
test_kadpkt_create_search_key_req(void** state)
{
  UINT128 target;
  uint8_t search_terms[10];
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_search_key_req(&target, search_terms, sizeof(search_terms), &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

void
test_kadpkt_create_search_source_req(void** state)
{
 UINT128 file_id;
 uint64_t file_size;
 void* raw_pkt = NULL;
 uint32_t raw_pkt_len = 0;

 assert_true(kadpkt_create_search_source_req(&file_id, file_size, &raw_pkt, &raw_pkt_len));

 mem_free(raw_pkt);

}

void
test_kadpkt_create_fw_check(void** state)
{
 UINT128* cli_hash;
 void* raw_pkt = NULL;
 uint32_t raw_pkt_len = 0;

 assert_true(kadpkt_create_fw_check(0, cli_hash, 0, &raw_pkt, &raw_pkt_len));

 mem_free(raw_pkt);

}

void
test_kadpkt_create_fw_check_udp(void** state)
{
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;

  assert_true(kadpkt_create_fw_check_udp(true, 0, &raw_pkt, &raw_pkt_len));

  mem_free(raw_pkt);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kadpkt_create_bootstrap),
    unit_test(test_kadpkt_create_ping),
    unit_test(test_kadpkt_create_pong),
    unit_test(test_kadpkt_create_bootstrap_res),
    unit_test(test_kadpkt_create_hello),
    unit_test(test_kadpkt_create_hello_ack),
    unit_test(test_kadpkt_create_search_response),
    unit_test(test_kadpkt_create_search_key_req),
    unit_test(test_kadpkt_create_search_source_req),
    unit_test(test_kadpkt_create_fw_check),
    unit_test(test_kadpkt_create_fw_check_udp)
  };

  return run_tests(tests);
}
