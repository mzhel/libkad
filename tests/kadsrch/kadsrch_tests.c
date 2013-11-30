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
#include <kadfw.h>
#include <kadses.h>
#include <kadsrch.h>
#include <kadqpkt.h>
#include <kad.h>
#include <ticks.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>
#include <random.h>

bool
_generate_nodes(
                KAD_SESSION* ks,
                uint32_t nodes_count
                )
{
  bool result = false;
  UINT128 id;
  UINT128 dist;
  KAD_NODE* kn = NULL;

  do {

    for (uint32_t i = 0; i < nodes_count; i++){

      uint128_generate(&id);

      uint128_xor(&ks->kad_id, &id, &dist);

      assert_true(node_create(
                              &id, 
                              kadses_get_pub_ip(ks), 
                              random_uint32(), 
                              random_uint16(), 
                              random_uint16(), 
                              10, 
                              random_uint32(),
                              true,
                              &dist,
                              &kn
                              )
      );

      if (!routing_add_node(&ks->active_zones, ks->root_zone, kn, kadses_get_pub_ip(ks), false, NULL, true)){

        node_destroy(kn);

      }

    }

    result = true;

  } while (false);

  return result;
}

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

void
test_kad_search_find_node(void** status)
{
  KAD_SESSION* ks;
  UINT128 id_to_find;
  KAD_QUEUED_PACKET* qpkt = NULL;
  uint32_t pkt_count = 0;

  uint128_generate(&id_to_find);

  kad_session_init(3001, 3002, &ks);

  _generate_nodes(ks, 100);

  kad_search_find_node(
                       ks,
                       ks->root_zone,
                       &ks->kad_id,
                       &id_to_find,
                       true,
                       &ks->searches
                       );

  
  LOG_DEBUG_UINT128("Queued packet id_to_find: ", ((UINT128*)&id_to_find));

  while (queue_deq(ks->queue_out_udp, (void**)&qpkt)){

    LOG_DEBUG_UINT128("Queued packet kad_id: ", ((UINT128*)&qpkt->kad_id));

    kadqpkt_destroy(qpkt);

  }

  kad_session_uninit(ks);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kad_search_create_destroy),
    unit_test(test_kad_search_find_node)
  };

  return run_tests(tests);
}

