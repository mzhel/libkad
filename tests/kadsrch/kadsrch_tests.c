#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
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

bool
_create_kad_session(
                    uint16_t udp_port,
                    uint16_t tcp_port,
                    uint32_t gen_nodes_cnt,
                    KAD_SESSION** ks_out
        
                    )
{
  bool result = false;
  KAD_SESSION* ks;

  do {

    if (!ks_out) break;

    kad_session_init(tcp_port, udp_port, NULL, &ks);

    _generate_nodes(ks, gen_nodes_cnt);

    *ks_out = ks;

    result = true;

  } while (false);

  return result;
}

bool
_node_from_session(
                   KAD_SESSION* from_ks,
                   KAD_SESSION* to_ks,
                   KAD_NODE** kn_out
                   )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  UINT128 dist;

  do {

    if (!from_ks || !to_ks || !kn_out) break;

    uint128_xor(
                &from_ks->kad_id,
                &to_ks->kad_id,
                &dist
                );

    if (!node_create(
                     &from_ks->kad_id,
                     kadses_get_pub_ip(to_ks),
                     kadses_get_pub_ip(from_ks),
                     htons(from_ks->tcp_port),
                     htons(from_ks->udp_port),
                     (uint8_t)from_ks->version,
                     from_ks->udp_key,
                     true,
                     &dist,
                     &kn
                     )
    ){

      LOG_ERROR("Failed to create node from session.");

      break;

    }

    *kn_out = kn;

    result = true;

  } while (false);

  return result;
}

bool
_add_node_to_session(
                     KAD_SESSION* ks,
                     KAD_NODE* kn
                    )
{
  bool result = false;

  do {

    if (!ks || !kn) break;

    if (!routing_add_node(
                          &ks->active_zones,
                          ks->root_zone,
                          kn,
                          kadses_get_pub_ip(ks),
                          false,
                          NULL,
                          true
                          )
    ){

      LOG_ERROR("Failed to add node to session.");

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
_link_sessions(
              KAD_SESSION* ks,
              KAD_SESSION* ks2,
              KAD_NODE** ks_kn_out,
              KAD_NODE** ks2_kn_out
              )
{
  bool result = false;
  KAD_NODE* ks_kn;
  KAD_NODE* ks2_kn;

  
  do {

    if (!ks || !ks2) break;

    if (!_node_from_session(ks, ks2, &ks_kn)){

      LOG_ERROR("Failed to create node from session.");

      break;

    }

    if (!_node_from_session(ks2, ks, &ks2_kn)){

      LOG_ERROR("Failed to create node from session.");

      break;

    }

    if (!_add_node_to_session(ks, ks2_kn)){

      LOG_ERROR("Failed to add node to session.");

      break;

    }

    if (!_add_node_to_session(ks2, ks_kn)){

      LOG_ERROR("Failed to add node to session.");

      break;

    }

    if (ks_kn_out) *ks_kn_out = ks_kn;

    if (ks2_kn_out) *ks2_kn_out = ks2_kn;

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
  KAD_SESSION* ks2;
  KAD_NODE* ks_kn;
  KAD_NODE* ks2_kn;
  UINT128 id_to_find;
  KAD_QUEUED_PACKET* qpkt = NULL;
  uint32_t pkt_count = 0;
  uint32_t ip4_to_snd_no = 0;
  uint16_t port_to_snd_no = 0;
  void* srch_pkt = 0;
  uint32_t srch_pkt_len = 0;

  uint128_generate(&id_to_find);

  _create_kad_session(3001, 3002, 100, &ks);

  _create_kad_session(3003, 3004, 100, &ks2);

  assert_true(_link_sessions(ks, ks2, &ks_kn, &ks2_kn));

  LOG_DEBUG_UINT128("searcher id: ", ((UINT128*)&ks->kad_id));

  LOG_DEBUG_UINT128("id to find: ", ((UINT128*)&ks2->kad_id));

  kad_search_find_node(
                       ks,
                       ks->root_zone,
                       &ks->kad_id,
                       &ks2->kad_id,
                       true,
                       &ks->searches
                       );

  assert_true(kad_get_control_packet_to_send(ks, &ip4_to_snd_no, &port_to_snd_no, &srch_pkt, &srch_pkt_len));

  assert_true(
              kad_control_packet_received(
                                          ks2,
                                          kadses_get_pub_ip(ks),
                                          htons(kadses_get_udp_port(ks)),
                                          srch_pkt,
                                          srch_pkt_len
                                         )
  );

  assert_true(
              kad_deq_and_handle_control_packet(ks2)
             );

  kad_session_uninit(ks);

  kad_session_uninit(ks2);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[kadsrch] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    //unit_test(test_kad_search_create_destroy),
    unit_test(test_kad_search_find_node)
  };

  return run_tests(tests);
}

