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
#include <tag.h>
#include <protocols.h>
#include <packet.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadpkt.h>
#include <kadhlp.h>
#include <random.h>
#include <ticks.h>
#include <mem.h>
#include <log.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>

bool
kadhlp_id_from_string(
                      char* str,
                      uint32_t str_len,
                      UINT128* kad_id
                     )
{
  bool result = false;
  uint8_t dgst[16];

  do {

    if (!str || !str_len || !kad_id) break;

    md4((uint8_t*)str, str_len, dgst);

    uint128_from_buffer(kad_id, dgst, sizeof(dgst), true);

    result = true;

  } while (false);

  return result;
}

bool
kadhlp_find_kn_in_nle_list(
                           LIST** nle_lst_ptr,
                           UINT128* dist,
                           KAD_NODE** kn_out
                          )
{
  bool result = false;
  LIST* nle_lst = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  KAD_NODE* kn = NULL;

  do {

    if (!nle_lst || !dist) break;

    nle_lst = *nle_lst_ptr;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(nle_lst, e, nle);

      kn = nle->node;

      if (0 == uint128_compare(dist, &kn->dist)){

        LOG_DEBUG("Found matched node.");

        if (kn_out) *kn_out = kn;

        result = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

  } while (false);

  return result;
}

bool
kadhlp_send_ping_pkt_to_rand_node(
                                  KAD_SESSION* ks
                                 )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks) break;

    if (!routing_get_random_node(ks->root_zone, 3, 6, &kn, true)){

      LOG_ERROR("Failed to get random node.");

      break;

    }

    if (!kadpkt_create_ping(&pkt, &pkt_len)){

      LOG_ERROR("Failed to create ping packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks, 
                                     &ks->kad_id, 
                                     kn->ip4_no, 
                                     kn->udp_port_no, 
                                     &kn->id, 
                                     node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks)),
                                     pkt,
                                     pkt_len
                                     )
    ){

      LOG_ERROR("Failed to queue ping packet.");

      break;

    }

    result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kadhlp_send_bs_req_pkt_to_rand_node(
                                    KAD_SESSION* ks
                                   )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  bool pkt_queued = false;

  do {

    if (!routing_get_random_node(ks->root_zone, 3, 6, &kn, true)){

      LOG_ERROR("Failed to get random node.");

      break;

    }

    if (kadpkt_create_bootstrap(&pkt, &pkt_len)){

      LOG_ERROR("Failed to create bootstrap packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks, 
                                     &ks->kad_id,
                                     kn->ip4_no,
                                     kn->udp_port_no,
                                     &kn->id,
                                     node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks)),
                                     pkt,
                                     pkt_len
                                     )
    ){

      LOG_ERROR("Failed to queue bootstrap packet.");

      break;

    }

    result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kadhlp_calc_udp_verify_key(
                           uint32_t udp_key,
                           uint32_t ip4_no,
                           uint32_t* verify_key_out
                          )
{
  bool result = false;
  uint8_t dgst[16];
  uint32_t* p = NULL;
  uint64_t buf = 0;
  uint32_t verify_key = 0;

  do {

    if (!verify_key_out) break;

    memset(dgst, 0, sizeof(dgst));

    buf = udp_key;

    buf <<= 32;

    buf |= ip4_no;

    md5((uint8_t*)&buf, sizeof(buf), dgst);

    p = (uint32_t*)dgst;

    verify_key = (*p ^ *(p + 1) ^ *(p + 2) ^ *(p + 3)) % 0xfffffffe + 1;

    *verify_key_out = verify_key;

    result = true;

  } while (false);


  return result;
}
