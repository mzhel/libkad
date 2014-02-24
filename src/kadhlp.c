#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <stdio.h>
#include <arpa/inet.h>
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
#include <kadqpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadpkt.h>
#include <kadhlp.h>
#include <kadfile.h>
#include <random.h>
#include <ticks.h>
#include <kaddbg.h>
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

      kn = &nle->kn;

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
kadhlp_send_ping_pkt_to_node(
                             KAD_SESSION* ks,
                             KAD_NODE* kn
                             )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    KADDBG_PRINT_KN("selected node:", kn);

    if (!kadpkt_create_ping(&pkt, &pkt_len)){

      LOG_ERROR("Failed to create ping packet.");

      break;

    }

    LOG_DEBUG("pkt = %.8x, pkt_len = %.8x", pkt, pkt_len);

    if (!kadses_create_queue_udp_pkt(
                                     ks, 
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
kadhlp_send_ping_pkt_to_rand_node(
                                  KAD_SESSION* ks
                                 )
{
  bool result = false;
  KAD_NODE* kn = NULL;

  do {

    if (!ks) break;

    if (!routing_get_random_node(ks->root_zone, 3, 6, &kn, true)){

      LOG_ERROR("Failed to get random node.");

      break;

    }

    result = kadhlp_send_ping_pkt_to_node(ks, kn);

  } while (false);

  return result;
}

bool
kadhlp_send_bootstrap_pkt(
                          KAD_SESSION* ks,
                          uint32_t ip4_no,
                          uint16_t port_no
                          )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  bool pkt_queued = false;

  do {

    if (!ks) break;

    if (!kadpkt_create_bootstrap(&pkt, &pkt_len)){

      LOG_ERROR("Failed to create bootstrap packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks, 
                                     ip4_no,
                                     port_no,
                                     NULL,
                                     0,
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
kadhlp_send_bs_req_pkt_to_rand_node(
                                    KAD_SESSION* ks
                                   )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!routing_get_random_node(ks->root_zone, 3, 6, &kn, true)){

      LOG_ERROR("Failed to get random node.");

      break;

    }

    if (!kadpkt_create_bootstrap(&pkt, &pkt_len)){

      LOG_ERROR("Failed to create bootstrap packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks, 
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
kadhlp_send_hello_req_pkt_to_node(
                                 KAD_SESSION* ks,
                                 KAD_NODE* kn
                                 )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks || !kn) break;

    if (!kadpkt_create_hello_req(
                                 &ks->kad_id,
                                 ks->tcp_port,
                                 0, // [IMPLEMENT] here should be check use external udp port or not, for now used by default.
                                 kn->version,
                                 node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks)),
                                 &kn->id,
                                 false,
                                 ks->fw.firewalled,
                                 ks->fw.udp_firewalled,
                                 &pkt,
                                 &pkt_len
                                 )
    ){

      LOG_ERROR("Failed to create hello packet.");

      break;

    }

    if (kn->version >= 6){

      if (!kadses_create_queue_udp_pkt(
                                       ks,
                                       kn->ip4_no,
                                       kn->udp_port_no,
                                       &kn->id,
                                       node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks)),
                                       pkt,
                                       pkt_len
                                       )
      ){

        LOG_ERROR("Failed to queue hello packet.");

        break;

      }

    } else if (kn->version >= 2){

      if (!kadses_create_queue_udp_pkt(
                                       ks,
                                       kn->ip4_no,
                                       kn->udp_port_no,
                                       NULL,
                                       0,
                                       pkt,
                                       pkt_len
                                       )
      ){

        LOG_ERROR("Failed to queue hello packet.");

        break;

      } 

    } else {

      // Version mismatch.

      break;

    }

    result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kadhlp_send_fw_check_udp(
                         KAD_SESSION* ks,
                         uint16_t check_port,
                         uint32_t key,
                         uint32_t ip4_no
                        )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks) break;

    if (!kadpkt_create_fw_check_udp(
                                    false, 
                                    check_port,
                                    &pkt,
                                    &pkt_len
                                   )
    ){

      LOG_ERROR("Failed to create fw check udp.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks,
                                     ip4_no,
                                     htons(check_port),
                                     NULL,
                                     key,
                                     pkt,
                                     pkt_len
                                    )
    ){

      LOG_ERROR("Failed to queue udp packet.");

      break;

    }

    result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kadhlp_send_fw_check_tcp(
                         KAD_SESSION* ks,
                         UINT128* node_id,
                         uint32_t ip4_no,
                         uint16_t port_no,
                         uint32_t sender_key,
                         uint16_t tcp_port
                        )
{
  bool result = false;
  UINT128 hash_id;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks || !node_id) break;

    uint128_from_buffer(&hash_id, ks->user_hash, sizeof(ks->user_hash), true);

    if (!kadpkt_create_fw_check(tcp_port, &hash_id, 0x00, &pkt, &pkt_len)){

      LOG_ERROR("Failed to create firewall check request packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks,
                                     ip4_no,
                                     port_no,
                                     node_id,
                                     sender_key,
                                     pkt,
                                     pkt_len
                                    )
    ){

      LOG_ERROR("Failed to queue udp packet.");

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

bool
kadhlp_gen_udp_key(
                   uint32_t* udp_key_out
                  )
{
  bool result = false;
  uint32_t udp_key = 0;

  do {

    if (!udp_key_out) break;

    udp_key = random_uint32();

    *udp_key_out = udp_key;

    result = true;

  } while (false);

  return result;
}

bool
kadhlp_destroy_qpkt_queue(
                          KAD_SESSION* ks,
                          QUEUE* q
                          )
{
  bool result = false;
  KAD_QUEUED_PACKET *qpkt = NULL;

  do {

    if (!q) break;

    do {

      qpkt = NULL;

      DEQ_OUT_UDP(ks, (void**)&qpkt);

      if (!qpkt) break;

      kadqpkt_destroy(qpkt, true);

    } while (true);

    queue_destroy(q);

    result = true;

  } while (false);

  return result;
}

bool
kadhlp_parse_nodes_dat(
                       KAD_SESSION* ks,
                       char* file_path,
                       LIST** kn_lst_out
                       )
{
  bool result = false;
  KAD_FILE* kf = NULL;
  uint32_t file_len = 0;
  uint32_t ver = 0;
  uint32_t kn_cnt = 0;
  UINT128 id;
  UINT128 dist;
  uint32_t ip4_no;
  uint16_t udp_port;
  uint16_t tcp_port;
  uint8_t type;
  uint8_t contact_ver;
  uint32_t udp_key_ip4;
  uint32_t udp_key;
  uint8_t verified;
  KAD_NODE* kn;
  LIST* kn_lst = NULL;

  do {

    if (!kadfile_open_read(file_path, &file_len, &kf)){

      LOG_ERROR("Failed to open file %s", file_path);
      
      break;

    }

    LOG_DEBUG("Nodes file length %.8x(%d)", file_len, file_len);

    if (!file_len) break;

    // Skip zero counter for older versions.

    kadfile_read_uint32(kf, NULL);

    file_len -= 4;

    if (file_len < 8) break;

    // nodes file version.

    kadfile_read_uint32(kf, &ver);

    file_len -= 4;

    if (ver != 2) {

      LOG_ERROR("Wrong nodes file version.");
      
      break;

    }

    // nodes count in file.

    kadfile_read_uint32(kf, &kn_cnt);

    LOG_DEBUG("%d nodes in file.", kn_cnt);

    file_len -= 4;

    if (kn_cnt && file_len < kn_cnt * 25) break;

    while (kn_cnt--){

      // node id
      
      kadfile_read_uint128(kf, &id);

      file_len -= sizeof(UINT128);

      // node ip address

      kadfile_read_uint32(kf, &ip4_no);

      file_len -= sizeof(uint32_t);

      // node udp port
      
      kadfile_read_uint16(kf, &udp_port);

      file_len -= sizeof(uint16_t);

      // node tcp port
      
      kadfile_read_uint16(kf, &tcp_port);

      file_len -= sizeof(uint16_t);

      // contact version

      kadfile_read_uint8(kf, &contact_ver);

      file_len -= sizeof(uint8_t);

      // udp key data

      kadfile_read_uint32(kf, &udp_key);

      file_len -= sizeof(uint32_t);

      kadfile_read_uint32(kf, &udp_key_ip4);

      file_len -= sizeof(uint32_t);
      
      // node verification status
      
      kadfile_read_uint8(kf, &verified);

      file_len -= sizeof(uint8_t);

      uint128_xor(&ks->kad_id, &id, &dist);

      if (!node_create(
                       &id,
                       htonl(udp_key_ip4),
                       htonl(ip4_no),
                       htons(tcp_port),
                       htons(udp_port),
                       contact_ver,
                       udp_key,
                       verified > 0,
                       &dist,
                       &kn 
                       )
      ) continue;

      list_add_entry(kn_lst_out, kn);

    }

    LOG_DEBUG("Remained file length %.8x", file_len);

    result = true;

  } while (false);

  if (kf) kadfile_close(kf);

  return result;
}

bool
kadhlp_add_nodes_from_file(
                           KAD_SESSION* ks,
                           char* file_path
                           )
{
  bool result = false;
  LIST* kn_lst = NULL;
  KAD_NODE* kn = NULL;

  do {

    if (!ks || !file_path) break;

    if (!kadhlp_parse_nodes_dat(ks, file_path, &kn_lst)){

      LOG_ERROR("Failed to parse %s.", file_path);

      break;

    }

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kn_lst, e, kn);

      if (!routing_add_node(&ks->active_zones, ks->root_zone, kn, kadses_get_pub_ip(ks), false, NULL, true)){

        node_destroy(kn);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  if (kn) list_destroy(kn_lst, false);

  return result;
}
