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
#include <kadhlp.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <random.h>
#include <ticks.h>
#include <cipher.h>
#include <comprs.h>
#include <mem.h>
#include <log.h>

bool
kad_zone_random_lookup(
                       KAD_SESSION* ks,
                       ROUTING_ZONE* rz,
                       UINT128* id_self
                      )
{
  bool result = false;
  UINT128 prefix;
  UINT128 rnd;

  do {
    
    uint128_copy(&rz->idx, &prefix);

    uint128_shift_left(&prefix, 128 - (uint8_t)rz->level, NULL);

    uint128_copy_bits_be(&prefix, &rnd, rz->level, true);

    uint128_xor(&rnd, id_self, false);

    kad_search_find_node(ks, rz, id_self, &rnd, false, &ks->searches);

    result = true;

  } while (false);

  return result;
}

bool
kad_zone_update_bucket(
                       KAD_SESSION* ks,
                       ROUTING_ZONE* rz
                       )
{
  bool result = false;
  KBUCKET* kb = NULL;
  uint32_t now = ticks_now_ms();
  uint32_t kn_cnt = 0;
  KAD_NODE* rmvd_kn = NULL;
  KAD_NODE* kn = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  bool pkt_queued = false;

  do {

    if (!ks || !rz) break;

    kb = rz->kb;

    kn_cnt = kb->nodes_count;

    for (uint32_t i = 0; i < kn_cnt; i++){

      kn = kb->nodes[i];

      if (kn->expires && kn->expires < now){

        if (!kn->in_use){

          if (!kbucket_remove_node_by_idx(kb, i, &rmvd_kn)){

            LOG_ERROR("Failed to delete expired node.");

            break;

          }

          kn_cnt--;

          node_destroy(rmvd_kn);
          
        }

        continue;

      }

      if (!kn->expires) kn->expires = now;

    }

    if (!kbucket_get_oldest_node(kb, &kn)) break;

    if (!kn) break;

    if (kn->expires >= now || kn->type == 4){

      kbucket_push_node_up(kb, kn);

    } else {

      node_update_expired(kn);

      if (!kadpkt_create_hello_req(
                                   &ks->kad_id,
                                   ks->tcp_port,
                                   ks->udp_port,
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
                                         &ks->kad_id,
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
                                         &ks->kad_id,
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

      }

      pkt_queued = true;

    }

    if (pkt_queued && pkt) mem_free(pkt);

    result = true;

  } while (false);

  return result;
}

bool
kad_init(KAD_SESSION** ks_out)
{
  bool result = false;
  KAD_SESSION* ks = NULL;

  do {
    
    if (!ks_out) break;

    ks = (KAD_SESSION*)mem_alloc(sizeof(KAD_SESSION));

    if (!ks){

      LOG_ERROR("Failed to allocate memory for kad session.");

      break;

    }

    random_init();

    *ks_out = ks;

    result = true;

  } while (false);

  return result;
}

bool
kad_update(
           KAD_SESSION* ks,
           uint32_t now
          )
{
  bool result = false;
  ROUTING_ZONE* rz;
  LIST* active_zones = NULL;
  bool zones_locked = false;
  uint32_t kn_cnt = 0;

  do {

    now = ticks_now_ms();

    if (ks->timers.self_lookup <= now){

      kad_search_find_node(ks, ks->root_zone, &ks->kad_id, &ks->kad_id, true, &ks->searches);

      ks->timers.self_lookup = now + HR2MS(4);

    }

    if (ks->timers.udp_port_lookup <= now && kad_fw_udp_check_running(&ks->fw) && !kad_fw_extrn_port_valid(&ks->fw)){

      kadhlp_send_ping_pkt_to_rand_node(ks);

      ks->timers.udp_port_lookup = now + SEC2MS(15);

    }

    if (kad_fw_extrn_port_valid(&ks->fw) && kad_fw_need_more_udp_checks(&ks->fw)){

      // [IMPLEMENT] kad_fw_next_udp_check_request()

    }

    ACTIVE_ZONES_LOCK(ks);

    zones_locked = true;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ks->active_zones, e, rz);

      if (now >= rz->next_bucket_timer){

        kad_zone_update_bucket(ks, rz);

        rz->next_bucket_timer = now + MIN2MS(1);

      }

      if (now >= rz->next_lookup_timer){

        kad_zone_random_lookup(ks, rz, &ks->kad_id);

        rz->next_lookup_timer = now + HR2MS(1);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (now >= ks->timers.nodes_count_check){

      if (routing_get_nodes_count(ks->root_zone, &kn_cnt, true) && kn_cnt < 200){

        kadhlp_send_bs_req_pkt_to_rand_node(ks);

      }

      ks->timers.nodes_count_check = now + SEC2MS(10);

    }

    ACTIVE_ZONES_UNLOCK(ks);

    zones_locked = false;

  } while (false);

  return result;
}

bool
kad_timer(KAD_SESSION* ks)
{
  bool result = false;
  uint32_t now = ticks_now_ms();

  do {

    kad_update(ks, now);

    if (now >= ks->timers.search_jumpstart){

      kad_search_jumpstart_all(ks, &ks->searches);

      ks->timers.search_jumpstart = now + SEC2MS(1);

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_handle_control_packet(
                          KAD_SESSION* ks,
                          uint8_t* pkt,
                          uint32_t pkt_len,
                          uint32_t ip4_no,
                          uint16_t port_no,
                          bool valid_rcvr_key,
                          uint32_t sndr_verify_key
                          )
{
  bool result = false;
  uint8_t proto = 0;
  uint8_t op = 0;
  uint8_t* ctrl_pkt = NULL;
  uint32_t ctrl_pkt_len = 0;

  do {

    if (!pkt || !pkt_len) break;

    proto = pkt[0];

    op = pkt[1];

    ctrl_pkt = pkt + 2;

    ctrl_pkt_len = pkt_len - 2;

    switch(op){

      case KADEMLIA_BOOTSTRAP_REQ:

        LOG_DEBUG("KADEMLIA_BOOTSTAP_REQ");

      break;

      case KADEMLIA2_BOOTSTRAP_REQ:

        LOG_DEBUG("KADEMLIA2_BOOTSTAP_REQ");

        kadproto_kademlia2_bootstrap_req(ks, ip4_no, port_no, sndr_verify_key);

      break;

      case KADEMLIA2_BOOTSTRAP_RES:

        LOG_DEBUG("KADEMLIA2_BOOTSTRAP_RES");

        kadproto_kademlia2_bootstrap_res(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no, sndr_verify_key, valid_rcvr_key);

        // [THINK] old source has state change to bootstrapped here, maybe do not need that anymore.

      break;

      case KADEMLIA_HELLO_REQ:

        LOG_DEBUG("KADEMLIA_HELLO_REQ");

      break;

      case KADEMLIA2_HELLO_REQ:

        LOG_DEBUG("KADEMLIA2_HELLO_REQ");

        kadproto_kademlia2_hello_req(
                                     ks,
                                     ctrl_pkt,
                                     ctrl_pkt_len,
                                     ip4_no,
                                     port_no,
                                     valid_rcvr_key,
                                     sndr_verify_key
                                    );

      break;

      case KADEMLIA_HELLO_RES:

        LOG_DEBUG("KADEMLIA_HELLO_RES");

      break;

      case KADEMLIA2_HELLO_RES:

        LOG_DEBUG("KADEMLIA2_HELLO_RES");

        kadproto_kademlia2_hello_res(
                                     ks,
                                     ctrl_pkt,
                                     ctrl_pkt_len,
                                     ip4_no,
                                     port_no,
                                     valid_rcvr_key,
                                     sndr_verify_key
                                    );

      break;

      case KADEMLIA2_HELLO_RES_ACK:

        LOG_DEBUG("KADEMLIA2_HELLO_RES_ACK");

      break;

      case KADEMLIA_REQ:

        LOG_DEBUG("KADEMLIA_REQ");

      break;

      case KADEMLIA2_REQ:

        LOG_DEBUG("KADEMLIA2_REQ");

        kadproto_kademlia2_req(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no, sndr_verify_key);

      break;

      case KADEMLIA2_RES:

        LOG_DEBUG("KADEMLIA2_RES");

        kadproto_kademlia2_res(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no);

      break;

      case KADEMLIA_SEARCH_REQ:

        LOG_DEBUG("KADEMLIA_SEARCH_REQ");

      break;

      case KADEMLIA_SEARCH_NOTES_REQ:

      break;

      case KADEMLIA2_SEARCH_NOTES_REQ:

        LOG_DEBUG("KADEMLIA2_SEARCH_NOTES_REQ");

      break;

      case KADEMLIA2_SEARCH_KEY_REQ:

        LOG_DEBUG("KADEMLIA2_SEARCH_KEY_REQ");

      break;

      case KADEMLIA2_SEARCH_SOURCE_REQ:

        LOG_DEBUG("KADEMLIA2_SEARCH_SOURCE_REQ");

        kadproto_kademlia2_search_source_req(
                                             ks,
                                             ctrl_pkt,
                                             ctrl_pkt_len,
                                             ip4_no,
                                             port_no,
                                             sndr_verify_key
                                             );

      break;

      case KADEMLIA_SEARCH_RES:

        LOG_DEBUG("KADEMLIA_SEARCH_RES");

      break;

      case KADEMLIA_SEARCH_NOTES_RES:

        LOG_DEBUG("KADEMLIA_SEARCH_NOTES_RES");

      break;

      case KADEMLIA2_SEARCH_RES:

        LOG_DEBUG("KADEMLIA2_SEARCH_RES");

        kadproto_kademlia2_search_res(ks, ctrl_pkt, ctrl_pkt_len, sndr_verify_key);

      break;

      case KADEMLIA_PUBLISH_REQ:

        LOG_DEBUG("KADEMLIA_PUBLISH_REQ");

      break;

      case KADEMLIA_PUBLISH_NOTES_REQ:

        LOG_DEBUG("KADEMLIA_PUBLISH_NOTES_REQ");

      break;

      case KADEMLIA2_PUBLISH_NOTES_REQ:

        LOG_DEBUG("KADEMLIA2_PUBLISH_NOTES_REQ");

      break;

      case KADEMLIA2_PUBLISH_KEY_REQ:

        LOG_DEBUG("KADEMLIA2_PUBLISH_KEY_REQ");

      break;

      case KADEMLIA2_PUBLISH_SOURCE_REQ:

        LOG_DEBUG("KADEMLIA2_PUBLISH_SOURCE_REQ");

      break;

      case KADEMLIA_PUBLISH_RES:

        LOG_DEBUG("KADMLIA_PUBLISH_RES");

      break;

      case KADEMLIA_PUBLISH_NOTES_RES:

        LOG_DEBUG("KADEMLIA_PUBLISH_NOTES_RES");

      break;

      case KADEMLIA2_PUBLISH_RES:

        LOG_DEBUG("KADEMLIA2_PUBLISH_RES");

      break;

      case KADEMLIA2_FIREWALLED_REQ:

        LOG_DEBUG("KADEMLIA2_FIREWALLED_REQ");

      break;

      case KADEMLIA_FIREWALLED_RES:

        LOG_DEBUG("KADEMLIA_FIREWALLED_RES");

        kadproto_kademlia2_firewalled_res(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no);

      break;

      case KADEMLIA_FIREWALLED_ACK_RES:

        LOG_DEBUG("KADEMLIA_FIREWALLED_ACK_RES");

      break;

      case KADEMLIA_FINDBUDDY_REQ:

        LOG_DEBUG("KADEMLIA_FINDBUDDY_REQ");

      break;

      case KADEMLIA_FINDBUDDY_RES:

        LOG_DEBUG("KADEMLIA_FINDBUDY_RES");

      break;

      case KADEMLIA_CALLBACK_REQ:

        LOG_DEBUG("KADEMLIA_CALLBACK_REQ");

      break;

      case KADEMLIA2_PING:

        LOG_DEBUG("KADEMLIA2_PING");

        kadproto_kademlia_ping(ks, ip4_no, port_no, sndr_verify_key);

      break;

      case KADEMLIA2_PONG:

        LOG_DEBUG("KADEMLIA2_PONG");

        kadproto_kademlia2_pong(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no);

      break;

      case KADEMLIA2_FIREWALLUDP:

        LOG_DEBUG("KADEMLIA2_FIREWALLUDP");

        kadproto_kademlia2_fw_udp(ks, ctrl_pkt, ctrl_pkt_len, ip4_no, port_no);

      break;

      default:

        LOG_DEBUG("Unknown op(%.2d)", op);

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_get_control_packet_to_send(
                               KAD_SESSION* ks,
                               void** pkt_out,
                               uint32_t* pkt_len_out
                               )
{
  bool result = false;
  KAD_QUEUED_PACKET* qpkt = NULL;
  uint32_t sndr_verify_key = 0;
  uint8_t* enc_pkt = NULL;
  uint32_t enc_pkt_len = 0;

  do {

    if (!ks || !pkt_out || !pkt_len_out) break;

    DEQ_OUT_UDP(ks, (void**)&qpkt);

    if (!qpkt) break;

    if (qpkt->encrypt){
      
      kadhlp_calc_udp_verify_key(ks->udp_key, qpkt->ip4_no, &sndr_verify_key);

      cipher_encrypt_packet(
                            qpkt->pkt, 
                            qpkt->pkt_len, 
                            &qpkt->kad_id, 
                            qpkt->recv_verify_key, 
                            sndr_verify_key, 
                            &enc_pkt, 
                            &enc_pkt_len
                            );

    } else {

      enc_pkt_len = qpkt->pkt_len;

      enc_pkt = (uint8_t*)mem_alloc(enc_pkt_len);

      if (enc_pkt) memcpy(enc_pkt, qpkt->pkt, enc_pkt_len);

    }

    *pkt_out = enc_pkt;

    *pkt_len_out = enc_pkt_len;

    kadqpkt_destroy(qpkt);

    result = true;

  } while (false);

  return result;
}

bool
kad_control_packet_received(
                            KAD_SESSION* ks,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            void* ctrl_pkt,
                            uint32_t ctrl_pkt_len
                            )
{
  bool result = false;
  KAD_QUEUED_PACKET* qpkt = NULL;
  void* pkt = NULL;

  do {

    if (!ks || !ctrl_pkt || !ctrl_pkt_len) break;
    
    pkt = mem_alloc(ctrl_pkt_len);

    if (!pkt){

      LOG_ERROR("Failed to allocate memory for control packet.");

      break;

    }

    memcpy(pkt, ctrl_pkt, ctrl_pkt_len);

    if (!kadqpkt_alloc(ip4_no, port_no, pkt, ctrl_pkt_len, &qpkt)){

      LOG_ERROR("Failed to create queued packet.");

      break;

    }

    QUEUE_IN_UDP(ks, qpkt);

    result = true;

  } while (false);

  return result;
}

bool
kad_deq_and_handle_control_packet(
                                  KAD_SESSION* ks
                                  )
{
  bool result = false;
  KAD_QUEUED_PACKET* qpkt = NULL;
  uint32_t rcvr_verify_key = 0;
  uint32_t sndr_verify_key = 0;
  uint32_t calc_verify_key = 0;
  bool encrypted = false;
  bool compressed = false;
  uint8_t* dec_pkt = NULL;
  uint32_t dec_pkt_len = 0;
  uint8_t* unk_pkt = NULL;
  uint32_t unk_pkt_len = 0;

  do {

    DEQ_IN_UDP(ks, (void**)&qpkt);

    if (!qpkt) break;

    encrypted = cipher_is_packet_encrypted(qpkt->pkt, qpkt->pkt_len);

    if (encrypted){

      if (!cipher_decrypt_packet(
                                 qpkt->pkt,
                                 qpkt->pkt_len,
                                 qpkt->ip4_no,
                                 &ks->kad_id,
                                 ks->udp_key,
                                 &dec_pkt,
                                 &dec_pkt_len,
                                 &rcvr_verify_key,
                                 &sndr_verify_key
                                 )
      ){

        LOG_ERROR("Failed to decrypt control packet.");

        break;

      }

    } else {

      dec_pkt = qpkt->pkt;

      dec_pkt_len = qpkt->pkt_len;

    }

    compressed = compress_is_packet_compressed(dec_pkt, dec_pkt_len);

    if (compressed){

      if (!compress_uncompress_packet(
                                      dec_pkt,
                                      dec_pkt_len,
                                      &unk_pkt,
                                      &unk_pkt_len
                                      )
      ){

        LOG_ERROR("Failed to uncompress packet.");

        break;

      }

    } else {

      unk_pkt = dec_pkt;

      unk_pkt_len = dec_pkt_len;

    }

    // Here was firewall check start, probably need to stuck it somwhere else.
    
    kadhlp_calc_udp_verify_key(ks->udp_key, qpkt->ip4_no, &calc_verify_key);
    
    result = kad_handle_control_packet(
                                       ks, 
                                       unk_pkt, 
                                       unk_pkt_len, 
                                       qpkt->ip4_no, 
                                       qpkt->port_no, 
                                       calc_verify_key == rcvr_verify_key,
                                       sndr_verify_key
                                       );

  } while (false);

  if (compressed && unk_pkt){

    mem_free(unk_pkt);

  }

  if (encrypted && dec_pkt){

    mem_free(dec_pkt);

  }

  if (qpkt) kadqpkt_destroy(qpkt);

  return result;
}
