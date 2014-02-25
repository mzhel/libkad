#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadhlp.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <kad.h>
#include <random.h>
#include <ticks.h>
#include <cipher.h>
#include <comprs.h>
#include <kaddbg.h>
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
  struct in_addr ia;

  do {

    if (!ks || !rz || !rz->kb) break;

    kb = rz->kb;

    kn_cnt = kb->nodes_count;

    // Check all nodes for expiration,
    // if node expire time is not set -
    // set it to now. If node expiration time
    // is lesser than now remove node from bucket
    // and destroy it.

    for (uint32_t i = 0; i < kn_cnt; i++){

      kn = kb->nodes[i];

      if (kn->status == NODE_STATUS_TO_REMOVE || ((kn->status & NODE_STATUS_WAIT_MASK) && kn->packet_timeout < now)){

        LOG_DEBUG("Removing node: %s:%d with status %s, packet timeout.", kn->ip4_str, ntohs(kn->udp_port_no), node_status_str(kn));

        if (!kbucket_remove_node_by_idx(kb, i, &rmvd_kn)){

          LOG_ERROR("Failed to delete expired node.");

          break;

        }

        kn_cnt--;

        node_destroy(rmvd_kn);
          
      }

    }

    if (!kbucket_get_oldest_node(kb, &kn)) break;

    if (!kn) break;

    if (kn->next_check_time >= now){

      kbucket_push_node_up(kb, kn);

    } else {

      switch (kn->status){

        case NODE_STATUS_NEW:

          if (kadhlp_send_hello_req_pkt_to_node(ks, kn)){

            kn->packet_timeout = now + SEC2MS(15);

            kn->status = NODE_STATUS_HELLO_REQ_SENT;

            LOG_DEBUG("NODE_STATUS_HELLO_REQ_SENT for %s:%d", kn->ip4_str, ntohs(kn->udp_port_no));

          } else {

            // Something happened and hello request was not sent.
            
            if (kn->version < 2) kn->status = NODE_STATUS_TO_REMOVE;

          }

        break;

        case NODE_STATUS_HELLO_RES_RECEIVED:

        case NODE_STATUS_PONG_RECEIVED:

          kadhlp_send_ping_pkt_to_node(ks, kn);

          kn->packet_timeout = now + SEC2MS(10);

          kn->status = NODE_STATUS_PING_SENT;

          LOG_DEBUG("NODE_STATUS_PING_SENT for %s:%d", kn->ip4_str, ntohs(kn->udp_port_no));

        break;

      }

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_session_init(
                 uint16_t tcp_port,
                 uint16_t udp_port,
                 char* nodes_file_path,
                 KAD_SESSION** ks_out
                 )
{
  bool result = false;
  KAD_SESSION* ks = NULL;
  struct hostent* he = NULL;
  UINT128 zone_idx;
  uint32_t now = 0;

  do {

    LOG_PREFIX("[libkad] ");

    LOG_LEVEL_DEBUG;

    LOG_FILE_NAME("libkad.log");

    LOG_OUTPUT_CONSOLE_AND_FILE;
    
    if (!ks_out) break;

    ks = (KAD_SESSION*)mem_alloc(sizeof(KAD_SESSION));

    if (!ks){

      LOG_ERROR("Failed to allocate memory for kad session.");

      break;

    }

    ks->version = KADEMLIA_VERSION;

    random_init(ticks_now_ms());

    he = gethostbyname("localhost");

    ks->loc_ip4_no = *(uint32_t*)he->h_addr;

    kad_fw_set_status(&ks->fw, true);

    kad_fw_set_status_udp(&ks->fw, true);

    uint128_generate(&ks->kad_id);

    LOG_DEBUG_UINT128("kad_id: ", ((UINT128*)&ks->kad_id));

    for (uint32_t i = 0; i < sizeof(ks->user_hash); i++){

      ks->user_hash[i] = random_uint8();

    }

    ks->user_hash[5] = 14;

    ks->user_hash[14] = 111;

    kadhlp_gen_udp_key(&ks->udp_key);

    LOG_DEBUG("udp_key: %.8x", ks->udp_key);

    ks->udp_port = udp_port;

    ks->tcp_port = tcp_port;

    LOG_DEBUG("udp_port = %d", udp_port);

    LOG_DEBUG("tcp_port = %d", tcp_port);

    uint128_init(&zone_idx, 0);

    routing_create_zone(NULL, 0, &zone_idx, &ks->root_zone);

    list_add_entry(&ks->active_zones, ks->root_zone);

    now = ticks_now_ms();

    ks->timers.self_lookup = now + MIN2MS(3);

    ks->timers.udp_port_lookup = now;

    ks->timers.nodes_count_check = now + SEC2MS(10);

    ks->opts.use_extrn_udp_port = true;

    queue_create(CONTROL_PACKET_QUEUE_LENGTH, &ks->queue_in_udp);

    queue_create(CONTROL_PACKET_QUEUE_LENGTH, &ks->queue_out_udp);

    if (nodes_file_path) kadhlp_add_nodes_from_file(ks, nodes_file_path);
  
    *ks_out = ks;

    result = true;

  } while (false);

  return result;
}

bool
kad_session_uninit(
                   KAD_SESSION* ks
                   )
{
  bool result = false;

  do {

    kadhlp_destroy_qpkt_queue(ks, ks->queue_in_udp);

    kadhlp_destroy_qpkt_queue(ks, ks->queue_out_udp);

    routing_destroy_zone(ks->root_zone);

    list_destroy(ks->active_zones, false);

    kad_search_delete_all_from_ongoing(&ks->searches);

    list_destroy(ks->searches, false);

    kad_fw_destroy(&ks->fw);

    mem_free(ks);

    result = true;

  } while (false);

  return result;
}

bool
kad_session_set_id(
                   KAD_SESSION* ks,
                   UINT128* id
                  )
{
  bool result = false;

  do {

    if (!ks || !id) break;

    uint128_copy(id, &ks->kad_id);

    result = true;

  } while (false);

  return result;
}

bool
kad_session_update(
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

    if (ks->timers.self_lookup <= now){

      LOG_DEBUG("Self-lookup.");

      kad_search_find_node(ks, ks->root_zone, &ks->kad_id, &ks->kad_id, true, &ks->searches);

      ks->timers.self_lookup = now + HR2MS(4);

    }

    if (ks->timers.udp_port_lookup <= now && kad_fw_udp_check_running(&ks->fw) && !kad_fw_extrn_port_valid(&ks->fw)){

      LOG_DEBUG("Ping packet to random node.");

      kadhlp_send_ping_pkt_to_rand_node(ks);

      ks->timers.udp_port_lookup = now + SEC2MS(15);

    }

    if (
        !kad_fw_udp_check_started(&ks->fw) && 
        kad_fw_udp_check_running(&ks->fw) &&
        kad_fw_need_more_udp_checks(&ks->fw)
      ){

      ks->fw.udp_check_running = true; 

      LOG_DEBUG("Starting search for nodes for udp firewall check.");

      kad_search_find_node_for_fw_check(
                                        ks,
                                        ks->root_zone,
                                        &ks->kad_id, 
                                        &ks->searches
                                       );

    }

    if (kad_fw_extrn_port_valid(&ks->fw) && kad_fw_need_more_udp_checks(&ks->fw)){

      LOG_DEBUG("Sending udp firewall check request.");

      kad_fw_udp_check_request(ks);

    }

    ACTIVE_ZONES_LOCK(ks);

    zones_locked = true;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ks->active_zones, e, rz);

      if (now >= rz->next_bucket_timer){

        kad_zone_update_bucket(ks, rz);

        rz->next_bucket_timer = now + MIN2MS(1);

      }

      if (now >= rz->next_lookup_timer){

        LOG_DEBUG("Random lookup.");

        kad_zone_random_lookup(ks, rz, &ks->kad_id);

        rz->next_lookup_timer = now + HR2MS(1);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    // [IMPLEMENT] Empty zones consolidation.

    if (now >= ks->timers.nodes_count_check){

      if (routing_get_nodes_count(ks->root_zone, &kn_cnt, true) && kn_cnt < 200){

    //    LOG_DEBUG("Bootstrap packet.");

    //    kadhlp_send_bs_req_pkt_to_rand_node(ks);

      }

      LOG_DEBUG("Nodes count: %d", kn_cnt);

      ks->timers.nodes_count_check = now + SEC2MS(10);

    }

    ACTIVE_ZONES_UNLOCK(ks);

    zones_locked = false;

    // Jumpstart stalled searches.
  
    if (now >= ks->timers.search_jumpstart){

      // LOG_DEBUG("Jump-start searches.");

      kad_search_jumpstart_all(ks, &ks->searches);

      ks->timers.search_jumpstart = now + SEC2MS(1);

    }

  } while (false);

  return result;
}

bool
kad_timer(KAD_SESSION* ks)
{
  bool result = false;
  uint32_t now = ticks_now_ms();

  do {

    kad_session_update(ks, now);

    kad_deq_and_handle_control_packet(ks);
    
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
                               uint32_t* ip4_no_out,
                               uint16_t* port_no_out,
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

    if (!ks || !ip4_no_out || !port_no_out || !pkt_out || !pkt_len_out) break;

    DEQ_OUT_UDP(ks, (void**)&qpkt);

    if (!qpkt) break;

    KADDBG_PRINT_QPKT("packet to send:", qpkt, true);

    if (qpkt->encrypt){

      LOG_DEBUG("encryption required");
      
      kadhlp_calc_udp_verify_key(ks, ks->udp_key, qpkt->ip4_no, &sndr_verify_key);

      LOG_DEBUG("sndr_verify_key = %.8x", sndr_verify_key);

      cipher_encrypt_packet(
                            ks,
                            qpkt->pkt, 
                            qpkt->pkt_len, 
                            &qpkt->kad_id, 
                            qpkt->recv_verify_key, 
                            sndr_verify_key, 
                            &enc_pkt, 
                            &enc_pkt_len
                            );

    } else {

      LOG_DEBUG("no encryption required");

      enc_pkt_len = qpkt->pkt_len;

      enc_pkt = (uint8_t*)mem_alloc(enc_pkt_len);

      if (enc_pkt) memcpy(enc_pkt, qpkt->pkt, enc_pkt_len);

    }

    if (!enc_pkt || !enc_pkt_len) break;

    LOG_DEBUG("enc_pkt_len = %.8x", enc_pkt_len);

    *ip4_no_out = qpkt->ip4_no;

    *port_no_out = qpkt->port_no;

    *pkt_out = enc_pkt;

    *pkt_len_out = enc_pkt_len;

    result = true;

  } while (false);

  if (qpkt) kadqpkt_destroy(qpkt, true);

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

    KADDBG_PRINT_QPKT("received control packet:", qpkt, true);

    encrypted = cipher_is_packet_encrypted(qpkt->pkt, qpkt->pkt_len);

    if (encrypted){

      LOG_DEBUG("Packet encrypted.");

      if (!cipher_decrypt_packet(
                                 ks,
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

      LOG_DEBUG("Packet compressed.");

      if (!compress_uncompress_packet(
                                      ks,
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

    KADDBG_PRINT_PACKET_HEADER(unk_pkt, unk_pkt_len, "received packet header: ");

    kadhlp_calc_udp_verify_key(ks, ks->udp_key, qpkt->ip4_no, &calc_verify_key);
    
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

  if (qpkt) kadqpkt_destroy(qpkt, true);

  return result;
}

bool
kad_bootstrap_from_node(
                        KAD_SESSION* ks,
                        char* node_addr,
                        uint16_t node_port
                        )
{
  bool result = false;
  uint32_t ip4_no = 0;
  uint16_t port_no = 0;
  struct in_addr sin;

  do {

    if (!ks || !node_addr || !node_port) break;

    memset(&sin, 0, sizeof(sin));

    if (!inet_aton(node_addr, &sin)){

      LOG_ERROR("Failed to convert %s into binary form.", node_addr);

      break;
      
    }

    port_no = htons(node_port);

    ip4_no = sin.s_addr;

    if (!kadhlp_send_bootstrap_pkt(ks, ip4_no, port_no)){

      LOG_ERROR("Failed to send bootstrap packet to %s:%d", node_addr, node_port);

    }

    result = true;

  } while (false);

  return result;
}
