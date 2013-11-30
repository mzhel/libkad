#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <log.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadsrch.h>
#include <kadproto.h>
#include <kadqpkt.h>
#include <packet.h>
#include <tag.h>
#include <mem.h>

bool
kadproto_kademlia2_bootstrap_req(
                                 KAD_SESSION* ks,
                                 uint32_t ip4_no,
                                 uint16_t port_no,
                                 uint32_t sender_key
                                 )
{
  bool result = false;
  LIST* kn_lst = NULL;
  uint32_t kn_cnt = 0;
  void* bs_pkt = NULL;
  uint32_t bs_pkt_len = 0;
  KAD_QUEUED_PACKET* qp = NULL;

  do {

    if (!routing_get_bootstrap_contacts(ks->root_zone, BOOTSTRAP_CONTACTS_COUNT, &kn_lst, true)){

      LOG_ERROR("Failed to get contacts for bootstrap request.");

      break;

    }

    list_entries_count(kn_lst, &kn_cnt);

    if (kn_cnt){

      LOG_WARN("No bootstrap contacts, answer packeet won't be send.");

      break;

    }

    if (!kadpkt_create_bootstrap_res(&ks->kad_id, port_no, kn_lst, &bs_pkt, &bs_pkt_len)){

      LOG_ERROR("Failed to create bootstrap response packet.");

      break;

    }

    if (!kadqpkt_create_udp(&ks->kad_id, ip4_no, port_no, NULL, sender_key, bs_pkt, bs_pkt_len, &qp)){

      LOG_ERROR("Failed to create bootstrap response packet.");

      break;

    }

    QUEUE_OUT_UDP(ks, qp);

    result = true;

  } while (false);
  
  if (!result && bs_pkt) mem_free(bs_pkt);

  list_destroy(bs_pkt, false);

  return result;
}

bool
kadproto_kademlia2_bootstrap_res(
                                 KAD_SESSION* ks,
                                 uint8_t* pkt_data,
                                 uint32_t pkt_data_len,
                                 uint32_t ip4_no,
                                 uint16_t port_no,
                                 uint32_t sender_key,
                                 bool ip_verified
                                )
{
  bool result = false;
  UINT128 node_id;
  UINT128 dist;
  uint32_t ip4 = 0;
  uint32_t kn_cnt = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint16_t tcp_port = 0;
  uint16_t udp_port = 0;
  uint8_t ver = 0;
  KAD_NODE* kn;
  bool updated = false;

  do {

    if (!ks || !pkt_data || !pkt_data_len) break;

    if (!routing_get_nodes_count(ks->root_zone, &kn_cnt, true)){

      LOG_ERROR("Failed to get nodes count.");

      break;

    }

    // No nodes in zone - first bootstrap.
    
    if (!kn_cnt) ip_verified = true;

    p = pkt_data;

    rem_len = pkt_data_len;

    // Node id
    
    uint128_from_buffer(&node_id, p, sizeof(UINT128), false);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Tcp port
    
    tcp_port = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Version 
    
    ver = *p++;

    rem_len--;

    // Nodes count
    
    kn_cnt = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Add responded node to routing zone

    uint128_xor(&ks->kad_id, &node_id, &dist);

    if (!node_create(
                     (UINT128*)&node_id,
                     kadses_get_pub_ip(ks),
                     ip4_no,
                     htons(tcp_port), // tcp port
                     port_no, // udp port
                     ver,
                     sender_key,
                     ip_verified,
                     &dist,
                     &kn
                     )
    ){

      LOG_ERROR("Failed to create node.");

      break;

    }

    kn->ip_verified = ip_verified;

    if (!routing_add_node(
                          &ks->active_zones,
                          ks->root_zone,
                          kn,
                          kadses_get_pub_ip(ks),
                          true,
                          &updated,
                          true
                          )
    ) node_destroy(kn);

    // Add nodes from respone list.
    
    for (uint32_t i = 0; i < kn_cnt; i++){

      if (rem_len < sizeof(UINT128) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t)) break;

      kn = NULL;

      // Node id.

      uint128_from_buffer(&node_id, p, sizeof(UINT128), false); 

      p += sizeof(UINT128);

      rem_len -= sizeof(UINT128);

      // Ip addr.

      ip4 = *(uint32_t*)p;

      p += sizeof(uint32_t);

      rem_len -= sizeof(uint32_t);

      // Udp port.

      udp_port = *(uint16_t*)p;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Tcp port.

      tcp_port = *(uint16_t*)p;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Version.

      ver = *p++;

      rem_len--;

      uint128_xor(&ks->kad_id, &node_id, &dist);

      if (!node_create(
                       (UINT128*)&node_id,
                       kadses_get_pub_ip(ks),
                       htonl(ip4),
                       htons(tcp_port),
                       htons(udp_port),
                       ver,
                       0,
                       ip_verified,
                       &dist,
                       &kn
                      )
      ){

        LOG_ERROR("Failed to create kad node.");

        break;

      }

      kn->ip_verified = ip_verified;

      if (!routing_add_node(
                            &ks->active_zones, 
                            ks->root_zone, 
                            kn, 
                            kadses_get_pub_ip(ks),
                            true,
                            &updated,
                            true
                            )
      ){

        node_destroy(kn);

      }

    }

    result = true;

  } while (false);

  return result;
}

bool
kadproto_kademlia2_req(
                       KAD_SESSION* ks,
                       uint8_t* pkt_data,
                       uint32_t pkt_data_len,
                       uint32_t ip4_no,
                       uint16_t port_no,
                       uint32_t sender_key
                      )
{
  bool result = false;
  uint8_t kn_cnt = 0;
  UINT128 trgt;
  UINT128 self_id;
  UINT128 dst;
  LIST* res_lst = NULL;
  void* resp_pkt = NULL;
  uint32_t resp_pkt_len = 0;
  uint32_t res_cnt = 0;
  uint32_t kn_closest_cnt = 0;
  KAD_QUEUED_PACKET* qp = NULL;

  do {

    if (!ks || !pkt_data) break;

    if (pkt_data_len < (sizeof(UINT128) * 2) + 1){

      LOG_ERROR("Packet length is too small.");

      break;

    }

    kn_cnt = *pkt_data;

    kn_cnt &= 0x1f;

    uint128_from_buffer(&trgt, pkt_data + 1, pkt_data_len - 1, false);

    uint128_from_buffer(&self_id, pkt_data + 1 + sizeof(UINT128), pkt_data_len - 1 - sizeof(UINT128), false);

    uint128_xor(&ks->kad_id, &trgt, &dst);

    if (0 == uint128_compare(&ks->kad_id, &self_id)){

      LOG_WARN("Node id in request is not ours so response won't be send.");

      break;

    }

    if (!routing_get_closest_to(ks->root_zone, 2, kn_cnt, &trgt, &dst, true, &res_lst, true)){

      LOG_ERROR("Failed to get closest entries.");

      break;

    }

    list_entries_count(res_lst, &kn_closest_cnt);

    // result list is a list of NODE_LIST_ENTRY entries.
    
    if (!kadpkt_create_search_response(&trgt, res_lst, &resp_pkt, &resp_pkt_len)){

      LOG_ERROR("Failed to create search response packet.");

      break;

    }

    if (!kadqpkt_create_udp(&ks->kad_id, ip4_no, port_no, NULL, sender_key, resp_pkt, resp_pkt_len, &qp)){

      LOG_ERROR("Failed to create bootstrap response packet.");

      break;

    }

    QUEUE_OUT_UDP(ks, qp);

    result = true;

  } while (false);

  if (!result && resp_pkt) mem_free(resp_pkt);

  if (res_lst){

    // [IMPLEMENT] unlock nodes list.
    
    list_destroy(res_lst, false);

  }

  return result;
}

bool
kadproto_kademlia2_res(
                       KAD_SESSION* ks,
                       uint8_t* pkt_data,
                       uint32_t pkt_data_len,
                       uint32_t ip4_no,
                       uint16_t port_no
                      )
{
  bool result = false;
  ROUTING_ZONE* rz = NULL;
  UINT128 trgt;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint8_t num_cnt = 0;
  bool fw_chk = false;
  KAD_NODE* kn = NULL;
  UINT128 kn_id;
  uint32_t kn_ip4 = 0;
  uint16_t kn_udp_prt = 0;
  uint16_t kn_tcp_prt = 0;
  uint8_t kn_ver = 0;
  UINT128 dst_to_kn;
  bool updated = false;
  LIST* kn_from_resp = NULL;

  do {

    if (!pkt_data || !pkt_data_len) break;

    rz = ks->root_zone;

    // [TODO] Legacy challenge check
    
    p = pkt_data;

    rem_len = pkt_data_len;

    // target

    uint128_from_buffer(&trgt, p, rem_len, false);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Count
    
    num_cnt = *p++;

    rem_len--;


    if (kad_search_is_udp_fw_check(ks, &trgt)){

      fw_chk = true;

    }

    // Add all nodes from response to routing tables
    // on in case of firewall check to firewall
    // check list.

    for (uint32_t i = 0; i < num_cnt; i++){

      if (rem_len < sizeof(UINT128) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t)) break;

      kn = NULL;

      // Node id

      uint128_from_buffer(&kn_id, p, rem_len, false);

      p += sizeof(UINT128);

      rem_len -= sizeof(UINT128);

      // Node ip
      
      kn_ip4 = *(uint32_t*)p;

      p += sizeof(uint32_t);

      rem_len -= sizeof(uint32_t);

      // Udp port
      
      kn_udp_prt = *(uint16_t*)p;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Tcp port
      
      kn_tcp_prt = *(uint16_t*)p;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Node version
      
      kn_ver = *p;

      p++;

      rem_len--;

      // Calculate distance from self to node.
      
      uint128_xor(&ks->kad_id, &kn_id, &dst_to_kn);

      if (!node_create(
                       &kn_id, 
                       kadses_get_pub_ip(ks), 
                       htonl(kn_ip4), 
                       htons(kn_tcp_prt), 
                       htons(kn_udp_prt), 
                       kn_ver, 
                       0, 
                       false, 
                       &dst_to_kn, 
                       &kn
                       )
      ){

        LOG_ERROR("Failed to create node.");

        continue;

      }

      if (fw_chk){

        // This is response to firewall check request.
        
        if (!kad_fw_add_node_for_udp_check(&ks->fw, kn)){

          LOG_ERROR("Failed to add node to fw check nodes.");

          node_destroy(kn);

          break;

        }

      } else {

        // [TODO] check before adding if we already have this contact with changed ip,
        // and if it is exist and pass checks add it to search results.
        
        if (routing_add_node(&ks->active_zones, rz, kn, kadses_get_pub_ip(ks), false, &updated, true)){

          LOG_WARN("Failed to add node to routing zone.");

          node_destroy(kn);

        } else {

          kn->in_use++;

          list_add_entry(&kn_from_resp, (void*)kn);

        }

      }

    }

    // Process search response in search module.
    
    kad_search_process_response(ks, &trgt, ip4_no, port_no, kn_from_resp, &ks->searches);

    if (kn_from_resp) list_destroy(kn_from_resp, false);

    result = true; 

  } while (false);

  return result;
}

bool
kadproto_kademlia2_search_source_req(
                                     KAD_SESSION* ks,
                                     uint8_t* pkt_data,
                                     uint32_t pkt_data_len,
                                     uint32_t ip4_no,
                                     uint16_t port_no,
                                     uint32_t sender_key
                                    )
{
  bool result = false;

  do {

    // [IMPLEMENT]

    result = true;

  } while (false);

  return result;
}

bool
kadproto_kademlia_ping(
                       KAD_SESSION* ks,
                       uint32_t ip4_no,
                       uint16_t port_no,
                       uint32_t sender_key
                      )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

      if (!ks) break;

      if (!kadpkt_create_pong(port_no, &pkt, &pkt_len)){

        LOG_ERROR("Failed to create pong packet.");

        break;

      }

      if (!kadses_create_queue_udp_pkt(ks, &ks->kad_id, ip4_no, port_no, NULL, sender_key, &pkt, pkt_len)){

        LOG_ERROR("Failed to queue pong packet.");

        break;

      }

      result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kadproto_kademlia2_pong(
                        KAD_SESSION* ks,
                        uint8_t* pkt_data,
                        uint32_t pkt_data_len,
                        uint32_t ip4_no,
                        uint16_t port_no
                       )
{
  bool result = false;
  uint16_t ext_port = 0;

  do {

    kad_fw_set_extrn_port(&ks->fw,ip4_no, *(uint16_t*)pkt_data);

    if (kad_fw_extrn_port_valid(&ks->fw)){

      kad_fw_get_extrn_port(&ks->fw, &ext_port);

      // [IMPLEMENT] callback about external port resolving.

    }

    result = true;

  } while (false);

  return result;
}

bool
kadproto_kademlia2_search_res(
                              KAD_SESSION* ks,
                              uint8_t* pkt_data,
                              uint32_t pkt_data_len,
                              uint32_t sender_key
                              )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  UINT128 sndr_id;
  UINT128 srch_key;
  uint16_t res_cnt = 0;
  UINT128 answ_id;
  uint8_t tags_in_answ = 0;
  TAG* tag = NULL;
  uint32_t io_bytes = 0;
  bool failed = false;
  LIST* tag_lst = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    p = pkt_data;

    rem_len = pkt_data_len;

    // Sender id

    uint128_from_buffer(&sndr_id, p, rem_len, false);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Searhc key hash
    
    uint128_from_buffer(&srch_key, p, rem_len, false);
        
    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Results count
    
    res_cnt = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    while(res_cnt--){

      // Answer id

      uint128_from_buffer(&answ_id, p, rem_len, false);

      p += sizeof(UINT128);

      rem_len -= sizeof(UINT128);

      // Tags in answer
      
      tags_in_answ = *p++;

      while(tags_in_answ--){

        tag = NULL;

        if (!tag_read(p, rem_len, false, &tag, &p, &io_bytes)){

          LOG_ERROR("Failed to read tag.");

          failed = true; 

          break;

        }

        rem_len -= io_bytes;

        list_add_entry(&tag_lst, (void*)tag);

      }

      if (failed){

        if (tag) tag_destroy(tag);

        break;

      }

      kad_search_process_result(ks, &srch_key, &answ_id, tag_lst);

      list_destroy(tag_lst, true);

      tag_lst = NULL;

    }

    if (failed) break;
    
    result = true;

  } while (false);

  if (tag_lst) list_destroy(tag_lst, true);

  return result;
}

bool
kadproto_kademlia2_hello_req(
                             KAD_SESSION* ks,
                             uint8_t* pkt_data,
                             uint32_t pkt_data_len,
                             uint32_t ip4_no,
                             uint16_t port_no,
                             bool valid_rcvr_key,
                             uint32_t sndr_key
                             )
{
  bool result = false;
  UINT128 kn_id;
  UINT128 dist;
  uint16_t tcp_port;
  uint16_t udp_port;
  uint16_t int_udp_port;
  uint8_t ver = 0;
  bool udp_fw = false;
  bool tcp_fw = false;
  bool ack_needed = false;
  KAD_NODE* kn = NULL;
  bool res_queued = false;
  bool kn_updated = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks || !pkt_data || !pkt_data_len) break;

    if (!kadpkt_parse_hello(pkt_data, pkt_data_len, &kn_id, &tcp_port, &int_udp_port, &ver, &udp_fw, &tcp_fw, &ack_needed)){

      LOG_ERROR("Failed to parse hello packet.");

      break;

    }

    if (int_udp_port) udp_port = int_udp_port;

    if (udp_fw){

      uint128_xor(&ks->kad_id, &kn_id, &dist);

      if (!node_create(
                       &kn_id,
                       kadses_get_pub_ip(ks),
                       ip4_no,
                       htons(tcp_port),
                       htons(udp_port),
                       ver,
                       sndr_key,
                       valid_rcvr_key,
                       &dist,
                       &kn
                      )
      ){

        LOG_ERROR("Failed to create node.");

        break;

      }

      kn->hello_received = true;

      if (!routing_add_node(&ks->active_zones, ks->root_zone, kn, kadses_get_pub_ip(ks), true, &kn_updated, true)){

        LOG_ERROR("Failed to ad node to routing zone.");

        node_destroy(kn);

      }

    }

    // Send hello response
    
    if (!kadpkt_create_hello_res(
                                 &ks->kad_id, 
                                 ks->tcp_port, 
                                 ks->udp_port, 
                                 KADEMLIA_VERSION, 
                                 0, 
                                 &ks->kad_id, 
                                 false,
                                 kad_fw_firewalled(&ks->fw),
                                 kad_fw_firewalled_udp(&ks->fw),
                                 &pkt, 
                                 &pkt_len
                                 )
     ){

      LOG_ERROR("Failed to create hello response packet.");

      break;

    }

    if (!kadses_create_queue_udp_pkt(ks, &ks->kad_id, ip4_no, port_no, NULL, sndr_key, pkt, pkt_len)){

      LOG_ERROR("Failed ot queue hello resp packet.");

      break;

    }

    res_queued = true;

    // [TODO] ping and firewall check
    
    if (kad_fw_need_more_udp_checks(&ks->fw)){

      // kad_fw_queue_check_pkt
      // [IMPLEMENT] sources implementation needed.

    }

    result = true;

  } while (false);

  if (!res_queued && pkt) mem_free(pkt);

  return result;
}

bool
kadproto_kademlia2_hello_res(
                             KAD_SESSION* ks,
                             uint8_t* pkt_data,
                             uint32_t pkt_data_len,
                             uint32_t ip4_no,
                             uint16_t port_no,
                             bool valid_rcvr_key,
                             uint32_t sndr_key
                            )
{
  bool result = false;
  UINT128 kn_id;
  UINT128 dist;
  uint16_t tcp_port;
  uint16_t udp_port;
  uint16_t int_udp_port = 0;
  uint8_t ver = 0;
  uint8_t tag_cnt;
  bool udp_fw = false;
  bool tcp_fw = false;
  bool ack_needed = false;
  KAD_NODE* kn = NULL;
  bool kn_updated = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  bool ack_queued = false;

  do {

    udp_port = ntohs(port_no);

    if (kadpkt_parse_hello(
                           pkt_data,
                           pkt_data_len,
                           &kn_id,
                           &tcp_port,
                           &int_udp_port,
                           &ver,
                           &udp_fw,
                           &tcp_fw,
                           &ack_needed
                          )
    ){

      LOG_ERROR("Failed to parse hello packet.");

      break;

    }

    if (int_udp_port) udp_port = int_udp_port;

    // [TODO] fetch node id requests
    
    if (!udp_fw){

      uint128_xor(&ks->kad_id, &kn_id, &dist);

      if (!node_create(
                       &kn_id,
                       kadses_get_pub_ip(ks),
                       ip4_no,
                       htons(tcp_port),
                       htons(udp_port),
                       ver,
                       sndr_key,
                       valid_rcvr_key,
                       &dist,
                       &kn
                      )
      ){

        LOG_ERROR("Failed to create node.");

        break;

      }

      kn->hello_received = true;

      if (!routing_add_node(
                            &ks->active_zones, 
                            ks->root_zone, 
                            kn, 
                            kadses_get_pub_ip(ks),
                            true,
                            &kn_updated,
                            true
                            )
      ){

        LOG_ERROR("Failed to add node to routing zone.");

        node_destroy(kn);

        break;

      }

    }

    if (ack_needed){

      if (!kadpkt_create_hello_ack(&ks->kad_id, &pkt, &pkt_len)){

        LOG_ERROR("Failed to create hello ack packet.");

        break;

      }

      if (!kadses_create_queue_udp_pkt(ks, &ks->kad_id, ip4_no, port_no, NULL, sndr_key, pkt, pkt_len)){

        LOG_ERROR("Failed to queue hello ack packet.");

        break;

      }

      ack_queued = true;

    }

    if (kad_fw_need_more_udp_checks(&ks->fw)){

      // kad_fw_queue_check_pkt
      // [IMPLEMENT] sources implementation needed.

    }

    //[TODO] external port and firewall checks

    result = true;

  } while (false);

  if (!ack_queued && pkt) mem_free(pkt);

  return result;
}

bool
kadproto_kademlia2_fw_udp(
                          KAD_SESSION* ks,
                          uint8_t* pkt_data,
                          uint32_t pkt_data_len,
                          uint32_t ip4_no,
                          uint16_t port_no
                         )
{
  bool result = false;
  uint32_t rem_len = 0;
  uint8_t* p = NULL;
  uint8_t already_known;
  uint16_t inc_port = 0;
  bool udp_fwld = false;

  do {

      if (!ks || !pkt_data || !pkt_data_len) break;

      p = pkt_data;

      rem_len = pkt_data_len;

      // Already known flag
      
      already_known = *p++;

      rem_len--;

      // Incoming udp port
      
      inc_port = *(uint16_t*)p;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // [IMPLEMENT] // kad_fw_udp_check_response
      
      // [IMPLEMENT] // callback for udp firewalled status

    result = true;

  } while (false);

  return result;
}

bool
kadproto_kademlia2_firewalled_res(
                                  KAD_SESSION* ks,
                                  uint8_t* pkt_data,
                                  uint32_t pkt_data_len,
                                  uint32_t ip4_no,
                                  uint16_t port_no
                                 )
{
  bool result = false;
  uint32_t fw_ip4_no = 0;

  do {

    if (!ks || !pkt_data || !pkt_data_len) break;

    fw_ip4_no = htonl(*(uint32_t*)pkt_data);

    kadses_set_pub_ip(ks, fw_ip4_no);

    // [IMPLEMENT] callback about public ip resolved

    result = true;

  } while (false);

  return result;
}
