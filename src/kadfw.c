#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadqpkt.h>
#include <kadpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadhlp.h>
#include <kadsrch.h>
#include <str.h>
#include <ticks.h>
#include <tag.h>
#include <mem.h>
#include <log.h>

bool
kad_fw_init(
            KAD_FW* kfw 
            )
{
  bool result = false;

  do {

    if (!kfw) break;

    // [LOCK] initialize nodes and used nodes lock.

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_free_nodes_for_udp_check(
                                KAD_FW* kfw
                               )
{
  bool result = false;
  UDP_FW_CHECK_NODE* ufcn = NULL;
  KAD_NODE* kn = NULL;

  do {

    if (!kfw) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kfw->nodes_for_udp_check, e, kn);

      node_destroy(kn);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(kfw->nodes_for_udp_check, false);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_free_nodes_used_for_udp_fw_check(
                                        KAD_FW* kfw
                                       )
{
  bool result = false;

  do {

    if (!kfw) break;

    list_destroy(kfw->nodes_used_for_udp_check, true);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_destroy(
               KAD_FW* kfw
              )
{
  bool result = false;

  do {

    if (!kfw) break;

    // [LOCK] Delete locks
    
    list_destroy(kfw->extrn_port_asked_ips, false);

    list_destroy(kfw->extrn_ports, false);

    kad_fw_free_nodes_used_for_udp_fw_check(kfw);

    kad_fw_free_nodes_for_udp_check(kfw);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_set_extrn_port(
                      KAD_FW* kfw,
                      uint32_t ip4_no,
                      uint32_t new_port
                     )
        
{
  bool result = false;
  uint32_t port = 0;
  bool found = false;

  do {

    if (!kfw) break;

    if (kfw->extrn_udp_port_valid) break;

    if (list_entry_by_data(kfw->extrn_port_asked_ips, (void*)(uint64_t)ip4_no, NULL)){

      // Already have answer from that ip.
      
      break;

    }

    list_add_entry(&kfw->extrn_port_asked_ips, (void*)(uint64_t)ip4_no);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kfw->extrn_ports, e, port);

      if (port == new_port){

        kfw->extrn_udp_port = new_port;

        kfw->extrn_udp_port_valid = true;

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (found) break;

    list_add_entry(&kfw->extrn_ports, (void*)(uint64_t)new_port);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_get_extrn_port(
                      KAD_FW* kfw,
                      uint16_t* ext_prt_out
                     )
{
  bool result = false;

  do {

    if (!kfw || !ext_prt_out) break;

    *ext_prt_out = kfw->extrn_udp_port;

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_extrn_port_valid(
                        KAD_FW* kfw
                       )
{
  bool result = false;

  do {

    result = kfw->extrn_udp_port_valid;

  } while (false);

  return result;
}

bool
kad_fw_udp_check_started(
                         KAD_FW* kfw
                        )
{
  bool result = false;

  do {

    result = kfw->udp_check_running;

  } while (false);

  return result;
}

bool
kad_fw_udp_check_running(
                         KAD_FW* kfw
                        )
{
  bool result = false;

  do {

    result = (kfw->udp_checks_running_cnt < KAD_UDPFWCHECK_CLIENTS_TO_ASK);

  } while (false);

  return result;
}

bool
kad_fw_add_node_for_udp_check(
                              KAD_FW* kfw,
                              void* kn
                             )
{
  bool result = false;
  bool locked = false;

  do {

    if (!kfw || !kn) break;

    FW_NODES_LOCK(fw);

    locked = true;

    if (!list_add_entry(&kfw->nodes_for_udp_check, kn)){

      LOG_ERROR("Failed to add node to udp firewall check.");

      break;

    }

    result = true;

  } while (false);

  if (locked) FW_NODES_UNLOCK(fw);

  return result;
}

bool
kad_fw_firewalled(
                  KAD_FW* kfw
                 )
{
  bool result = false;

  do {

    if (!kfw) break;

    result = kfw->firewalled;

  } while (false);

  return result;
}

bool
kad_fw_firewalled_udp(
                      KAD_FW* kfw
                      )
{
  bool result = false;

  do {

    if (!kfw) break;

    result = kfw->udp_firewalled;

  } while (false);

  return result;
}

bool
kad_fw_set_status(
                  KAD_FW* kfw,
                  bool firewalled
                 )
{
  bool result = false;

  do {

    if (!kfw) break;

    kfw->firewalled = firewalled;

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_set_status_udp(
                      KAD_FW* kfw,
                      bool firewalled
                     )
{
  bool result = false;

  do {

    if (!kfw) break;

    kfw->udp_firewalled = firewalled;

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_need_more_udp_checks(
                            KAD_FW* kfw
                            )
{
  bool result = false;

  do {

    if (!kfw) break;

    result = ((kfw->udp_checks_finished_cnt + kfw->udp_checks_running_cnt) < KAD_UDPFWCHECK_CLIENTS_TO_ASK)?true:false;
/*
    LOG_DEBUG(
              "udp_checks_finished_cnt = %d, udp_checks_running_cnt = %d",
              kfw->udp_checks_finished_cnt,
              kfw->udp_checks_running_cnt
             );
*/
  } while (false);

  return result;
}

bool
kad_fw_udp_check_request(
                         void* hks
                        )
{
  bool result = false;
  KAD_SESSION* ks;
  KAD_FW* fw = NULL;
  KAD_NODE* kn = NULL;
  UDP_FW_CHECK_NODE* fw_check_node = NULL;
  bool node_copied = false;

  do {

    if (!hks) break;

    ks = (KAD_SESSION*)hks;

    fw = &ks->fw;

    // No port - no request.

    if (!kad_fw_extrn_port_valid(fw)) break;

    FW_NODES_LOCK(fw);

    if (!list_remove_first_entry(&fw->nodes_for_udp_check, (void**)&kn) || !kn){

      LOG_ERROR("Failed to get node from list.");

      break;

    }

    FW_NODES_UNLOCK(fw);

    fw_check_node = (UDP_FW_CHECK_NODE*)mem_alloc(sizeof(UDP_FW_CHECK_NODE));

    if (!fw_check_node){

      LOG_ERROR("Failed to allocate memory for fw check node.");

      break;

    }

    node_copy(kn, &fw_check_node->kn, NULL);

    node_copied = true;

    if (!ks->mule_session || !ks->mcbs.add_source_for_udp_fw_check){

      break;

    }

    list_add_entry(&fw->nodes_used_for_udp_check, (void*)fw_check_node);

    LOG_DEBUG("Adding source for udp firewall check.");

    ks->mcbs.add_source_for_udp_fw_check(ks->mule_session, &kn->id, kn->ip4_no, kn->tcp_port_no, kn->udp_port_no);

    fw->udp_checks_running_cnt++;

    LOG_DEBUG("udp_checks_running_cnt = %d", fw->udp_checks_running_cnt);

    result = true;

  } while (false);

  if (node_copied) node_destroy(kn);

  if (!result && fw_check_node) mem_free(fw_check_node);

  return result;
}

bool
kad_fw_udp_check_response(
                          KAD_FW* fw,
                          bool already_known,
                          uint32_t ip4_no,
                          uint16_t int_port,
                          uint16_t inc_port,
                          bool* answ_to_int_port_out,
                          bool* answ_to_ext_port_out
                         )
{
  bool result = false;
  uint16_t ext_port = 0;
  UDP_FW_CHECK_NODE* check_node = NULL;
  bool answer_received = false;

  do {

    if (!fw) break;

    if (answ_to_int_port_out) *answ_to_int_port_out = false;

    if (answ_to_ext_port_out) *answ_to_ext_port_out = false;

    kad_fw_get_extrn_port(fw, &ext_port);

    LOG_DEBUG("inc_port = %d, ext_port = %d, int_port = %d", inc_port, ext_port, int_port);

    if (!inc_port || (inc_port != ext_port && inc_port != int_port)){

      LOG_ERROR("Response to unknown port.");

      break;

    }

    fw->udp_checks_finished_cnt++;

    LOG_DEBUG("udp_checks_finished_cnt = %d", fw->udp_checks_finished_cnt);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(fw->nodes_used_for_udp_check, e, check_node);

      if (check_node->kn.ip4_no == ip4_no){

        if (inc_port == ext_port){

          check_node->ext_port_answer = true;

          if (answ_to_ext_port_out) *answ_to_ext_port_out = true;

        } else if (inc_port == int_port){

          check_node->int_port_answer = true;

          if (answ_to_int_port_out) *answ_to_int_port_out = true;

        }

        fw->udp_firewalled = false;

        answer_received = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!answer_received){

      fw->udp_firewalled = true;

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_check_response(
                      KAD_FW* fw
                     )
{
  bool result = false;

  do {

    if (!fw) break;

    LOG_DEBUG("firewalled = false");

    fw->firewalled = false;

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_dec_checks_running(
                          KAD_FW* fw
                         )
{
  bool result = false;

  do {

    if (!fw) break;

    if (fw->tcp_checks_running_cnt) fw->tcp_checks_running_cnt--;

    LOG_DEBUG("tcp_checks_running_cnt = %d", fw->tcp_checks_running_cnt);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_dec_checks_running_udp(
                              KAD_FW* fw
                             )
{
  bool result = false;

  do {

    if (!fw) break;

    if (fw->udp_checks_running_cnt) fw->udp_checks_running_cnt--;

    LOG_DEBUG("udp_checks_running_cnt = %d", fw->udp_checks_running_cnt);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_add_source_for_inbound_tcp_check(
                                        void* hks,
                                        KAD_FW* fw,
                                        UINT128* id,
                                        uint32_t ip4_no,
                                        uint16_t tcp_port,
                                        uint16_t udp_port
                                       )
{
  bool result = false;
  KAD_SESSION* ks = NULL;

  do {

    if (!hks || !fw) break;

    ks = (KAD_SESSION*)hks;

    if (!ks->mcbs.add_source_for_tcp_fw_check) break;

    ks->mcbs.add_source_for_tcp_fw_check(
                                         ks->mule_session,
                                         id,
                                         ip4_no,
                                         htons(tcp_port),
                                         htons(udp_port)
                                        );

    fw->tcp_checks_running_cnt++; 

    LOG_DEBUG("tcp_checks_running_cnt = %d", fw->tcp_checks_running_cnt);

    result = true;

  } while (false);

  return result;
}

bool
kad_fw_need_more_tcp_checks(
                            KAD_FW* kfw
                            )
{
  bool result = false;

  do {

    if (!kfw) break;

    LOG_DEBUG("tcp_checks_running_cnt = %d", kfw->tcp_checks_running_cnt);

    result = kfw->tcp_checks_running_cnt < KAD_FIREWALL_CHECKS_SIMUL;

  } while (false);

  return result;
}

