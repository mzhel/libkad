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

    LIST_EACH_ENTRY_WITH_DATA_END(e);

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

  } while (false);

  return result;
}

