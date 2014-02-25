#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <log.h>
#include <node.h>
#include <kbucket.h>
#include <routing.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadhlp.h>

uint32_t
kadses_get_pub_ip(
                  KAD_SESSION* ks
                  )
{
  uint32_t result = 0;

  result = ks->pub_ip4_no?ks->pub_ip4_no:ks->loc_ip4_no;

  return result;
}

uint16_t
kadses_get_udp_port(
                    KAD_SESSION* ks
                   )
{
  uint16_t result = 0;

  do {

    result = ks->udp_port;

  } while (false);

  return result;
}

bool
kadses_create_queue_udp_pkt(
                            KAD_SESSION* ks,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            UINT128* target_id,
                            uint32_t verify_key,
                            void* pkt,
                            uint32_t pkt_len
                            )
{
  bool result = false;
  KAD_QUEUED_PACKET* qp = NULL;

  do {

    if (!kadqpkt_create_udp(
                            ip4_no,
                            port_no,
                            target_id,
                            verify_key,
                            pkt,
                            pkt_len,
                            &qp
                            )
    ){

      LOG_ERROR("Failed to create udp packet.");

      break;

    }

    QUEUE_OUT_UDP(ks, qp);

    result = true;

  } while (false);

  return result;
}

bool
kadses_set_pub_ip(
                  KAD_SESSION* ks,
                  uint32_t ip4_no
                  )
{
  bool result = false;

  do {

    if (!ks) break;

    ks->pub_ip4_no = ip4_no;

    result = true;

  } while (false);

  return result;
}

bool
kadses_get_status(
                  void* ks,
                  KAD_SESSION_STATUS* kss
                 )
{
  bool result = false;
  KAD_SESSION* ks_ = (KAD_SESSION*)ks;

  do {

    if (!ks || !kss) break;

    kss->version = KADEMLIA_VERSION;

    kss->udp_port = ks_->udp_port;

    kad_fw_get_extrn_port(&ks_->fw, &kss->ext_udp_port);

    kss->fw = kad_fw_firewalled(&ks_->fw);

    kss->fw_udp = kad_fw_firewalled_udp(&ks_->fw);

    kss->pub_ip4_no = kadses_get_pub_ip(ks_);

    result = true;

  } while (false);

  return result;
}

bool
kadses_calc_verify_key(
                       void* ks,
                       uint32_t ip4_no,
                       uint32_t* key_out
                      )
{
  bool result = false;

  do {

    result = kadhlp_calc_udp_verify_key((KAD_SESSION*)ks, ((KAD_SESSION*)ks)->udp_key, ip4_no, key_out);

  } while (false);

  return result;
}

bool
kadses_bootstrap_from_node(
                           void* ks,
                           uint32_t ip4_no,
                           uint16_t port_no
                           )
{
  bool result = false;

  do {

    if (!ks) break;

    if (!kadhlp_send_bootstrap_pkt((KAD_SESSION*)ks, ip4_no, port_no)){

      LOG_ERROR("Failed to send bootstrap packet to node");

    }

    result = true;

  } while (false);

  return result;
}
bool
kadses_send_fw_check_udp(
                         void* ks,
                         uint16_t check_port,
                         uint32_t key,
                         uint32_t ip4_no
                        )
{
  bool result = false;

  do {

    result = kadhlp_send_fw_check_udp((KAD_SESSION*)ks, check_port, key, ip4_no);

  } while (false);

  return result;
}

bool
kadses_fw_check_response(
                         void* ks
                        )
{
  bool result = false;

  do {

  result = kad_fw_check_response(&((KAD_SESSION*)ks)->fw);

  } while (false);

  return result;
}

bool
kadses_fw_dec_checks_running(
                             void* ks
                            )
{
  bool result = false;

  do {

    result = kad_fw_dec_checks_running(&((KAD_SESSION*)ks)->fw);

  } while (false);

  return result;
}

bool
kadses_fw_dec_checks_running_udp(
                                 void* ks
                                )
{
  bool result = false;

  do {

    result = kad_fw_dec_checks_running_udp(&((KAD_SESSION*)ks)->fw);

  } while (false);

  return result;
}

bool
kadses_set_mule_callbacks(
                          KAD_SESSION* ks,
                          MULE_SESSION* ms,
                          MULE_CALLBACKS* mcbs
                         )
{
  bool result = false;

  do {

    if (!ks || !ms || !mcbs) break;

    ks->mule_session = ms;

    memcpy(&ks->mcbs, mcbs, sizeof(MULE_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
kadses_set_zlib_callbacks(
                          KAD_SESSION* ks,
                          ZLIB_CALLBACKS* zcbs
                         )
{
  bool result = false;

  do {

    if (!ks || !zcbs) break;

    memcpy(&ks->zcbs, zcbs, sizeof(ZLIB_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
kadses_set_cipher_callbacks(
                            KAD_SESSION* ks,
                            CIPHER_CALLBACKS* ccbs
                           )
{
  bool result = false;

  do {

    if (!ks || !ccbs) break;

    memcpy(&ks->ccbs, ccbs, sizeof(CIPHER_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
kadses_save_nodes_to_file(
                          KAD_SESSION* ks,
                          char* file_path
                         )
{
  bool result = false;
  LIST* kn_lst = NULL;

  do {

    if (!ks || !file_path) break;

    if (!routing_get_nodes_list(ks->root_zone, &kn_lst)){

      LOG_ERROR("Failed to get nodes list.");

      break;

    }

    if (!kadhlp_create_nodes_dat(kn_lst, file_path)){

      LOG_ERROR("Failed to create nodes file - %s.", file_path);

      break;

    }

    result = true;

  } while (false);

  if (kn_lst) list_destroy(kn_lst, false);

  return result;
}
