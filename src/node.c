#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <byteswap.h>
#include <ticks.h>
#include <node.h>
#include <mem.h>
#include <log.h>

uint8_t
node_set_udp_key_with_ip(
                         KAD_NODE* kn,
                         uint32_t udp_key,
                         uint32_t ip4_no
                        )
{
  uint8_t result = 0;

  do {

    kn->udp_key = udp_key;

    kn->udp_key_ip4_no = ip4_no;

    result = 1;

  } while (false);

  return result;
}

uint8_t
node_create(
            UINT128* id,
            uint32_t self_ip4_no,
            uint32_t ip4_no,
            uint16_t tcp_port_no,
            uint16_t udp_port_no,
            uint8_t version,
            uint32_t udp_key,
            bool ip_verified,
            UINT128* dist,
            KAD_NODE** kn_out
           )
{
  uint8_t result = 0;
  KAD_NODE* kn;
#ifdef CONFIG_VERBOSE
  struct in_addr ia = {0};
#endif
  uint32_t now;

  do {

    if (!id || !dist || !kn_out) break;

    LOG_DEBUG("+++node_create+++");

    LOG_DEBUG_UINT128("id:", id);

#ifdef CONFIG_VERBOSE
    ia.s_addr = ip4_no; 
#endif

    LOG_DEBUG("ip %s, tcp_port %.4d, udp_port %.4d, version %.2d", inet_ntoa(ia), ntohs(tcp_port_no), ntohs(udp_port_no), version);

    LOG_DEBUG_UINT128("distance", dist);

    kn = (KAD_NODE*)mem_alloc(sizeof(KAD_NODE));

    if (!kn) {

      LOG_ERROR("Failed to allocate memory for node.");

      break;

    }

    memcpy(&kn->id, id, sizeof(UINT128));

    uint128_copy(id, &kn->id);

    kn->ip4_no = ip4_no;

    kn->tcp_port_no = tcp_port_no;

    kn->udp_port_no = udp_port_no;

    uint128_copy(dist, &kn->dist);

    kn->status = NODE_STATUS_NEW;

    now = ticks_now_ms();

    kn->created = now;

    kn->next_check_time = now + SEC2MS(5);

    kn->packet_timeout = 0;

    kn->version = version;

    kn->check_kad2 = true;
    
    kn->ip_verified = ip_verified;

    kn->hello_received = false;

    node_set_udp_key_with_ip(kn, udp_key, self_ip4_no);

#ifdef CONFIG_VERBOSE

    strcpy(kn->ip4_str, inet_ntoa(ia));

#endif

    // Here should be node lock initializer

    *kn_out = kn;

    result = 1;

  } while (false);

  if (!result && kn) mem_free(kn);

  return result;

}

uint8_t
node_destroy(
             KAD_NODE* kn
            )
{
  uint8_t result = 0;

  do {

    // Here should be lock deinitialization.
    
    mem_free(kn);

    result  = 1;

  } while (false);

  return result;

}

uint32_t
node_get_udp_key_by_ip(
                       KAD_NODE* kn,
                       uint32_t ip4_no
                      )
{
  uint32_t result = 0;

  do {

    result = ip4_no == kn->udp_key_ip4_no ? kn->udp_key : 0;

  } while (false);

  return result;

}

bool
node_copy(
          KAD_NODE* kn_src,
          KAD_NODE* kn_dst,
          KAD_NODE** kn_dst_out
         )
{
  bool result = false;

  do {

    if (!kn_src) break;

    if (!kn_dst){

      kn_dst = (KAD_NODE*)mem_alloc(sizeof(KAD_NODE));

      if (!kn_dst){

        LOG_ERROR("Failed to allocate memory for node.");

        break;

      }

    }

    memcpy(kn_dst, kn_src, sizeof(KAD_NODE));

    kn_dst->created = ticks_now_ms();

    if (kn_dst_out) *kn_dst_out = kn_dst;

    result = true;

  } while (false);

  return result;
}

char*
node_status_str(
                KAD_NODE* kn
               )
{
  char* result = "UNDEFINED";

  do {

    switch(kn->status){

      case NODE_STATUS_NEW:

        result = "NODE_STATUS_NEW";

      break;

      case NODE_STATUS_HELLO_REQ_SENT:

        result = "NODE_STATUS_HELLO_REQ_SENT";

      break;

      case NODE_STATUS_HELLO_RES_RECEIVED:

        result = "NODE_STATUS_HELLO_RES_RECEIVED";

      break;

      case NODE_STATUS_PING_SENT:

        result = "NODE_STATUS_PING_SENT";

      break;

      case NODE_STATUS_PONG_RECEIVED:

        result = "NODE_STATUS_PONG_RECEIVED";

      break;

    }

  } while (false);

  return result;
}
