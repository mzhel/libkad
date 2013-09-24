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
  struct in_addr ia = {0};
  uint32_t now;

  do {

    if (!id || !dist || !kn_out) break;

    LOG_DEBUG("+++node_create+++");

    LOG_DEBUG_UINT128("id:", id);

    ia.s_addr = ip4_no; 

    LOG_DEBUG("ip %s, tcp_port %.4d, udp_port %.4d, version %.2d", inet_ntoa(ia), ntohs(tcp_port_no), ntohs(udp_port_no), version);

    LOG_DEBUG_UINT128("distance", dist);

    kn = (KAD_NODE*) mem_alloc(sizeof(KAD_NODE));

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

    kn->type = 3;

    now = ticks_now_ms();

    kn->last_type_set = kn->created = now;

    kn->expires = kn->in_use = 0;

    kn->version = version;

    kn->check_kad2 = true;
    
    kn->ip_verified = ip_verified;

    kn->hello_received = false;

    node_set_udp_key_with_ip(kn, udp_key, self_ip4_no);

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
  uint8_t result = 0;;

  do {

    // Here should be lock deinitialization.
    
    mem_free(kn);

    result  = 1;

  } while (false);

  return result;

}

bool
node_update_expired(
                    KAD_NODE* kn
                   )
{
  bool result = false;
  uint32_t now;

  do {

    if (!kn) break;

    now = ticks_now_ms();

    if (now - kn->last_type_set < SEC2MS(10) || kn->type == 4){
      
      result = true;

      break;

    }

    kn->last_type_set = now;

    kn->expires = now + MIN2MS(2);

    kn->type++;


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

uint8_t
node_set_alive(
               KAD_NODE* kn
              )
{
  uint8_t result = 0;
  uint32_t now = ticks_now_ms();
  uint32_t hrs = 0;

  do {

    if (!kn) break;


    // Check time passed since  node creation.

    hrs = (now - kn->created) / HR2MS(1);

    switch (hrs){

      case 0:

        kn->type = 2;

        // Expiration time 1 hour.

        kn->expires = now + HR2MS(1);

        break;

      case 1:

        kn->type = 1;

        // Expiration time 1,5 hours. 

        kn->expires = now + MIN2MS(90);

        break;

      default:

        kn->type = 0;

        // Expiration time - 2 hours.

        kn->expires = now + HR2MS(2);

    }

  } while (false);

  return result;
}

