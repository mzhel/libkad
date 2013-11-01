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

uint32_t
kadses_get_pub_ip(
                  KAD_SESSION* ks
                 )
{
  uint32_t result = 0;

  result = ks->pub_ip4_no?ks->pub_ip4_no:ks->loc_ip4_no;

  return result;
}

bool
kadses_create_queue_udp_pkt(
                            KAD_SESSION* ks,
                            UINT128* self_kad_id,
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
                            self_kad_id,
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
