#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <list.h>
#include <queue.h>
#include <uint128.h>
#include <mem.h>
#include <kadqpkt.h>
#include <ticks.h>
#include <log.h>

bool
kadqpkt_alloc(
              uint32_t ip4_no, 
              uint16_t port_no,
              void* pkt,
              uint32_t pkt_len,
              KAD_QUEUED_PACKET** qp_out 
             )
{
  bool result = false;
  KAD_QUEUED_PACKET* qp = NULL;

  do {

    if (!pkt || !pkt_len || !qp_out) break;

    qp = (KAD_QUEUED_PACKET*)mem_alloc(sizeof(KAD_QUEUED_PACKET));

    if (!qp){

      LOG_ERROR("Failed to allocate memory for queued packet.");

      break;

    }

    qp->ip4_no = ip4_no;

    qp->port_no = port_no;

    qp->pkt = pkt;

    qp->pkt_len = pkt_len;

    qp->ts = ticks_now_ms();

    *qp_out = qp;

    result = true;

  } while (false);

  return result;
}

bool
kadqpkt_destroy(
                KAD_QUEUED_PACKET* qp,
                bool free_data
               )
{
  bool result = false;

  do {

    if (!qp) break;

    if (free_data) mem_free(qp->pkt);

    mem_free(qp);

    result = true;

  } while (false);

  return result;
}

bool
kadqpkt_create_udp(
                   uint32_t ip4_no,
                   uint16_t port_no,
                   UINT128* target_id,
                   uint32_t verify_key,
                   void* pkt,
                   uint32_t pkt_len,
                   KAD_QUEUED_PACKET** qp_out
                   )
{
  bool result = false;
  KAD_QUEUED_PACKET* qp = NULL;

  do {

    if (!pkt || !pkt_len) break;

    if (!kadqpkt_alloc(ip4_no, port_no, pkt, pkt_len, &qp)){

      LOG_ERROR("Failed to allocate queued packet.");

      break;

    }

    qp->encrypt = (verify_key != 0 || target_id != NULL);

    if (qp->encrypt){

      qp->recv_verify_key = verify_key;

      uint128_emit(target_id, &qp->kad_id, sizeof(UINT128));

    }

    *qp_out = qp;

    result = true;

  } while (false);

  if (!result && qp) kadqpkt_destroy(qp, false);

  return result;
}
