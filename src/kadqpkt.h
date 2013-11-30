#ifndef _KADQPKT_H_
#define _KADQPKT_H_

typedef struct _kad_queued_packet {
  uint32_t ip4_no;
  uint16_t port_no;
  uint8_t* pkt;
  uint32_t pkt_len;
  uint32_t ts;
  bool  encrypt;
  uint32_t recv_verify_key;
  UINT128 kad_id;
} KAD_QUEUED_PACKET;

bool
kadqpkt_alloc(
              uint32_t ip4_no, 
              uint16_t port_no,
              void* pkt,
              uint32_t pkt_len,
              KAD_QUEUED_PACKET** qp_out 
             );

bool
kadqpkt_destroy(
                KAD_QUEUED_PACKET* qp
               );

bool
kadqpkt_create_udp(
                   uint32_t ip4_no,
                   uint16_t port_no,
                   UINT128* target_id,
                   uint32_t verify_key,
                   void* pkt,
                   uint32_t pkt_len,
                   KAD_QUEUED_PACKET** qp_out
                   );

#endif // _KADQPKT_H_
