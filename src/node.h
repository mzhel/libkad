#ifndef _NODE_H_
#define _NODE_H_

#define NODE_STATUS_WAIT_MASK          0x80000000

#define NODE_STATUS_NEW                1
#define NODE_STATUS_HELLO_REQ_SENT     0x80000002
#define NODE_STATUS_HELLO_RES_RECEIVED 3
#define NODE_STATUS_PING_SENT          0x80000004
#define NODE_STATUS_PONG_RECEIVED      5
#define NODE_STATUS_TO_REMOVE          6

#define MAX_IP_STR_LENGTH 16

typedef struct _kad_node {
  UINT128 id;
  uint32_t ip4_no;
  uint16_t tcp_port_no;
  uint16_t udp_port_no;
  UINT128 dist;
  uint32_t created;
  uint32_t status;
  uint32_t next_check_time;
  uint32_t packet_timeout;
  uint32_t in_use;
  uint8_t version;
  bool check_kad2;
  bool ip_verified;
  bool hello_received;
  uint32_t udp_key;
  uint32_t udp_key_ip4_no;
#ifdef CONFIG_VERBOSE
  char ip4_str[MAX_IP_STR_LENGTH];
#endif
  // here should be node lock
} KAD_NODE;

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
           );

uint8_t
node_destroy(
             KAD_NODE* kn
            );

bool
node_copy(
          KAD_NODE* kn_src,
          KAD_NODE* kn_dst,
          KAD_NODE** kn_dst_out
         );

uint8_t
node_set_udp_key_with_ip(
                         KAD_NODE* kn,
                         uint32_t udp_key,
                         uint32_t ip4_no
                        );

uint32_t
node_get_udp_key_by_ip(
                       KAD_NODE* kn,
                       uint32_t ip4_no
                      );

char*
node_status_str(
                KAD_NODE* kn
               );

#endif // _NODE_H_
