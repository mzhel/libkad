#ifndef _NODE_H_
#define _NODE_H_

typedef struct _kad_node {
  UINT128 id;
  uint32_t ip4_no;
  uint16_t tcp_port_no;
  uint16_t udp_port_no;
  UINT128 dist;
  uint8_t type;
  uint32_t created;
  uint32_t expires;
  uint32_t last_type_set;
  uint32_t in_use;
  uint8_t version;
  bool check_kad2;
  bool ip_verified;
  bool hello_received;
  uint32_t udp_key;
  uint32_t udp_key_ip4_no;
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
node_update_expired(
                    KAD_NODE* kn
                   );

uint32_t
node_get_udp_key_by_ip(
                       KAD_NODE* kn,
                       uint32_t ip4_no
                      );

uint8_t
node_set_alive(
               KAD_NODE* kn
              );

#endif // _NODE_H_
