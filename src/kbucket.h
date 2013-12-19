#ifndef _KBUCKET_H_
#define _KBUCKET_H_

#define K 10

#define KAD_NODE_TCP_PORT 1
#define KAD_NODE_UDP_PORT 2

#define KBUCKET_LOCK(kb)
#define KBUCKET_UNLOCK(kb)

typedef struct _kbucket {
  KAD_NODE* nodes[K];
  uint32_t nodes_count;
  // Here should be bucket lock.
} KBUCKET;

bool
kbucket_create(
               KBUCKET** kb_ptr
              );

bool
kbucket_destroy(
                KBUCKET* kb,
                bool keep_nodes
               );

bool
kbucket_add_node(
                 KBUCKET* kb,
                 KAD_NODE* kn
                );

bool
kbucket_node_by_id(
                   KBUCKET* kb,
                   UINT128* id,
                   KAD_NODE** kn_out
                  );

bool
kbucket_node_by_ip_port(
                        KBUCKET* kb,
                        uint32_t ip4_no,
                        uint16_t port_no,
                        uint8_t port_type,
                        KAD_NODE** kn_out
                       );

bool
kbucket_remove_node_by_idx(
                           KBUCKET* kb,
                           uint32_t idx,
                           KAD_NODE** rmvd_kn_out
                          );

bool
kbucket_remove_node_by_node(
                            KBUCKET* kb,
                            KAD_NODE* kn,
                            KAD_NODE** rmvd_kn_out
                           );

bool
kbucket_get_oldest_node(
                        KBUCKET* kb,
                        KAD_NODE** kn_out
                       );

bool
kbucket_push_node_up(
                     KBUCKET* kb,
                     KAD_NODE* kn
                    );

bool
kbucket_get_closest_to(
                       KBUCKET* kb,
                       uint32_t max_type,
                       uint32_t max_required,
                       UINT128* trgt_id,
                       bool protect_picked_nodes,
                       LIST** lst_inout
                      );

bool
kbucket_get_random_node(
                        KBUCKET* kb,
                        uint32_t max_type,
                        uint32_t min_kad_ver,
                        KAD_NODE** kn_out
                       );

bool
kbucket_get_nodes(
                  KBUCKET* kb,
                  LIST** lst_out
                 );

#endif // _KBUCKET_H_

