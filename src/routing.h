#ifndef _ROUTING_H_
#define _ROUTING_H_

#define KBASE 4
#define KK 5
#define LOG_BASE_EXPONENT 5

struct _routing_zone;

typedef struct _routing_zone {
  uint32_t level;
  UINT128 idx;
  struct _routing_zone* super_zone;
  struct _routing_zone* sub_zones[2];
  KBUCKET* kb;
  uint32_t next_bucket_timer;
  uint32_t next_lookup_timer;
} ROUTING_ZONE;

bool
routing_create_zone(
                    ROUTING_ZONE* super_zone,
                    uint32_t level,
                    UINT128* zone_idx,
                    ROUTING_ZONE** rz_out
                   );

bool
routing_destroy_zone(
                     ROUTING_ZONE* rz
                    );

bool
routing_zone_can_be_split(
                          ROUTING_ZONE* rz
                         );

bool
routing_gen_sub_zone(
                     ROUTING_ZONE* rz,
                     uint8_t tree_side,
                     ROUTING_ZONE** sz_out
                    );

bool
routing_split_zone(
                   ROUTING_ZONE* rz
                  );

bool
routing_add_node(
                 LIST** active_zones_ptr,
                 // [LOCK] Here should be zone lock.
                 ROUTING_ZONE* rz,
                 KAD_NODE* kn,
                 uint32_t self_pub_ip4_no,
                 bool update_existing,
                 bool* existing_updated_out,
                 bool top_level_call
                );

bool
routing_get_node_by_id(
                       ROUTING_ZONE* rz,
                       // [LOCK] here should be zone lock object
                       UINT128* id_self,
                       UINT128* id_to_find,
                       KAD_NODE** kn_out,
                       bool top_level_call
                      );

bool
routing_get_node_by_ip_port(
                            ROUTING_ZONE* rz,
                            // [LOCK] active zones lock
                            uint32_t ip4_no,
                            uint16_t port_no,
                            uint8_t port_type,
                            KAD_NODE** kn_out,
                            bool top_level_call
                           );

bool
routing_get_nodes_count(
                        ROUTING_ZONE* rz,
                        // [LOCK] 
                        uint32_t* kn_cnt_out,
                        bool top_level_call
                       );

bool
routing_get_closest_to(
                       ROUTING_ZONE* rz,
                       // [LOCK]
                       uint32_t max_type,
                       uint32_t max_required,
                       UINT128* target_id,
                       UINT128* dist,
                       bool protect_picked_nodes,
                       LIST** lst_out,
                       bool top_level_call
                      );

bool
routing_get_random_node(
                        ROUTING_ZONE* rz,
                        // [LOCK]
                        uint32_t max_type,
                        uint32_t min_kad_ver,
                        KAD_NODE** kn_out,
                        bool top_level_call
                       );

bool
routing_get_entries_from_random_bucket(
                                       ROUTING_ZONE* rz,
                                       // [LOCK]
                                       LIST** kn_lst_out,
                                       bool top_level_call
                                      );

bool
routing_get_top_depth_entries(
                              ROUTING_ZONE* rz,
                              // [LOCK]
                              int32_t depth,
                              LIST** kn_lst_out,
                              bool top_level_result
                             );

bool
routing_get_bootstrap_contacts(
                              ROUTING_ZONE* rz,
                              // [LOCK]
                              uint32_t max_required,
                              LIST** kn_lst_out,
                              bool top_level_call
                              );

bool
routing_get_nodes_list(
                       ROUTING_ZONE* rz,
                       LIST** kn_lst_out
                      );

#endif // _ROUTING_H_

