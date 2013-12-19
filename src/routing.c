#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <byteswap.h>
#include <list.h>
#include <ticks.h>
#include <node.h>
#include <kbucket.h>
#include <routing.h>
#include <mem.h>
#include <log.h>

bool
routing_create_zone(
                    ROUTING_ZONE* super_zone,
                    uint32_t level,
                    UINT128* zone_idx,
                    ROUTING_ZONE** rz_out
                   )
{
  bool result = false;
  ROUTING_ZONE* rz = NULL;

  do {

    if (!zone_idx || !rz_out) break;

    rz = (ROUTING_ZONE*)mem_alloc(sizeof(ROUTING_ZONE));

    if (!rz) {

      LOG_ERROR("Failed to allocate memory for routing zone.");

      break;

    }

    if (!kbucket_create(&rz->kb)){

      LOG_ERROR("Failed to allocate memory for zone bucket.");

      break;

    }

    rz->super_zone = super_zone;

    rz->level = level;

    uint128_copy(zone_idx, &rz->idx);

    rz->next_lookup_timer = ticks_now_ms() + SEC2MS(10);

    *rz_out = rz;

    result = true;

  } while (false);

  if (!result && rz) routing_destroy_zone(rz);

  return result;
}

bool
routing_destroy_zone(
                     ROUTING_ZONE* rz
                    )
{
  bool result = false;

  do {

    if (!rz) break;

    LOG_DEBUG("+++routing_destroy_zone");

    LOG_DEBUG("level: %.2d", rz->level);

    LOG_DEBUG_UINT128("idx:",((UINT128*)&rz->idx));

    if (rz->sub_zones[0]) routing_destroy_zone(rz->sub_zones[0]);

    if (rz->sub_zones[1]) routing_destroy_zone(rz->sub_zones[1]);

    if (rz->kb) kbucket_destroy(rz->kb, false);

    mem_free(rz);

    result = true;

  } while (false);

  return result;
}

bool
routing_zone_can_be_split(
                          ROUTING_ZONE* rz
                         )
{
  bool result = false;

  do {

    if (!rz) break;

    LOG_DEBUG("+++routing_zone_can_be_split+++");

    LOG_DEBUG("level: %.2d", rz->level);

    LOG_DEBUG_UINT128("idx: ", ((UINT128*)&rz->idx));

    if (rz->level >= 127) break;

    if ((0xff == uint128_compare_dword(&rz->idx, KK) || rz->level < KBASE) && rz->kb->nodes_count == K) result = true;

  } while (false);

  LOG_DEBUG("can_be_split %d", result);

  return result;
}

bool
routing_gen_sub_zone(
                     ROUTING_ZONE* rz,
                     uint8_t tree_side,
                     ROUTING_ZONE** sz_out
                    )
{
  bool result = false;
  UINT128 new_idx;

  do {

    if (!rz || !sz_out) break;

    LOG_DEBUG("+++routing_gen_sub_zone+++");

    uint128_zero_init(&new_idx);

    uint128_copy(&rz->idx, &new_idx);

    uint128_shift_left(&new_idx, 1, NULL);

    uint128_add_dword(&new_idx, (uint32_t)tree_side, NULL);

    LOG_DEBUG_UINT128("zone_idx:", ((UINT128*)&rz->idx));

    LOG_DEBUG("zone_level %d", rz->level);

    LOG_DEBUG_UINT128("sub_zone_idx:", ((UINT128*)&new_idx));

    LOG_DEBUG("sub_zone_level %d", rz->level + 1);

    result = routing_create_zone(rz, rz->level + 1, &new_idx, sz_out);

  } while (false);

  return result;
}

bool
routing_split_zone(
                   ROUTING_ZONE* rz
                  )
{
  bool result = false;
  KBUCKET* kb = NULL;
  uint32_t idx = 0;
  bool error = false;

  do {

    if (!rz) break;

    LOG_DEBUG("+++routing_split_zone+++");

    if (!routing_gen_sub_zone(rz, 0, &rz->sub_zones[0])){

      LOG_ERROR("routing_gen_sub_zone(0) failed");

      break;

    }

    if (!routing_gen_sub_zone(rz, 1, &rz->sub_zones[1])){

      LOG_ERROR("routing_gen_sub_zone(1)");

      break;

    }

    LOG_DEBUG("level %.2d", rz->level);

    kb = rz->kb;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      idx = uint128_get_bit_value_reverse(&kb->nodes[i]->dist, rz->level);

      if (!kbucket_add_node(rz->sub_zones[idx]->kb, kb->nodes[i])) {

        LOG_ERROR("Failed to add node to sub zone kbucket.");

        error = true;

        break;

      }

    }

    if (error) break;

    kbucket_destroy(rz->kb, true); // Destroy splited bucket but keep nodes.

    rz->kb = NULL;

    result = true;

  } while (false);

  return result;
}

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
                )
{
  bool result = false;
  uint32_t idx = 0;
  KAD_NODE* found_kn = NULL;
  uint32_t check_udp_key = 0;

  do {

    if (!active_zones_ptr || !rz || !kn) break;

    // [LOCK] here should be active zones lock if call is top level.
    
    if (existing_updated_out) *existing_updated_out = false;

    // If zone bucket is empty then zone have sub zones.
    // Add node to one of zone sub zones.

    if (!rz->kb){

      idx = uint128_get_bit_value_reverse(&kn->dist, rz->level);

      result = routing_add_node(
                                active_zones_ptr, 
                                //[LOCK] here should be zone lock 
                                rz->sub_zones[idx], 
                                kn, 
                                self_pub_ip4_no, 
                                update_existing, 
                                existing_updated_out, 
                                false
                                );

      break;

    }

    if (kbucket_node_by_id(rz->kb, &kn->id, &found_kn)){

      // Node already added to zone bucket.
      
      if (update_existing){

        check_udp_key = node_get_udp_key_by_ip(found_kn, self_pub_ip4_no);

        if (check_udp_key && check_udp_key != node_get_udp_key_by_ip(kn, self_pub_ip4_no)) {

          // Nodes keys do not match.
          
          LOG_ERROR("Udp keys do not match, old = %.8x, new = %.8x", check_udp_key, node_get_udp_key_by_ip(kn, self_pub_ip4_no));       

          break;

        }

        if (kn->version < found_kn->version){

          // New node version in lesser than old.

          break;

        }

        // Update node information.

        // [TODO] Legacy kad2 contacts.
        // [TODO] Checks when changing ip of exisitng node.
        
        found_kn->ip4_no = kn->ip4_no;

        found_kn->udp_port_no = kn->udp_port_no;

        found_kn->tcp_port_no = kn->tcp_port_no;

        found_kn->version = kn->version;

        if (kn->hello_received) found_kn->hello_received = true;

        found_kn->status = kn->status;

        found_kn->next_check_time = kn->next_check_time;

        node_set_udp_key_with_ip(found_kn, kn->udp_key, self_pub_ip4_no);

        if (!found_kn->ip_verified) found_kn->ip_verified = kn->ip_verified;

        if (existing_updated_out) *existing_updated_out = true;

        // All information copied to existing node
        // so we destroy the original.

        node_destroy(kn);

        result = true;

      } else {

        // Node found but we do not update it.

        result = true;

      }

    } else if (rz->kb->nodes_count < K) {

      // Have space in current zone bucket.
      
      result = kbucket_add_node(rz->kb, kn);

    } else if (routing_zone_can_be_split(rz)){

      // Zone bucket is full, zone split required.
      
      if (!routing_split_zone(rz)){

        LOG_ERROR("Failed to split zone.");

        break;

      }

      list_add_entry(active_zones_ptr, rz->sub_zones[0]);

      list_add_entry(active_zones_ptr, rz->sub_zones[1]);

      idx = uint128_get_bit_value_reverse(&kn->dist, rz->level);

      result = routing_add_node(
                                active_zones_ptr,
                                // [LOCK] lock
                                rz->sub_zones[idx],
                                kn,
                                self_pub_ip4_no,
                                update_existing,
                                existing_updated_out,
                                false
                               );

    }


  } while (false);

  // [LOCK] if (top_level_call) unlock active zones

  return result;
}

bool
routing_get_node_by_id(
                       ROUTING_ZONE* rz,
                       // [LOCK] here should be zone lock object
                       UINT128* id_self,
                       UINT128* id_to_find,
                       KAD_NODE** kn_out,
                       bool top_level_call
                      )
{
  bool result = false;
  UINT128 dist;
  uint32_t idx;

  do {

    if (!rz || !id_self || !id_to_find || !kn_out) break;

    // [LOCK] here should be zone lock
    
    if (rz->kb){

      result = kbucket_node_by_id(rz->kb, id_to_find, kn_out);

    } else {

      uint128_xor(id_self, id_to_find, &dist);

      idx = uint128_get_bit_value_reverse(&dist, rz->level);

      result = routing_get_node_by_id(rz->sub_zones[idx], id_self, id_to_find, kn_out, false);

    }


  } while (false);

  // [LOCK] here should be zones unlock if call is top level

  return result;
}

bool
routing_get_node_by_ip_port(
                            ROUTING_ZONE* rz,
                            // [LOCK] active zones lock
                            uint32_t ip4_no,
                            uint16_t port_no,
                            uint8_t port_type,
                            KAD_NODE** kn_out,
                            bool top_level_call
                           )
{
  bool result = false;

  do {
    
    // [LOCK] active zones lock
    
    if (rz->kb){

      result = kbucket_node_by_ip_port(rz->kb, ip4_no, port_no, port_type, kn_out);

    } else {

      result = routing_get_node_by_ip_port(rz->sub_zones[0], ip4_no, port_no, port_type, kn_out, false);

      if (!result) result = routing_get_node_by_ip_port(rz->sub_zones[1], ip4_no, port_no, port_type, kn_out, false);

    }

  } while (false);

  // [LOCK] active zones unlock

  return result;
}

bool
routing_get_nodes_count(
                        ROUTING_ZONE* rz,
                        // [LOCK] 
                        uint32_t* kn_cnt_out,
                        bool top_level_call
                       )
{
  bool result = false;

  do {

    if (!rz || !kn_cnt_out) break;

    // [LOCK]
    
    if (top_level_call) *kn_cnt_out = 0;


    if (rz->kb){

      *kn_cnt_out += rz->kb->nodes_count;

    } else {

      routing_get_nodes_count(rz->sub_zones[0], kn_cnt_out, false);

      routing_get_nodes_count(rz->sub_zones[1], kn_cnt_out, false);

    }

    result = true;

  } while (false);

  // [LOCK] unlock zones if top level call
  
  return result;
}

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
                      )
{
  bool result = false;
  uint32_t idx = 0;
  uint32_t count = 0;

  do {

    if (!rz) break;

    if (top_level_call){

      // [LOCK] lock active zones
      
      *lst_out = NULL;

    }

    if (rz->kb){

      result = kbucket_get_closest_to(rz->kb, max_type, max_required, target_id, protect_picked_nodes, lst_out);

    } else {

      idx = uint128_get_bit_value_reverse(dist, rz->level);

      result = routing_get_closest_to(
                                      rz->sub_zones[idx], 
                                      max_type, max_required, 
                                      target_id, 
                                      dist, 
                                      protect_picked_nodes, 
                                      lst_out, 
                                      false
                                      );

      list_entries_count(*lst_out, &count);

      if (count < max_required){

        result = routing_get_closest_to(
                                        rz->sub_zones[1 - idx], 
                                        max_type, max_required, 
                                        target_id, 
                                        dist, 
                                        protect_picked_nodes, 
                                        lst_out, 
                                        false
                                        );

      }

    }

    result = true;

  } while (false);

  // [LOCK] unlock active nodes list.

  return result;
}

bool
routing_get_random_node(
                        ROUTING_ZONE* rz,
                        // [LOCK]
                        uint32_t max_type,
                        uint32_t min_kad_ver,
                        KAD_NODE** kn_out,
                        bool top_level_call
                       )
{
  bool result = false;
  uint32_t rnd_zone_idx = 0;

  do {

    if (!rz || !kn_out) break;

    if (top_level_call){

      // [LOCK]
      
      *kn_out = NULL;

    }

    if (rz->kb){

      result = kbucket_get_random_node(rz->kb, max_type, min_kad_ver, kn_out);

    } else {

      rnd_zone_idx = random_uint8() & 1;

      result = routing_get_random_node(rz->sub_zones[rnd_zone_idx], max_type, min_kad_ver, kn_out, false); 

      if (result) break;

      result = routing_get_random_node(rz->sub_zones[1 - rnd_zone_idx], max_type, min_kad_ver, kn_out, false); 

    }

  } while (false);

  // [LOCK] unlock active zones list

  return result;
}

bool
routing_get_entries_from_random_bucket(
                                       ROUTING_ZONE* rz,
                                       // [LOCK]
                                       LIST** kn_lst_out,
                                       bool top_level_call
                                      )
{
  bool result = false;

  do {

    if (!rz || !kn_lst_out) break;

    if (rz->kb){

      kbucket_get_nodes(rz->kb, kn_lst_out);

    } else {

      routing_get_entries_from_random_bucket(rz->sub_zones[random_uint8() & 1], kn_lst_out, false);

    }

    result = true;

  } while (false);

  // [LOCK] unlock active zones list.

  return result;
}

bool
routing_get_top_depth_entries(
                              ROUTING_ZONE* rz,
                              // [LOCK]
                              int32_t depth,
                              LIST** kn_lst_out,
                              bool top_level_result
                             )
{
  bool result = false;

  do {

    // [LOCK] here should be lock

    if (!rz || !kn_lst_out) break;

    if (rz->kb){

      result = kbucket_get_nodes(rz->kb, kn_lst_out);

    } else if (depth <= 0) {

      result = routing_get_entries_from_random_bucket(rz, kn_lst_out, false);

    } else {

      result = routing_get_top_depth_entries(rz->sub_zones[0], depth - 1, kn_lst_out, false);

      result = routing_get_top_depth_entries(rz->sub_zones[1], depth - 1, kn_lst_out, false);

    }

  } while (false);

  // [LOCK] unlock active zones.

  return result;
}

bool
routing_get_bootstrap_contacts(
                              ROUTING_ZONE* rz,
                              // [LOCK]
                              uint32_t max_required,
                              LIST** kn_lst_out,
                              bool top_level_call
                              )
{
  bool result = false;
  LIST* kn_lst = NULL;
  LIST* entry = NULL;
  uint32_t ent_cnt = 0;
  void* data = NULL;
  uint32_t copy_cnt = 0;

  do {

    // [LOCK] lock active zones.

    if (!rz || !kn_lst_out) break;

    if (!routing_get_top_depth_entries(rz, LOG_BASE_EXPONENT, &kn_lst, false)){

      LOG_ERROR("Failed to get top entries.");

      break;

    }
    
    list_entries_count(kn_lst, &ent_cnt);

    entry = kn_lst;

    if (ent_cnt){

      copy_cnt = ent_cnt > max_required? max_required : ent_cnt;

      while (copy_cnt--) {

        if (!entry) break;

        list_get_entry_data(entry, &data);

        list_add_entry(kn_lst_out, data);

        list_next_entry(entry, &entry);

      }

    }

    result = true;

  } while (false);

  if (kn_lst) list_destroy(kn_lst, true);

  // [LOCK] unlock active zones.

  return result;
}
