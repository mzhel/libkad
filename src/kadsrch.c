#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadsrch.h>
#include <kadqpkt.h>
#include <kadpkt.h>
#include <kadhlp.h>
#include <str.h>
#include <ticks.h>
#include <tag.h>
#include <mem.h>
#include <log.h>

static uint32_t search_id = 0;

bool
kad_search_create(
                  uint32_t type,
                  KAD_SEARCH** kse_out
                 )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  uint32_t now;

  do {

    if (!kse_out) break;

    now = ticks_now_ms();

    kse = (KAD_SEARCH*)mem_alloc(sizeof(KAD_SEARCH));

    if (!kse){

      LOG_ERROR("Failed to allocate memory for kad search.");

      break;

    }

    // [LOCK] Here should be search lock initialization.
    
    kse->id = search_id++;

    kse->created = now;

    kse->last_response = now;

    kse->type = type;

    *kse_out = kse;

    result = true;

  } while (false);

  return result;
}

bool
kad_search_destroy(
                   KAD_SEARCH* kse
                   )
{
  bool result = false;

  do {

    if (!kse) break;

    LOG_DEBUG("(%d) Destroying search.", kse->id);

    // [LOCK] Here should be search lock deletion.
    
    if (kse->search_terms_data) mem_free(kse->search_terms_data);

    if (kse->file_name) mem_free(kse->file_name);

    if (kse->keywd_results) list_destroy(kse->keywd_results, true);

    if (kse->file_results) list_destroy(kse->file_results, true);

    mem_free(kse);

    result = true;

  } while (false);

  return result;
}

bool
kad_search_free_nodes_lists(
                            KAD_SEARCH* kse
                           )
{
  bool result = false;

  do {

    if (!kse) break;

    // All lists contain same set of NODE_LIST_ENTRY* pointers,
    // so we only free entries in nodes_in_use list.
    
    list_destroy(kse->nodes_best, false);

    list_destroy(kse->nodes_resp, false);

    list_destroy(kse->nodes_tried, false);

    list_destroy(kse->nodes_to_try, false);

    list_destroy(kse->nodes_in_use, true);

    kse->nodes_best = NULL;

    kse->nodes_resp = NULL;

    kse->nodes_tried = NULL;

    kse->nodes_in_use = NULL;

    kse->nodes_to_try = NULL;

    result = true;

  } while (false);

  return result;
}

bool
kad_search_contacts_count(
                          uint32_t type
                         )
{
  bool result = false;

  do {

    switch(type){

      case SEARCH_NODE:
      case SEARCH_NODE_COMPLETE:
      case SEARCH_NODE_SPECIAL:
      case SEARCH_NODE_FWCHECKUDP:

        result = SEARCH_REQ_CONTACTS_FIND_NODE;

      break;

      case SEARCH_FILE:
      case SEARCH_KEYWORD:
      case SEARCH_FIND_SOURCE:
      case SEARCH_NOTES:

        result = SEARCH_REQ_CONTACTS_FIND_VALUE;

      break;

      case SEARCH_FIND_BUDDY:
      case SEARCH_STORE_FILE:
      case SEARCH_STORE_KEYWORD:
      case SEARCH_STORE_NOTES:

        result = SEARCH_REQ_CONTACTS_STORE;

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_search_find_by_target(
                          UINT128* target,
                          LIST* kse_lst,
                          KAD_SEARCH** kse_out
                         )
{
  bool result = false;
  bool found = false;
  KAD_SEARCH* kse = NULL;

  do {

    if (!target || !kse_lst || !kse_out) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);

      SEARCH_LOCK(kse);
      
      if (0 == uint128_compare(&kse->target_id, target)){

        *kse_out = kse;

        SEARCH_UNLOCK(kse);

        found = true;

        break;

      }

      SEARCH_UNLOCK(kse);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    result = true;

  } while (false);

  return result;
}

bool
kad_search_already_going(
                         UINT128* id,
                         LIST** kse_lst_ptr
                         )
{
  bool result = false;
  LIST* kse_lst = NULL;
  KAD_SEARCH* kse = NULL;

  do {

    if (!id || !kse_lst) break;

    kse_lst = *kse_lst_ptr;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);

      if (0 == uint128_compare(id, &kse->target_id)) {

        // Search for this target is already going.
        
        result = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

  } while (false);

  return result;
}

bool
kad_search_find_in_ongoing_by_targ_id(
                                      UINT128* id,
                                      LIST** kse_lst_ptr,
                                      KAD_SEARCH** kse_out
                                     )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  LIST* kse_lst = NULL;

  do {

    if (!id || !kse_lst_ptr || !kse_out) break;

    kse_lst = *kse_lst_ptr;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);
      
      if (0 == uint128_compare(id, &kse->target_id)){

        *kse_out = kse;

        result = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

  } while (false);

  return result;
}

bool
kad_search_add_ongoing(
                       KAD_SEARCH* kse,
                       LIST** kse_lst_ptr
                      )
{
  bool result = false;

  do {

    if (!kse || !kse_lst_ptr) break;

    if (!list_add_entry(kse_lst_ptr, kse)){

      LOG_ERROR("(%d) Failed to add entry to ongoing searches list.", kse->id);

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_search_delete_from_ongoing(
                               KAD_SEARCH* kse,
                               LIST** kse_lst_ptr
                               )
{
  bool result = false;

  do {

    if (!kse || !kse_lst_ptr) break;

    kad_search_free_nodes_lists(kse);

    if (!list_remove_entry_by_data(kse_lst_ptr, kse, false)){

      LOG_DEBUG("(%d) Failed to remove entry from ongoing searches.", kse->id);

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
kad_search_delete_all_from_ongoing(
                                   LIST** kse_lst_ptr
                                  )
{
  bool result = false;
  KAD_SEARCH* kse;
  LIST* kse_lst = NULL;


  do {

    if (!kse_lst_ptr) break;

    kse_lst = *kse_lst_ptr;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);

      kad_search_free_nodes_lists(kse);

      kad_search_destroy(kse);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  return result;
}

bool
kad_search_send_find_node_pkt(
                              KAD_SESSION* ks,
                              KAD_SEARCH* kse,
                              KAD_NODE* kn,
                              UINT128* id_to_find
                              )
{
  bool result = false;
  KAD_QUEUED_PACKET* qp = NULL;
  uint8_t cont_cnt = 0;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ks || !kse || !kn || !id_to_find) break;

    if (kse->stopping) break;

    cont_cnt = kad_search_contacts_count(kse->type);

    if (!cont_cnt){

      LOG_DEBUG("(%d) Unknown search type, therefore contacts count is zero.", kse->id);

    }

    if (!kadpkt_create_search(
                              cont_cnt,
                              id_to_find,
                              &kn->id,
                              &pkt,
                              &pkt_len
                              )

    ){

      LOG_ERROR("(%d) Failed to create search packet.", kse->id);

      break;

    }

    if (!kadses_create_queue_udp_pkt(
                                     ks,
                                     kn->ip4_no,
                                     kn->udp_port_no,
                                     &kn->id,
                                     node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks)),
                                     pkt,
                                     pkt_len
                                     )
    ){

      LOG_DEBUG("(%d) Failed to queue search packet.", kse->id);

      break;

    }
                                
    result = true;

  } while (false);

  if (!result && pkt) mem_free(pkt);

  return result;
}

bool
kad_search_start(
                 KAD_SESSION* ks,
                 ROUTING_ZONE* rz,
                 UINT128* self_id,
                 UINT128* id_to_find,
                 KAD_SEARCH* kse,
                 LIST** kse_lst_ptr
                )
{
  bool result = false;
  UINT128 dist;
  bool locked = false;
  uint32_t kn_cnt = 0;
  bool canceled = false;
  uint32_t query_count = 0;
  NODE_LIST_ENTRY* nle = NULL;

  do {

    if (!ks || !rz || !self_id || !id_to_find || !kse) break;

    ONGOING_SEARCHES_LOCK(ks);
    
    locked = true;

    if (kad_search_already_going(id_to_find, kse_lst_ptr)){

      LOG_WARN("(%d) Search for this id is already going, not starting new one.", kse->id);

      break;

    }

    uint128_copy(id_to_find, &kse->target_id);

    if (!kad_search_add_ongoing(kse, kse_lst_ptr)){

      LOG_ERROR("(%d) Failed to add search to ongoing searches.", kse->id);

      break;

    }

    ONGOING_SEARCHES_UNLOCK(ks);
    
    locked = false;

    uint128_xor(self_id, id_to_find, &dist);

    LOG_DEBUG_UINT128("self_id: ", self_id);

    LOG_DEBUG_UINT128("id_to_find: ", id_to_find);

    LOG_DEBUG_UINT128("dist:", ((UINT128*)&dist));

    routing_get_closest_to(rz, 3, 50, id_to_find, &dist, true, &kse->nodes_in_use, true);

    list_entries_count(kse->nodes_in_use, &kn_cnt);

    LOG_DEBUG("(%d) closest nodes found: %d", kse->id, kn_cnt);

    if (!kn_cnt){

      LOG_WARN("(%d) No nodes collected search cancelled.", kse->id);

      canceled = true;

      break;

    }

    list_duplicate(kse->nodes_in_use, &kse->nodes_to_try);

    query_count = kse->type == SEARCH_NODE?1:(ALPHA_QUERY < kn_cnt?ALPHA_QUERY:kn_cnt);

    LOG_DEBUG("query_count: %d", query_count);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse->nodes_in_use, e, nle);

      if (!query_count--) break;

      if (kad_search_send_find_node_pkt(ks, kse, (KAD_NODE*)&nle->kn, &kse->target_id)){

        list_add_entry(&kse->nodes_tried, nle);

      } else {

        LOG_WARN("(%d) Failed to enqueue search packet.", kse->id);

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  if (locked) ONGOING_SEARCHES_UNLOCK(ks);

  if (canceled && kse){

    ONGOING_SEARCHES_LOCK(ks);

    kad_search_delete_from_ongoing(kse, kse_lst_ptr);

    ONGOING_SEARCHES_UNLOCK(ks);

  }
  
  if (!result && kse) kad_search_destroy(kse);

  return result;
}

bool
kad_search_find_node(
                     KAD_SESSION* ks,
                     ROUTING_ZONE* rz,
                     UINT128* self_id,
                     UINT128* id_to_find,
                     bool complete,
                     LIST** kse_lst_ptr
                     )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;

  do {

    if (!ks || !rz || !self_id || !id_to_find || !kse_lst_ptr) break;

    if (!kad_search_create(
                           complete?SEARCH_NODE_COMPLETE:SEARCH_NODE,
                           &kse
                           )
    ){

      LOG_ERROR("Failed to create search.");

      break;

    }

    result = kad_search_start(ks, rz, self_id, id_to_find, kse, kse_lst_ptr);

  } while (false);

  return result;
}

bool
kad_search_prepare_to_stop(
                           KAD_SEARCH* kse
                          )
{
  bool result = false;
  uint32_t base_time = 0;

  do {
    
    if (!kse || kse->stopping) break;

    LOG_DEBUG("(%d) Stopping search.", kse->id);

    switch(kse->type){

      case SEARCH_NODE:
      case SEARCH_NODE_COMPLETE:
      case SEARCH_NODE_SPECIAL:
      case SEARCH_NODE_FWCHECKUDP:

        base_time = SEARCH_LIFETIME_NODE;

      break;

      case SEARCH_KEYWORD:

        base_time = SEARCH_LIFETIME_KEYWORD;

      break;

    }

    // Search will be stopped after aproximately 15 seconds.
    
    kse->created = ticks_now_ms() - base_time + SEC2MS(15);

    kse->stopping = true;

    result = true;

  } while (false);

  return result;
}

bool
kad_search_find_node_for_fw_check(
                                  KAD_SESSION* ks,
                                  ROUTING_ZONE* rz,
                                  UINT128* self_id,
                                  LIST** kse_lst_ptr
                                 )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  UINT128 id_to_find;
  LIST* kse_lst = NULL;

  do {

    ONGOING_SEARCHES_LOCK(ks);

    kse_lst = *kse_lst_ptr;

    // Cancel all ongoing fw check searches.
    
    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);

      if (kse->type == SEARCH_NODE_FWCHECKUDP){

        kad_search_prepare_to_stop(kse);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    ONGOING_SEARCHES_UNLOCK(ks);

    if (!kad_search_create(SEARCH_NODE_FWCHECKUDP, &kse)){

      LOG_ERROR("Failed to create search.");

      break;

    }

    uint128_generate(&id_to_find);

    result = kad_search_start(ks, rz, self_id, &id_to_find, kse, kse_lst_ptr);

  } while (false);

  return result;
}

bool
kad_search_add_terms(
                     KAD_SEARCH* kse,
                     char* keywd,
                     uint32_t keywd_len
                    )
{
  bool result = false;
  uint8_t* st = NULL;
  uint32_t st_len = 0;

  do {

    if (!kse || !keywd || !keywd_len) break;

    // For now moslty hardcode,
    // other options will be implemented later.
    
    st_len = 3 + keywd_len;

    st = (uint8_t*)mem_alloc(st_len);

    if (!st){

      LOG_ERROR("Failed to allocate memory for search terms.");

      break;

    }

    *st = 1; // String type.

    *((uint16_t*)(st + 1)) = (uint16_t)keywd_len;

    kse->search_terms_data = st;

    kse->search_terms_data_len = st_len;

    result = true;

  } while (false);

  return result;
}

bool
search_find_keyword(
                    KAD_SESSION* ks,
                    ROUTING_ZONE* rz,
                    UINT128* self_id,
                    char* keywd,
                    uint32_t keywd_len,
                    LIST** kse_lst_ptr
                    )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  UINT128 id_to_find;

  do {

    if (!ks || !rz || !self_id || !keywd || !keywd_len || !kse_lst_ptr) break;

    if (!kad_search_create(SEARCH_KEYWORD, &kse)){

      LOG_ERROR("Failed to create search.");

      break;

    }

    if (!kad_search_add_terms(kse, keywd, keywd_len)){

      LOG_ERROR("Failed to add terms to search.");

      break;

    }

    kadhlp_id_from_string(ks, keywd, keywd_len, &id_to_find);  

    result = kad_search_start(ks, rz, self_id, &id_to_find, kse, kse_lst_ptr);

  } while (false);

  return result;
}

bool
kad_search_store_keyword(
                         KAD_SESSION* ks,
                         ROUTING_ZONE* rz,
                         UINT128* self_id,
                         char* keywd,
                         uint32_t keywd_len,
                         LIST** kse_lst_ptr
                        )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  UINT128 id_to_find;

  do {

    if (!ks || !rz || !self_id || !keywd || !keywd_len || !kse_lst_ptr) break;

    if (!keywd || !keywd_len) break;

    if (!kad_search_create(SEARCH_STORE_KEYWORD, &kse)){

      LOG_ERROR("Failed to create search.");

      break;

    }

    kadhlp_id_from_string(ks, keywd, keywd_len, &id_to_find);

    result = kad_search_start(ks, rz, self_id, &id_to_find, kse, kse_lst_ptr);

  } while (false);

  return result;
}

bool
kad_search_store_file(
                      KAD_SESSION* ks,
                      ROUTING_ZONE* rz,
                      UINT128* self_id,
                      UINT128* file_id,
                      LIST** kse_lst_ptr
                     )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;

  do {
    
    if (!ks || !rz || !self_id || !file_id || !kse_lst_ptr) break;

    if (!kad_search_create(SEARCH_STORE_FILE, &kse)) {

      LOG_ERROR("Failed to create search.");

      break;
      
    }

    result = kad_search_start(ks, rz, self_id, file_id, kse, kse_lst_ptr);

  } while (false);

  return result;
}

bool
kad_search_find_file(
                     KAD_SESSION* ks,
                     ROUTING_ZONE* rz,
                     UINT128* self_id,
                     UINT128* file_id,
                     char* file_name,
                     uint64_t file_size,
                     LIST** kse_lst_ptr
                    )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;

  do {

    if (!ks || !rz || !self_id || !file_id || !file_name || !file_size || !kse_lst_ptr) break;

    if (!kad_search_create(SEARCH_FILE, &kse)){

      LOG_ERROR("Failed to create search.");

      break;

    }

    kse->file_size = file_size;

    kse->file_name = (char*)mem_alloc(strlen(file_name) + 1);

    if (!kse->file_name){

      LOG_ERROR("Failed to allocate memory for file name.");

      break;

    }

    memcpy(kse->file_name, file_name, strlen(file_name));

    result = kad_search_start(ks, rz, self_id, file_id, kse, kse_lst_ptr);

  } while (false);

  if (!result && kse) kad_search_destroy(kse);

  return result;

}

bool
kad_search_process_response(
                            KAD_SESSION* ks,
                            UINT128* targ_id,
                            uint32_t ip4_no,
                            uint16_t udp_port_no,
                            LIST* resp_kn_lst,
                            LIST** kse_lst_ptr
                            )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  bool locked = true;
  bool kse_locked = false;
  uint32_t res_cnt = 0;
  LIST* nle_tried_lst = NULL;
  LIST* nle_best_lst = NULL;
  NODE_LIST_ENTRY* nle_tried = NULL;
  NODE_LIST_ENTRY* nle_new = NULL;
  NODE_LIST_ENTRY* nle_to_rem = NULL;
  NODE_LIST_ENTRY* nle_best = NULL;
  KAD_NODE* kn_resp = NULL;
  KAD_NODE* kn_in_resp = NULL;
  UINT128* dist_from_resp_kn = NULL;
  UINT128 dist_from_kn_in_resp;
  uint32_t best_kn_cnt = 0;
  bool new_best = false;
  UINT128 tmp_dist;

  do {

    if (!ks || !targ_id || !resp_kn_lst || !kse_lst_ptr) break;

    ONGOING_SEARCHES_LOCK(ks);

    locked = true;

    // Check if target is from valid ongoing search.

    if (!kad_search_find_in_ongoing_by_targ_id(targ_id, kse_lst_ptr, &kse)){

      LOG_DEBUG("Ongoing search for this target id not found.");

      break;

    }

    SEARCH_LOCK(kse);

    kse_locked = true;

    ONGOING_SEARCHES_UNLOCK(ks);

    locked = false;

    // Get contacts count in response list.

    list_entries_count(resp_kn_lst, &res_cnt);

    LOG_DEBUG("(%d) Entries in response list %.2d", kse->id, res_cnt);

    if (res_cnt > kad_search_contacts_count(kse->type)){

      LOG_DEBUG("(%d) More contacts in search list than needed discarding result.", kse->id);

      break;

    }

    // Update last response time.

    kse->last_response = ticks_now_ms();

    if (kse->type == SEARCH_NODE_FWCHECKUDP){

      LOG_DEBUG("(%d) Search type SEARCH_NODE_FWCHECKUDP.", kse->id);

      break;

    }

    if (kse->type == SEARCH_NODE){

      LOG_DEBUG("(%d) Search type SEARCH_NODE.", kse->id);

      kad_search_free_nodes_lists(kse);

      kse->answers++;

      break;

    }

    // Find responded node in tried nodes list.
    
    nle_tried_lst = kse->nodes_tried;
    
    LIST_EACH_ENTRY_WITH_DATA_BEGIN(nle_tried_lst, e, nle_tried);

      kn_resp = &nle_tried->kn;

      dist_from_resp_kn = &nle_tried->dist;

      if (kn_resp->ip4_no == ip4_no && kn_resp->udp_port_no == udp_port_no){

        // Found responded node.
        // Add node to responded nodes list.
        // Now node is a part of three lists nodes_in_use, nodes_tried, nodes_resp

        list_add_entry(&kse->nodes_resp, nle_tried);

        // Go through nodes received in response packet and find closest to target.
        
        LIST_EACH_ENTRY_WITH_DATA_BEGIN(resp_kn_lst, e, kn_in_resp); 

          // Calculate distance to node in response.

          uint128_xor(&kn_in_resp->id, &kse->target_id, &dist_from_kn_in_resp);

          // Check if we already use this node in this search.

          if (kadhlp_find_kn_in_nle_list(&kse->nodes_in_use, &kse->target_id, NULL)){

            LOG_DEBUG("(%d) Answered node already in nodes_in_use, discarding.", kse->id);

            continue;

          }

          // Check if we already send query to this node during this search.

          if (kadhlp_find_kn_in_nle_list(&kse->nodes_tried, &dist_from_kn_in_resp, NULL)){

            LOG_DEBUG("(%d) Answered node already in nodes_tried, discarding.", kse->id);

            continue;

          }

          // [TODO] here to place ip/subnet check.
          
          // Add responed node to nodes in use sorted by distance in ascending order.
          
          uint128_copy(&dist_from_kn_in_resp, &tmp_dist);

          nodelist_add_entry(&kse->nodes_in_use, kn_in_resp, &tmp_dist, &nle_new);

          nodelist_add_existing_entry(&kse->nodes_to_try, nle_new);

          // Check if distance to target from node listed in response is lesser than from responded node.
          
          if (0xff == uint128_compare(&dist_from_kn_in_resp, dist_from_resp_kn)){
            
            list_entries_count(kse->nodes_best, &best_kn_cnt);

            new_best = true;

            nle_to_rem = NULL;

            if (best_kn_cnt >= ALPHA_QUERY){

              // Delete farthest node from best nodes list and add closer one.
              
              new_best = false;

              nle_best_lst = kse->nodes_best;

              LIST_EACH_ENTRY_WITH_DATA_BEGIN(nle_best_lst, e, nle_best);

                if (0xff == uint128_compare(&dist_from_kn_in_resp, &nle_best->dist)){

                  nle_to_rem = nle_best;

                  new_best = true;

                  break;

                }

              LIST_EACH_ENTRY_WITH_DATA_END(e);

            }

            if (nle_to_rem) list_remove_entry_by_data(&kse->nodes_best, (void*)nle_to_rem, false);

            if (new_best){

              nodelist_add_existing_entry(&kse->nodes_best, nle_new);

              // We send search packet to a node that have shortest distance to target.
                
              if (kad_search_send_find_node_pkt(ks, kse, (KAD_NODE*)&nle_new->kn, &kse->target_id)){

                list_add_entry(&kse->nodes_tried, (void*)nle_new);

              }

            }

          }

        LIST_EACH_ENTRY_WITH_DATA_END(e); // LIST_EACH_ENTRY_WITH_DATA_BEGIN(resp_kn_lst, e, kn_in_resp); 

        if (kse->type == SEARCH_NODE_COMPLETE || kse->type == SEARCH_NODE_SPECIAL) kse->answers++;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e); // LIST_EACH_ENTRY_WITH_DATA_BEGIN(kn_tried_lst, e, nle_tried);

    result = true;

  } while (false);

  if (locked) ONGOING_SEARCHES_UNLOCK(ks);

  if (kse && kse_locked) SEARCH_UNLOCK(kse);

  return result;
}

bool
kad_search_process_last_node_response(
                                      KAD_SESSION* ks,
                                      KAD_SEARCH* kse,
                                      NODE_LIST_ENTRY* nle
                                     )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  UINT128* cli_id = NULL;
  uint32_t cli_key = 0;
  bool pkt_queued = false;

  do {

    if (!ks || !kse || !nle) break;

    kn = &nle->kn;

    switch(kse->type){

      case SEARCH_KEYWORD:

        if (kadpkt_create_search_key_req(
                                         &kse->target_id,
                                         kse->search_terms_data,
                                         kse->search_terms_data_len,
                                         &pkt,
                                         &pkt_len
                                         )
        ){

          LOG_ERROR("(%d) Failed to create search key request.", kse->id);

          break;

        }

        if (kn->version >= 6){

          cli_id = &kn->id;

          cli_key = node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks));

        }

        if (kadses_create_queue_udp_pkt(ks, kn->ip4_no, kn->udp_port_no, cli_id, cli_key, pkt, pkt_len)){

          LOG_ERROR("(%d) Failed to queue search request packet.", kse->id);

          break;

        }

        pkt_queued = true;

      break;

      case SEARCH_FILE:

        if (!kadpkt_create_search_source_req(
                                             &kse->target_id,
                                             kse->file_size,
                                             &pkt,
                                             &pkt_len
                                             )
        ){

          LOG_ERROR("(%d) Failed to create search source request packet.", kse->id);

          break;

        }

        if (kn->version >= 6){

          cli_id = &kn->id;

          cli_key = node_get_udp_key_by_ip(kn, kadses_get_pub_ip(ks));

        }

        if (kadses_create_queue_udp_pkt(ks, kn->ip4_no, kn->udp_port_no, cli_id, cli_key, pkt, pkt_len)){

          LOG_ERROR("(%d) Failed to queue search source request packet.");

          break;

        }

        pkt_queued = false;

      break;

      case SEARCH_STORE_KEYWORD:

        // [IMPLEMENT] publishing

      break;

      case SEARCH_STORE_FILE:

        // [IMPLEMENT] publishing

      break;


    }

    result = true;

  } while (false);

  if (pkt_queued && pkt) mem_free(pkt);

  return result;
}

bool
kad_search_jump_start(
                      KAD_SESSION* ks,
                      KAD_SEARCH* kse
                      )
{
  bool result = false;
  uint32_t nodes_to_try_cnt = 0;
  LIST* nodes_to_try = NULL;
  uint32_t now = 0;
  NODE_LIST_ENTRY* nle = NULL;
  LIST* del_from_to_try = NULL;

  do {

    if (!ks || !kse) break;

    now = ticks_now_ms();

    list_entries_count(kse->nodes_to_try, &nodes_to_try_cnt);

    if (!nodes_to_try_cnt){

      // If no more nodes available stop search.
      
      kad_search_prepare_to_stop(kse);

      break;

    }

    // Check if we had response within 3 seconds interval.

    if (kse->last_response + SEC2MS(3) > now){

      LOG_ERROR("(%d) No jump start needed.", kse->id);

      break;

    }

    nodes_to_try = kse->nodes_to_try;

    // Go through all nodes to try for current search
    // and first - find responded ones and handle
    // responses from them, second - find next
    // node to send search packet to.

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(nodes_to_try, e, nle);

      if (list_entry_by_data(kse->nodes_tried, nle, NULL)){

        // Already tried that node.
       
        if (list_entry_by_data(kse->nodes_resp, nle, NULL)){

          // Node responded.
          
          kad_search_process_last_node_response(ks, kse, nle);

        }

        // Remove tried node from nodes_to_try list.

        list_add_entry(&del_from_to_try, (void*)nle);

      } else {

          // Add node to tried nodes list.
          
          list_add_entry(&kse->nodes_tried, (void*)nle);

          // Use this node to send next search request.
          
          kad_search_send_find_node_pkt(ks, kse, (KAD_NODE*)&nle->kn, &kse->target_id);

          // [QUESTION] With this break in place not all nodes from to_try list
          // will be checked, i think.

          break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    // Now delete tried nodes.
    
    LIST_EACH_ENTRY_WITH_DATA_BEGIN(del_from_to_try, e, nle);

      // We do not free entry because it is a member
      // of at least nodes_in_use list.

      list_remove_entry_by_data(&kse->nodes_to_try, nle, false);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  if (del_from_to_try) list_destroy(del_from_to_try, false);

  return result;
}

bool
kad_search_expire(
                  KAD_SEARCH* kse,
                  LIST** expired_kse_lst
                  )
{
  bool result = false;

  do {

    if (!kse || !expired_kse_lst) break;

    LOG_DEBUG("(%d) Expiring search.", kse->id);

    kad_search_free_nodes_lists(kse);

    list_add_entry(expired_kse_lst, kse);

    result = true;

  } while (false);

  return result;
}

bool
kad_search_jumpstart_all(
                         KAD_SESSION* ks,
                         LIST** kse_lst_ptr
                        )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;
  LIST* kse_lst = NULL;
  LIST* kse_exp_lst = NULL;
  uint32_t now;
  SEARCH_KEYWORD_RESULT* kwd_res = NULL;

  do {

    if (!ks || !kse_lst_ptr) break;

    now = ticks_now_ms();

    kse_lst = *kse_lst_ptr;

    ONGOING_SEARCHES_LOCK(ks);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_lst, e, kse);

      SEARCH_LOCK(kse);

      switch (kse->type) {

        case SEARCH_FILE:

          if (kse->created + SEARCH_LIFETIME_FILE < now){

            kad_search_expire(kse, &kse_exp_lst);

          } else if (kse->answers > SEARCH_TOTAL_FILE || kse->created + SEARCH_LIFETIME_FILE - SEC2MS(20) < now) {

            kad_search_prepare_to_stop(kse);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;

        case SEARCH_KEYWORD:

          if (kse->created + SEARCH_LIFETIME_KEYWORD < now){

            kad_search_expire(kse, &kse_exp_lst);

          } else if (
                     kse->answers > SEARCH_TOTAL_KEYWORD || 
                     kse->created + SEARCH_LIFETIME_KEYWORD - SEC2MS(20) < now
          ){

            kad_search_prepare_to_stop(kse);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;

        case SEARCH_NODE:
        case SEARCH_NODE_SPECIAL:
        case SEARCH_NODE_FWCHECKUDP:

          if (kse->created + SEARCH_LIFETIME_NODE < now){

            // Search expired, will be deleted.
            
            kad_search_expire(kse, &kse_exp_lst);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;

        case SEARCH_NODE_COMPLETE:

          if (kse->created + SEARCH_LIFETIME_NODE < now){

            // [IMPLEMENT] set publish enabled flag.
            
            kad_search_expire(kse, &kse_exp_lst);

          } else if (
                     kse->created + SEARCH_LIFETIME_NODECOMP < now &&
                     kse->answers > SEARCH_TOTAL_NODECOMP
          ){

            // [IMPLEMENT] set publish enabled flag.
            
            kad_search_expire(kse, &kse_exp_lst);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;

        case SEARCH_STORE_FILE:

          if (kse->created + SEARCH_LIFETIME_STORE_FILE < now){

            kad_search_expire(kse, &kse_exp_lst);

          } else if (kse->answers > SEARCH_TOTAL_STORE_FILE || 
                     kse->created + SEARCH_LIFETIME_STORE_FILE - SEC2MS(20)
          ){

            kad_search_prepare_to_stop(kse);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;
        
        case SEARCH_STORE_KEYWORD:

          if (kse->created + SEARCH_LIFETIME_STORE_KEYWORD < now){

            kad_search_expire(kse, &kse_exp_lst);

          } else if (
                     kse->answers > SEARCH_TOTAL_STORE_KEYWORD ||
                     kse->created + SEARCH_LIFETIME_STORE_KEYWORD - SEC2MS(20) < now
          ){
            
            kad_search_prepare_to_stop(kse);

          } else {

            kad_search_jump_start(ks, kse);

          }

        break;

      }

      SEARCH_UNLOCK(kse);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    // Delete expired searches.
    
    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse_exp_lst, e, kse);

      list_remove_entry_by_data(kse_lst_ptr, (void*)kse, false);

      // Handle search results.

      LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse->keywd_results, e, kwd_res);

        // [IMPLEMENT] Handle keyword results

      LIST_EACH_ENTRY_WITH_DATA_END(e);

      // [IMPLEMENT] file results handling
      
      kad_search_destroy(kse);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    // Destroing only list all entries was freed
    // in previous loop.

    list_destroy(kse_exp_lst, false);

    ONGOING_SEARCHES_UNLOCK(ks);

    result = true;

  } while (false);

  return result;
}

bool
kad_search_add_keyword_result(
                              KAD_SEARCH* kse,
                              UINT128* id,
                              char* file_name,
                              uint64_t file_size,
                              char* file_type,
                              char* file_format,
                              uint16_t avail,
                              uint32_t pub_info
                              )
{
  bool result = false;
  SEARCH_KEYWORD_RESULT* kwd_res = NULL;
  uint32_t kwd_res_len = 0;
  char* p = NULL;
  uint32_t len = 0;

  do {

    kwd_res_len = (sizeof(SEARCH_KEYWORD_RESULT) - 1) +
                  (strlen(file_name) + 1) +
                  (strlen(file_type) + 1) +
                  (strlen(file_format) + 1);

    kwd_res = (SEARCH_KEYWORD_RESULT*)mem_alloc(kwd_res_len);

    if (kwd_res){

      LOG_ERROR("Failed to allocate memory for keyword result.");

      break;

    }

    p = (char*)kwd_res + (sizeof(SEARCH_KEYWORD_RESULT) - 1);

    // File name hash

    uint128_copy(id, &kwd_res->id);
    
    len = strlen(file_name);

    if (len){

      // File name

      kwd_res->file_name = p; 

      memcpy(p, file_name, len);

      p += len + 1;

    }

    // File size

    kwd_res->file_size = file_size;

    len = strlen(file_type);

    if (len){

      // File type

      kwd_res->file_type = p;

      memcpy(p, file_type, len);

      p += len + 1;

    } 

    len = strlen(file_format);

    if (len){

      kwd_res->file_format = p;

      memcpy(p, file_format, len);

      p += len + 1;

    }

    // Availability

    kwd_res->avail = avail;

    // Publish info.

    kwd_res->publish_info = pub_info;

    if (!list_add_entry(&kse->keywd_results, (void*)kwd_res)){

      LOG_ERROR("Failed to add keyword result.");

      break;

    }

    result = true;

  } while (false);

  if (!result && kwd_res) mem_free(kwd_res);

  return result;
}

bool
kad_search_check_file_result(
                             KAD_SEARCH* kse,
                             SEARCH_FILE_RESULT* chk_file_res
                            )
{
  bool result = false;
  SEARCH_FILE_RESULT* file_res = NULL;
  bool found = false;

  do {

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kse->file_results, e, file_res);

      if (chk_file_res->ip4 == file_res->ip4 && chk_file_res->udp_port == file_res->udp_port){

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (found) break;

    result = true;

  } while (false);

  return result;
}

bool
kad_search_add_file_result(
                           KAD_SEARCH* kse,
                           uint8_t type,
                           UINT128* id,
                           uint32_t ip4,
                           uint16_t tcp_port,
                           uint16_t udp_port,
                           uint32_t buddy_ip4,
                           uint32_t buddy_port,
                           UINT128* buddy_id,
                           uint8_t cipher_opts
                          )
{
  bool result = false;
  SEARCH_FILE_RESULT *file_res = NULL;

  do {

    if (!kse) break;

    file_res = (SEARCH_FILE_RESULT*)mem_alloc(sizeof(SEARCH_FILE_RESULT));

    if (!file_res){

      LOG_ERROR("Failed to allocate memory for file result.");

      break;

    }

    file_res->type = type;

    uint128_copy(id, &file_res->id);

    file_res->ip4 = ip4;

    file_res->tcp_port = tcp_port;

    file_res->udp_port = udp_port;

    file_res->buddy_ip4 = buddy_ip4;

    file_res->buddy_port = buddy_port;

    uint128_copy(buddy_id, &file_res->buddy_id);

    file_res->cipher_opts = cipher_opts;

    if (!kad_search_check_file_result(kse, file_res)) {

      LOG_WARN("File results with this address already exist.");

      break;

    }

    if (!list_add_entry(&kse->file_results, (void*)file_res)){

      LOG_ERROR("Failed to add file search result to list.");

      break;

    }

    result = true;

  } while (false);

  if (!result && file_res) mem_free(file_res);

  return result;
}

bool
kad_search_process_result_keyword(
                                  KAD_SESSION* ks,
                                  KAD_SEARCH* kse,
                                  UINT128* answer,
                                  LIST* tag_lst
                                 )
{
  bool result = false;
  TAG* tag = NULL;
  wchar_t* tag_name = NULL;
  uint32_t tag_name_len = 0;
  char* file_name = NULL;
  uint32_t file_name_len = 0;
  char* file_type = NULL;
  uint32_t file_type_len = 0;
  char* file_fmt = NULL;
  uint32_t file_fmt_len = 0;
  uint64_t avail = 0;
  uint64_t pub_info = 0;
  uint64_t file_size = 0;
  uint32_t len = 0;

  do {

    if (!ks || !kse || !answer || !tag_lst) break;

    kse->answers++;

    file_name_len = 256;

    file_name = (char*)mem_alloc(file_name_len);

    if (!file_name){

      LOG_ERROR("Failed to allocate memory for file name.");

      break;

    }

    file_type_len = 0;

    file_type = (char*)mem_alloc(file_type_len);

    if (!file_type){

      LOG_ERROR("Failed to allocate memory for file type.");

      break;

    }

    file_fmt_len = 32;

    file_fmt = (char*)mem_alloc(file_fmt_len);

    if (!file_fmt){

      LOG_ERROR("Failed to allocate memory for file format.");

      break;

    }

    tag_name_len = 128;

    tag_name = (wchar_t*)mem_alloc(tag_name_len * sizeof(wchar_t));

    if (!tag_name){

      LOG_ERROR("Failed to allocate memory for tag name.");

      break;

    }

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(tag_lst, e, tag);

      if (tag->name_len > tag_name_len){

        tag_name_len = tag->name_len;

        mem_realloc(tag_name, tag_name_len);

      }

      tag_get_name(tag, tag_name, tag_name_len);

      if (0 == str_wide_cmp(tag_name, TAG_FILENAME)){

        tag_string_get_len(tag, &len);

        MEM_ADJUST_BUFFER(file_name, file_name_len, len);

        memset(file_name, 0, file_name_len);

        tag_string_get_data(tag, (uint8_t*)file_name, file_name_len);

      } else if (0 == str_wide_cmp(tag_name, TAG_FILESIZE)){

        if (tag_is_bsob(tag)){

          tag_bsob_get_len(tag, &len);

          if (len == 8){

            tag_bsob_get_data(tag, (uint8_t*)file_size, sizeof(file_size));

          }

        } else {

          tag_get_integer(tag, &file_size);

        }

      } else if (0 == str_wide_cmp(tag_name, TAG_FILETYPE)){

        tag_string_get_len(tag, &len);

        MEM_ADJUST_BUFFER(file_type, file_type_len, len);

        memset(file_type, 0, file_type_len);

        tag_string_get_data(tag, (uint8_t*)file_type, file_type_len);

      } else if (0 == str_wide_cmp(tag_name, TAG_FILEFORMAT)){

        tag_string_get_len(tag, &len);

        MEM_ADJUST_BUFFER(file_fmt, file_fmt_len, len);

        memset(file_fmt, 0, file_fmt_len);

        tag_string_get_data(tag, (uint8_t*)file_fmt, file_fmt_len);

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_ARTIST)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_ALBUM)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_TITLE)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_LENGTH)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_BITRATE)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_MEDIA_CODEC)) {

      } else if (0 == str_wide_cmp(tag_name, TAG_SOURCES)) {

        tag_get_integer(tag, &avail);

      } else if (0 == str_wide_cmp(tag_name, TAG_PUBLISHINFO)) {

        tag_get_integer(tag, &pub_info);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    kad_search_add_keyword_result(kse, answer, file_name, file_size, file_type, file_fmt, (uint16_t)avail, (uint32_t)pub_info);

    result = true;

  } while (false);

  if (tag_name) mem_free(tag_name);

  if (file_name) mem_free(file_name);

  if (file_type) mem_free(file_type);

  if (file_fmt) mem_free(file_fmt);

  return result;
}

bool
kad_search_process_result_file(
                               KAD_SESSION* ks,
                               KAD_SEARCH* kse,
                               UINT128* resp_id,
                               LIST* tag_lst
                               )
{
  bool result = false;
  TAG* tag = NULL;
  wchar_t* tag_name = NULL;
  uint32_t tag_name_len = 0;
  uint32_t len = 0;
  uint8_t type = 0;
  uint32_t ip4 = 0;
  uint16_t udp_port = 0;
  uint16_t tcp_port = 0;
  uint32_t buddy_ip4 = 0;
  uint16_t buddy_port = 0;
  UINT128 buddy_id;
  uint8_t crypt_opts = 0;
  uint64_t val = 0;

  do {

    if (!ks || !kse || !resp_id || !tag_lst) break;

    kse->answers++;

    tag_name_len = 128;

    tag_name = (wchar_t*)mem_alloc(tag_name_len * sizeof(wchar_t));

    if (!tag_name){

      LOG_ERROR("Failed to allocate memory for tag name.");

      break;

    }

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(tag_lst, e, tag);

      if (tag->name_len > tag_name_len){

        tag_name_len = tag->name_len;

        mem_realloc(tag_name, tag_name_len);

      }

      tag_get_name(tag, tag_name, tag_name_len);

      if (!str_wide_cmp(tag_name, TAG_SOURCETYPE)){

        if (tag_get_integer(tag, &val)){

          type = (uint8_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_SOURCEIP)){

        if (tag_get_integer(tag, &val)){

          ip4 = (uint32_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_SOURCEPORT)){

        if (tag_get_integer(tag, &val)){

          tcp_port = (uint16_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_SOURCEUPORT)){

        if (!tag_get_integer(tag, &val)){

          udp_port = (uint16_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_SERVERIP)){

        if (tag_get_integer(tag, &val)){

          buddy_ip4 = (uint32_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_SERVERPORT)){

        if (tag_get_integer(tag, &val)){

          buddy_port = (uint16_t)val;

        }

      } else if (!str_wide_cmp(tag_name, TAG_BUDDYHASH)){

        // [TODO] decode string to UINT128
      
      } else if (!str_wide_cmp(tag_name, TAG_ENCRYPTION)){

        if (tag_get_integer(tag, &val)){

          crypt_opts = (uint8_t)val;

        }

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    kad_search_add_file_result(kse, type, resp_id, ip4, tcp_port, udp_port, buddy_ip4, buddy_port, &buddy_id, crypt_opts);

    result = true;

  } while (false);

  return result;
}

bool
kad_search_process_result(
                          KAD_SESSION* ks,
                          UINT128* trgt_id,
                          UINT128* resp_id,
                          LIST* tag_lst
                         )
{
  bool result = false;
  bool locked = false;
  KAD_SEARCH* kse = NULL;

  do {

    if (!ks || !trgt_id || !resp_id || !tag_lst) break;

    ONGOING_SEARCHES_LOCK(ks);

    locked = true;

    if (!kad_search_find_by_target(trgt_id, ks->searches, &kse)){

      LOG_ERROR("Target id not found in ongoing searches.");

      break;

    }

    LOG_DEBUG("(%d) Prosessing results.", kse->id);

    SEARCH_LOCK(kse);

    ONGOING_SEARCHES_UNLOCK(ks);

    locked = false;

    switch(kse->type){

      case SEARCH_KEYWORD:

        kad_search_process_result_keyword(ks, kse, resp_id, tag_lst);

      break;

      case SEARCH_FILE:

        kad_search_process_result_file(ks, kse, resp_id, tag_lst);

      break;

    }

    SEARCH_UNLOCK(kse);

    result = true;

  } while (false);

  if (locked) ONGOING_SEARCHES_UNLOCK(ks);

  return result;
}

bool
kad_search_is_udp_fw_check(
                           KAD_SESSION* ks,
                           UINT128* trgt_id
                           )
{
  bool result = false;
  KAD_SEARCH* kse = NULL;

  do {

    if (!ks || !trgt_id) break;

    if (!kad_search_find_in_ongoing_by_targ_id(trgt_id, &ks->searches, &kse)){

      LOG_ERROR("Ongoing search for given target id not found.");

      break;

    }

    if (kse->type != SEARCH_NODE_FWCHECKUDP) break;

    result = true;

  } while (false);

  return result;
}
