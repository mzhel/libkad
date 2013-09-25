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
#include <list.h>
#include <nodelist.h>
#include <node.h>
#include <kbucket.h>
#include <mem.h>
#include <log.h>

bool
kbucket_create(
               KBUCKET** kb_ptr
              )
{
  bool result = false;
  KBUCKET* kb = NULL;

  do {

    if (!kb_ptr) break;

    kb = (KBUCKET*)mem_alloc(sizeof(KBUCKET));

    if (!kb){

      LOG_ERROR("Failed to allocate memory for kbucket.");

      break;

    }

    // Here should be bucket lock initialization.
    
    *kb_ptr = kb;

    result = true;

  } while (false);

  return result;
}

bool
kbucket_destroy(
                KBUCKET* kb,
                bool keep_nodes
               )
{
  bool result = false;

  do {

    if (!kb) break;

    LOG_DEBUG("+++kbucket_destroy+++");

    LOG_DEBUG("nodes_count %.4d", kb->nodes_count);

    if (!keep_nodes){

      for (uint8_t i = 0; i < kb->nodes_count; i++) {

        node_destroy((KAD_NODE*)kb->nodes[i]);

      }

    }

    // Here should be bucket lock deinitialization.
    
    mem_free(kb);

    result = true;

  } while (false);

  return result;
}

bool
kbucket_add_node(
                 KBUCKET* kb,
                 KAD_NODE* kn
                )

{
  bool result = false;
  bool already_added = false;

  do {
    
    if (!kb || !kn) break;

    if (kb->nodes_count >= K) {

      break;

    }

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      if (0 == uint128_compare(&kn->id, &kb->nodes[i]->id)){

        already_added = true;

        break;

      }

    }

    if (already_added) break;

    kb->nodes[kb->nodes_count++] = kn;

    result = true;

  } while (false);

  return result;
}

bool
kbucket_node_by_id(
                   KBUCKET* kb,
                   UINT128* id,
                   KAD_NODE** kn_out
                  )
{
  bool result = false;

  do {

    if (!kb || !id || !kn_out) break;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      if (0 == uint128_compare(id, &kb->nodes[i]->id)){

        *kn_out = kb->nodes[i];

        result = true;

        break;

      }

    }

  } while (false);

  return result;
}

bool
kbucket_node_by_ip_port(
                        KBUCKET* kb,
                        uint32_t ip4_no,
                        uint16_t port_no,
                        uint8_t port_type,
                        KAD_NODE** kn_out
                       )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  bool found = false;

  do {

    if (!kb) break;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      kn = kb->nodes[i];

      if (kn->ip4_no == ip4_no) {
      
        if (
            (port_type == KAD_NODE_TCP_PORT && kn->tcp_port_no == port_no) ||
            (port_type == KAD_NODE_UDP_PORT && kn->udp_port_no == port_no)
        ){

          found = true;

          break;

        }

      }

    }

    if (!found) break;

  } while (false);

  *kn_out = kn;

  return result;
  
}

bool
kbucket_remove_node_by_idx(
                           KBUCKET* kb,
                           uint32_t idx,
                           KAD_NODE** rmvd_kn_out
                          )
{
  bool result = false;
  uint32_t shift = 0;

  do {

    if (!kb) break;

    if (kb->nodes_count <= idx) break;

    KBUCKET_LOCK(kb);

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      if (i == idx) {

        shift = 1;

        if (rmvd_kn_out) *rmvd_kn_out = kb->nodes[i];

      } else {

        if (shift) kb->nodes[i - shift] = kb->nodes[i];

      }

    }

    if (shift) {

      kb->nodes_count--;

      kb->nodes[kb->nodes_count] = NULL;

    }

    KBUCKET_UNLOCK(kb);

    result = true;

  } while (false);

  return result;
}

bool
kbucket_remove_node_by_node(
                            KBUCKET* kb,
                            KAD_NODE* kn,
                            KAD_NODE** rmvd_kn_out
                           )
{
  bool result = false;

  do {

    if (!kb || !kn) break;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      if (kb->nodes[i] == kn) {

        result = kbucket_remove_node_by_idx(kb, i, rmvd_kn_out);

        break;

      }

    }

    result = true;

  } while (false);

  return result;
}

bool
kbucket_get_oldest_node(
                        KBUCKET* kb,
                        KAD_NODE** kn_out
                       )
{
  bool result = false;

  do {
    
    if (!kb || !kn_out) break;

    if (!kb->nodes_count) break;

    *kn_out = kb->nodes[0];

    result = true;

  } while (false);

  return result;
}

bool
kbucket_push_node_up(
                     KBUCKET* kb,
                     KAD_NODE* kn
                    )
{
  bool result = false;
  uint32_t shift = 0;
  bool locked = false;
  uint32_t i;

  do {

    if (!kb) break;

    KBUCKET_LOCK(kb);

    locked = true;

    for (i = 0; i < kb->nodes_count; i++){

      if (kb->nodes[i] == kn) {

        shift = 1;

      } else {

        if (shift) kb->nodes[i - shift] = kb->nodes[i];

      }

    }

    if (shift) {

      i = kb->nodes_count - 1;

      kb->nodes[i] = kn;

    }

    result = true;

  } while (false);

  if (locked) KBUCKET_UNLOCK(kb);

  return result;
}

bool
kbucket_get_closest_to(
                       KBUCKET* kb,
                       uint32_t max_type,
                       uint32_t max_required,
                       UINT128* trgt_id,
                       bool protect_picked_nodes,
                       LIST** lst_inout
                      )
{
  bool result = false;
  KAD_NODE* kn = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t count = 0;

  do {

    if (!kb || !trgt_id || !lst_inout) break;

    for (uint32_t i = 0; i < kb->nodes_count; i++) {

      kn = kb->nodes[i];

      if (kn->type <= max_type && kn->ip_verified) {

        nle = (NODE_LIST_ENTRY*)mem_alloc(sizeof(NODE_LIST_ENTRY));

        if (!nle) {
          
          LOG_ERROR("Failed to allocate memory for node list entry.");

          break;

        }

        uint128_xor(trgt_id, &kn->id, &nle->dist);

        nle->node = (void*)kn;

        nodelist_add_entry(lst_inout, nle);

        if (protect_picked_nodes) kn->in_use++;

      }

    }

    do {

      list_entries_count(*lst_inout, &count);

      if (count <= max_required) break;

      list_remove_last_entry(lst_inout, (void*)&nle);

      if (nle) {

        ((KAD_NODE*)nle->node)->in_use--;

        mem_free(nle);

      }

    } while (true);

    result = true;

  } while (false);

  return result;
}

bool
kbucket_get_random_node(
                        KBUCKET* kb,
                        uint32_t max_type,
                        uint32_t min_kad_ver,
                        KAD_NODE** kn_out
                       )
{
  bool result = false;
  uint32_t rand_idx = 0;
  uint32_t last_fit_idx;
  KAD_NODE* kn;
  bool found = false;

  do {

    if (!kb || !kn_out) break;

    if (!kb->nodes_count) break;

    rand_idx = random_uint32() % kb->nodes_count;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      kn = kb->nodes[i];

      if (kn->type <= max_type && kn->version >= min_kad_ver){

        found = true;

        last_fit_idx = i;

        if (i >= rand_idx) break;

      }

    }

    if (!found) break;

    *kn_out = kb->nodes[last_fit_idx];

    result = true;

  } while (false);

  return result;
}

bool
kbucket_set_node_alive(
                       KBUCKET* kb,
                       KAD_NODE* kn
                       )
{
  bool result = false;
  KAD_NODE* kn2 = NULL;

  do {

    if (!kb || !kn) break;

    kbucket_node_by_id(kb, &kn->id, &kn2);

    if (kn == kn2){

      node_set_alive(kn);

      kbucket_push_node_up(kb, kn); 

      result = true;

    }

  } while(false);


  return result;
}

bool
kbucket_get_nodes(
                  KBUCKET* kb,
                  LIST** lst_out
                 )
{
  bool result = false;

  do {

    if (!kb || !lst_out) break;

    for (uint32_t i = 0; i < kb->nodes_count; i++){

      list_add_entry(lst_out, (void*)kb->nodes[i]);

    }

    result = true;

  } while (false);

  return result;
}

