#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <node.h>
#include <nodelist.h>
#include <mem.h>
#include <log.h>

bool
nodelist_add_entry(
                   LIST** nl_ptr,
                   KAD_NODE* kn,
                   UINT128* dist,
                   NODE_LIST_ENTRY** nle_out
                  )
{
  bool result = false;
  LIST* nl = NULL;
  NODE_LIST_ENTRY* e;
  NODE_LIST_ENTRY* nle = NULL;
  int32_t idx = 0;
  bool idx_found = false;

  do {

    if (!nl_ptr || !kn || !dist) break;
  
    nle = (NODE_LIST_ENTRY*)mem_alloc(sizeof(NODE_LIST_ENTRY));

    if (!nle) {

      LOG_ERROR("Failed to allocate memory for node entry.");

      break;

    }

    uint128_copy(dist, &nle->dist);

    node_copy(kn, &nle->kn, NULL);

    // All entries in node list sorted by distance in ascending order.
    
    nl = *nl_ptr;

    if (!nl) {

      // List is empty, this is first entry.
      
      result = list_add_entry(nl_ptr, (void*)nle);

      break;

    }

    do {

      if (!nl) break;

      list_get_entry_data(nl, (void**)&e);

      if (0xff == uint128_compare(&nle->dist, &e->dist)){

        result = list_add_entry_at_idx(nl_ptr, (void*)nle, idx);

        idx_found = true;

        break;

      }

      list_next_entry(nl, &nl);

      idx++;

    } while (true);

    if (!idx_found) {

      // Adding new entry to list end.
      
      result = list_add_entry(nl_ptr, (void*)nle);

    }

    result = true;

  } while (false);

  if (result && nle_out) *nle_out = nle;

  return result;
}

bool
nodelist_add_existing_entry(
                            LIST** nl_ptr,
                            NODE_LIST_ENTRY* nle
                            )
{
  bool result = false;
  LIST* nl = NULL;
  NODE_LIST_ENTRY* e;
  int32_t idx = 0;
  bool idx_found = false;

  do {

    if (!nl_ptr || !nle) break;
  
    // All entries in node list sorted by distance in ascending order.
    
    nl = *nl_ptr;

    if (!nl) {

      // List is empty, this is first entry.
      
      result = list_add_entry(nl_ptr, (void*)nle);

      break;

    }

    do {

      if (!nl) break;

      list_get_entry_data(nl, (void**)&e);

      if (0xff == uint128_compare(&nle->dist, &e->dist)){

        result = list_add_entry_at_idx(nl_ptr, (void*)nle, idx);

        idx_found = true;

        break;

      }

      list_next_entry(nl, &nl);

      idx++;

    } while (true);

    if (!idx_found) {

      // Adding new entry to list end.
      
      result = list_add_entry(nl_ptr, (void*)nle);

    }

    result = true;

  } while (false);

  return result;
}
