#ifndef _NODELIST_H_
#define _NODELIST_H_

typedef struct _nodelist_entry {
  UINT128 dist;
  KAD_NODE kn;
} NODE_LIST_ENTRY;

bool
nodelist_add_entry(
                   LIST** nl_ptr,
                   KAD_NODE* kn,
                   UINT128* dist,
                   NODE_LIST_ENTRY** nle_out
                  );

bool
nodelist_add_existing_entry(
                            LIST** nl_ptr,
                            NODE_LIST_ENTRY* nle
                            );

#endif // _NODELIST_H_
