#ifndef _NODELIST_H_
#define _NODELIST_H_

typedef struct _nodelist_entry {
  UINT128 dist;
  void* node;
} NODE_LIST_ENTRY;

bool
nodelist_add_entry(
                   LIST** nl_ptr,
                   NODE_LIST_ENTRY* nle 
                  );

#endif // _NODELIST_H_
