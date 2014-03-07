#ifndef _KADSRCH_H_
#define _KADSRCH_H_

#define SEARCH_NODE            1
#define SEARCH_NODE_COMPLETE   2
#define SEARCH_FILE            3
#define SEARCH_KEYWORD         4
#define SEARCH_NOTES           5
#define SEARCH_STORE_FILE      6
#define SEARCH_STORE_KEYWORD   7
#define SEARCH_STORE_NOTES     8
#define SEARCH_FIND_BUDDY      9
#define SEARCH_FIND_SOURCE     10
#define SEARCH_NODE_SPECIAL    11
#define SEARCH_NODE_FWCHECKUDP 12

#define SEARCH_REQ_CONTACTS_FIND_VALUE 0x02
#define SEARCH_REQ_CONTACTS_STORE      0x04
#define SEARCH_REQ_CONTACTS_FIND_NODE  0x0b

// Intervals in ms

#define SEARCH_LIFETIME_NODE          SEC2MS(45)
#define SEARCH_LIFETIME_NODECOMP      SEC2MS(10)
#define SEARCH_LIFETIME_KEYWORD       SEC2MS(45)
#define SEARCH_LIFETIME_FILE          SEC2MS(45)
#define SEARCH_LIFETIME_STORE_FILE    SEC2MS(140)
#define SEARCH_LIFETIME_STORE_KEYWORD SEC2MS(140)

#define SEARCH_TOTAL_NODECOMP       10
#define SEARCH_TOTAL_KEYWORD        300
#define SEARCH_TOTAL_FILE           300
#define SEARCH_TOTAL_STORE_KEYWORD  10
#define SEARCH_TOTAL_STORE_FILE     10

#define ALPHA_QUERY 3

typedef void (*KAD_SEARCH_RESULT_KEYWORD_CB)(void* arg, uint32_t search_id, char* file_name, uint64_t file_size, char* file_type, uint64_t length);

typedef struct _search_keyword_result {
  UINT128 id;
  char* file_name;
  uint64_t file_size;
  char* file_type;
  char* file_format;
  char* artist;
  char* album;
  char* title;
  uint64_t length;
  uint64_t bitrate;
  char* codec;
  uint16_t avail;
  uint32_t publish_info;
  char buf[1]; // All structure pointers point to some place in this buffer.
} SEARCH_KEYWORD_RESULT;

typedef struct search_file_result {
  uint8_t type;
  UINT128 id;
  uint32_t ip4;
  uint16_t tcp_port;
  uint16_t udp_port;
  uint32_t buddy_ip4;
  uint16_t buddy_port;
  UINT128 buddy_id;
  uint8_t cipher_opts;
} SEARCH_FILE_RESULT;

typedef struct kad_search {
  uint32_t created;
  uint32_t type;
  uint32_t answers;
  uint32_t total_request_answers;
  uint32_t id;
  bool stopping;
  uint32_t last_response;
  UINT128 target_id;
  uint8_t* search_terms_data;
  uint32_t search_terms_data_len;

  // All nodes lists contain NODE_LIST_ENTRY* values.
  LIST* nodes_in_use; // List of all nodes used for current search.
  LIST* nodes_to_try; // On start contain same nodes as in nodes_in_use list, as search continue tried nodes will
                      // be deleted from this list.
  LIST* nodes_tried;  // Contains nodes from nodes_in_use, nodes to which request was sent.
  LIST* nodes_resp;   // Contains nodes from nodes_in_use and nodes_tried, responded nodes.
  LIST* nodes_best;   // Contains nodes from nodes_in_use nodes_tried and nodes_resp, responded nodes with best dist.
  LIST* keywd_results;
  LIST* file_results;
  char* file_name;
  uint64_t file_size;
  void* kw_res_cb_arg;
  KAD_SEARCH_RESULT_KEYWORD_CB kw_res_cb;
} KAD_SEARCH;

#define SEARCH_LOCK(kse)

#define SEARCH_UNLOCK(kse)

bool
kad_search_create(
                  uint32_t type,
                  KAD_SEARCH** kse_out
                 );

bool
kad_search_destroy(
                   KAD_SEARCH* kse
                   );

bool
kad_search_free_nodes_lists(
                            KAD_SEARCH* kse
                           );

bool
kad_search_contacts_count(
                          uint32_t type
                         );

bool
kad_search_find_by_target(
                          UINT128* target,
                          LIST* kse_lst,
                          KAD_SEARCH** kse_out
                         );

bool
kad_search_already_going(
                         UINT128* id,
                         LIST** kse_lst_ptr
                         );

bool
kad_search_find_in_ongoing_by_targ_id(
                                      UINT128* id,
                                      LIST** kse_lst_ptr,
                                      KAD_SEARCH** kse_out
                                      );

bool
kad_search_add_ongoing(
                       KAD_SEARCH* kse,
                       LIST** kse_lst_ptr
                      );

bool
kad_search_delete_from_ongoing(
                               KAD_SEARCH* kse,
                               LIST** kse_lst_ptr
                               );

bool
kad_search_delete_all_from_ongoing(
                                   LIST** kse_lst_ptr
                                  );

bool
kad_search_send_find_node_pkt(
                              KAD_SESSION* ks,
                              KAD_SEARCH* kse,
                              KAD_NODE* kn,
                              UINT128* id_to_find
                              );

bool
kad_search_start(
                 KAD_SESSION* ks,
                 ROUTING_ZONE* rz,
                 UINT128* self_id,
                 UINT128* id_to_find,
                 KAD_SEARCH* kse,
                 LIST** kse_lst_ptr
                );

bool
kad_search_find_node(
                     KAD_SESSION* ks,
                     ROUTING_ZONE* rz,
                     UINT128* self_id,
                     UINT128* id_to_find,
                     bool complete,
                     LIST** kse_lst_ptr
                    );

bool
kad_search_prepare_to_stop(
                           KAD_SEARCH* kse
                          );

bool
kad_search_find_node_for_fw_check(
                                  KAD_SESSION* ks,
                                  ROUTING_ZONE* rz,
                                  UINT128* self_id,
                                  LIST** kse_lst_ptr
                                 );

bool
kad_search_add_terms(
                     KAD_SEARCH* kse,
                     char* keywd,
                     uint32_t keywd_len
                    );

bool
kad_search_find_keyword(
                        KAD_SESSION* ks,
                        ROUTING_ZONE* rz,
                        UINT128* self_id,
                        char* keywd,
                        uint32_t keywd_len,
                        LIST** kse_lst_ptr,
                        void* res_cb_arg,
                        KAD_SEARCH_RESULT_KEYWORD_CB res_cb

                        );

bool
kad_search_store_keyword(
                         KAD_SESSION* ks,
                         ROUTING_ZONE* rz,
                         UINT128* self_id,
                         char* keywd,
                         uint32_t keywd_len,
                         LIST** kse_lst_ptr
                        );

bool
kad_search_store_file(
                      KAD_SESSION* ks,
                      ROUTING_ZONE* rz,
                      UINT128* self_id,
                      UINT128* file_id,
                      LIST** kse_lst_ptr
                     );

bool
kad_search_find_file(
                     KAD_SESSION* ks,
                     ROUTING_ZONE* rz,
                     UINT128* self_id,
                     UINT128* file_id,
                     char* file_name,
                     uint64_t file_size,
                     LIST** kse_lst_ptr
                    );

bool
kad_search_process_response(
                            KAD_SESSION* ks,
                            UINT128* targ_id,
                            uint32_t ip4_no,
                            uint16_t udp_port_no,
                            LIST* resp_kn_lst,
                            LIST** kse_lst_ptr
                           );

bool
kad_search_process_last_node_response(
                                      KAD_SESSION* ks,
                                      KAD_SEARCH* kse,
                                      NODE_LIST_ENTRY* nle
                                     );

bool
kad_search_jump_start(
                      KAD_SESSION* ks,
                      KAD_SEARCH* kse
                     );

bool
kad_search_expire(
                  KAD_SEARCH* kse,
                  LIST** expired_kse_lst
                  );

bool
kad_search_jumpstart_all(
                         KAD_SESSION* ks,
                         LIST** kse_lst_ptr
                        );

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
                              );

bool
kad_search_check_file_result(
                             KAD_SEARCH* kse,
                             SEARCH_FILE_RESULT* chk_file_res
                            );

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
                          );

bool
kad_search_process_result_keyword(
                                  KAD_SESSION* ks,
                                  KAD_SEARCH* kse,
                                  UINT128* answer,
                                  LIST* tag_lst
                                 );

bool
kad_search_process_result_file(
                               KAD_SESSION* ks,
                               KAD_SEARCH* kse,
                               UINT128* resp_id,
                               LIST* tag_lst
                               );

bool
kad_search_process_result(
                          KAD_SESSION* ks,
                          UINT128* trgt_id,
                          UINT128* resp_id,
                          LIST* tag_lst
                         );

bool
kad_search_is_udp_fw_check(
                           KAD_SESSION* ks,
                           UINT128* trgt_id
                           );



#endif // _KADSRCH_H_
