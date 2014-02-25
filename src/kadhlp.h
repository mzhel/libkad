#ifndef _KADHLP_H_
#define _KADHLP_H_

bool
kadhlp_id_from_string(
                      KAD_SESSION* ks,
                      char* str,
                      uint32_t str_len,
                      UINT128* kad_id
                     );

bool
kadhlp_find_kn_in_nle_list(
                           LIST** nle_lst_ptr,
                           UINT128* dist,
                           KAD_NODE** kn_out
                          );

bool
kadhlp_send_ping_pkt_to_node(
                             KAD_SESSION* ks,
                             KAD_NODE* kn
                             );

bool
kadhlp_send_ping_pkt_to_rand_node(
                                  KAD_SESSION* ks
                                  );

bool
kadhlp_send_bs_req_pkt_to_rand_node(
                                    KAD_SESSION* ks
                                    );

bool
kadhlp_send_bootstrap_pkt(
                          KAD_SESSION* ks,
                          uint32_t ip4_no,
                          uint16_t port_no
                          );

bool
kadhlp_send_hello_req_pkt_to_node(
                                 KAD_SESSION* ks,
                                 KAD_NODE* kn
                                 );

bool
kadhlp_send_fw_check_udp(
                         KAD_SESSION* ks,
                         uint16_t check_port,
                         uint32_t key,
                         uint32_t ip4_no
                        );

bool
kadhlp_send_fw_check_tcp(
                         KAD_SESSION* ks,
                         UINT128* node_id,
                         uint32_t ip4_no,
                         uint16_t port_no,
                         uint32_t sender_key,
                         uint16_t tcp_port
                        );

bool
kadhlp_calc_udp_verify_key(
                           KAD_SESSION* ks,
                           uint32_t udp_key,
                           uint32_t ip4_no,
                           uint32_t* verify_key_out
                          );

bool
kadhlp_gen_udp_key(
                   uint32_t* udp_key_out
                  );

bool
kadhlp_destroy_qpkt_queue(
                          KAD_SESSION* ks,
                          QUEUE* q
                          );

bool
kadhlp_parse_nodes_dat(
                       KAD_SESSION* ks,
                       char* file_path,
                       LIST** kn_lst_out
                       );

bool
kadhlp_add_nodes_from_file(
                           KAD_SESSION* ks,
                           char* file_path
                           );

#endif // _KADHLP_H_
