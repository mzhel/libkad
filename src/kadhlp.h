#ifndef _KADHLP_H_
#define _KADHLP_H_

bool
kadhlp_id_from_string(
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
kadhlp_send_ping_pkt_to_rand_node(
                                  KAD_SESSION* ks
                                 );

bool
kadhlp_send_bs_req_pkt_to_rand_node(
                                    KAD_SESSION* ks
                                   );

bool
kadhlp_calc_udp_verify_key(
                           uint32_t udp_key,
                           uint32_t ip4_no,
                           uint32_t* verify_key_out
                          );

#endif // _KADHLP_H_
