#ifndef _KADPKT_H_
#define _KADPKT_H_

bool
kadpkt_create_bootstrap(
                        void** raw_pkt_out,
                        uint32_t* raw_pkt_len_out
                        );

bool
kadpkt_create_search(
                     uint8_t cont_cnt,
                     UINT128* search_id,
                     UINT128* node_id,
                     void** raw_pkt_out,
                     uint32_t* raw_pkt_len_out
                    );

bool
kadpkt_create_ping(
                   void** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                   );

bool
kadpkt_create_pong(
                   uint16_t port_from_no,
                   void** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                  );

bool
kadpkt_create_bootstrap_res(
                            UINT128* self_kad_id,
                            uint16_t tcp_port,
                            LIST* kn_lst,
                            void** raw_pkt_out,
                            uint32_t* raw_pkt_len_out
                           );

bool
kadpkt_create_hello(
                    UINT128* self_kad_id,
                    uint16_t tcp_port,
                    uint16_t udp_port,
                    uint8_t opcode,
                    uint8_t target_kad_ver,
                    uint32_t target_udp_key,
                    UINT128* target_id,
                    bool req_ack_pkt,
                    bool fw,
                    bool fw_udp,
                    void** raw_pkt_out,
                    uint32_t* raw_pkt_len_out
                    );

#define kadpkt_create_hello_req(a, b, c, d, e, f, g, h, i, j, k) kadpkt_create_hello(a, b, c, d, KADEMLIA2_HELLO_REQ, e, f, g, h, i, j, k)

#define kadpkt_create_hello_res(a, b, c, d, e, f, g, h, i, j, k) kadpkt_create_hello(a, b, c, d, KADEMLIA2_HELLO_RES, e, f, g, h, i, j, k)

bool
kadpkt_create_hello_ack(
                        UINT128* self_kad_id,
                        void** raw_pkt_out,
                        uint32_t* raw_pkt_len_out
                       );

bool
kadpkt_parse_hello(
                   uint8_t* pkt,
                   uint32_t pkt_len,
                   UINT128* kn_id_out,
                   uint16_t* tcp_port_out,
                   uint16_t* udp_port_out,
                   uint8_t* ver_out,
                   bool* udp_fw_out,
                   bool* tcp_fw_out,
                   bool* ack_needed_out
                  );

bool
kadpkt_create_search_response(
                              UINT128* target,
                              LIST* kn_lst,
                              void** raw_pkt_out,
                              uint32_t* raw_pkt_len_out
                             );

bool
kadpkt_create_search_key_req(
                             UINT128* target,
                             uint8_t* search_terms_data,
                             uint32_t search_terms_data_size,
                             void** raw_pkt_out,
                             uint32_t* raw_pkt_len_out
                            );

bool
kadpkt_create_search_source_req(
                                UINT128* file_id,
                                uint64_t file_size,
                                void** raw_pkt_out,
                                uint32_t* raw_pkt_len_out
                               );

bool
kadpkt_create_fw_check(
                       uint16_t tcp_port,
                       UINT128* cli_hash,
                       uint8_t conn_opts,
                       void** raw_pkt_out,
                       uint32_t* raw_pkt_len_out
                      );

bool
kadpkt_create_fw_check_udp(
                           bool already_known,
                           uint16_t port,
                           void** raw_pkt_out,
                           uint32_t* raw_pkt_len_out
                          );

#endif // _KADPKT_H_
