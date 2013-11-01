#ifndef _KADPROTO_H_
#define _KADPROTO_H_

#define BOOTSTRAP_CONTACTS_COUNT 20

bool
kadproto_kademlia2_bootstrap_req(
                                 KAD_SESSION* ks,
                                 uint32_t ip4_no,
                                 uint16_t port_no,
                                 uint32_t sender_key
                                 );

bool
kadproto_kademlia2_bootstrap_res(
                                 KAD_SESSION* ks,
                                 uint8_t* pkt_data,
                                 uint32_t pkt_data_len,
                                 uint32_t ip4_no,
                                 uint16_t port_no,
                                 uint32_t sender_key,
                                 bool ip_verified
                                );

bool
kadproto_kademlia2_req(
                       KAD_SESSION* ks,
                       uint8_t* pkt_data,
                       uint32_t pkt_data_len,
                       uint32_t ip4_no,
                       uint16_t port_no,
                       uint32_t sender_key
                      );

bool
kadproto_kademlia2_res(
                       KAD_SESSION* ks,
                       uint8_t* pkt_data,
                       uint32_t pkt_data_len,
                       uint32_t ip4_no,
                       uint16_t port_no
                      );

bool
kadproto_kademlia2_search_source_req(
                                     KAD_SESSION* ks,
                                     uint8_t* pkt_data,
                                     uint32_t pkt_data_len,
                                     uint32_t ip4_no,
                                     uint16_t port_no,
                                     uint32_t sender_key
                                    );

bool
kadproto_kademlia_ping(
                       KAD_SESSION* ks,
                       uint32_t ip4_no,
                       uint16_t port_no,
                       uint32_t sender_key
                      );

bool
kadproto_kademlia2_pong(
                        KAD_SESSION* ks,
                        uint8_t* pkt_data,
                        uint32_t pkt_data_len,
                        uint32_t ip4_no,
                        uint16_t port_no
                       );

bool
kadproto_kademlia2_search_res(
                              KAD_SESSION* ks,
                              uint8_t* pkt_data,
                              uint32_t pkt_data_len,
                              uint32_t sender_key
                              );

bool
kadproto_kademlia2_hello_req(
                             KAD_SESSION* ks,
                             uint8_t* pkt_data,
                             uint32_t pkt_data_len,
                             uint32_t ip4_no,
                             uint16_t port_no,
                             bool valid_rcvr_key,
                             uint32_t sndr_key
                             );

bool
kadproto_kademlia2_hello_res(
                             KAD_SESSION* ks,
                             uint8_t* pkt_data,
                             uint32_t pkt_data_len,
                             uint32_t ip4_no,
                             uint16_t port_no,
                             bool valid_rcvr_key,
                             uint32_t sndr_key
                            );

bool
kadproto_kademlia2_fw_udp(
                          KAD_SESSION* ks,
                          uint8_t* pkt_data,
                          uint32_t pkt_data_len,
                          uint32_t ip4_no,
                          uint16_t port_no
                         );

bool
kadproto_kademlia2_firewalled_res(
                                  KAD_SESSION* ks,
                                  uint8_t* pkt_data,
                                  uint32_t pkt_data_len,
                                  uint32_t ip4_no,
                                  uint16_t port_no
                                 );












#endif // _KADPROTO_H_

