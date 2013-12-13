#ifndef _KAD_H_
#define _KAD_H_

bool
kad_session_init(
                 uint16_t tcp_port,
                 uint16_t udp_port,
                 char* nodes_file_path,
                 KAD_SESSION** ks_out
                 );

bool
kad_session_uninit(
                   KAD_SESSION* ks
                   );

bool
kad_session_set_id(
                   KAD_SESSION* ks,
                   UINT128* id
                  );

bool
kad_session_update(
                   KAD_SESSION* ks,
                   uint32_t now
                   );

bool
kad_timer(KAD_SESSION* ks);

bool
kad_handle_control_packet(
                          KAD_SESSION* ks,
                          uint8_t* pkt,
                          uint32_t pkt_len,
                          uint32_t ip4_no,
                          uint16_t port_no,
                          bool valid_rcvr_key,
                          uint32_t sndr_verify_key
                          );

bool
kad_get_control_packet_to_send(
                               KAD_SESSION* ks,
                               uint32_t* ip4_no_out,
                               uint16_t* port_no_out,
                               void** pkt_out,
                               uint32_t* pkt_len_out
                               );

bool
kad_control_packet_received(
                            KAD_SESSION* ks,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            void* ctrl_pkt,
                            uint32_t ctrl_pkt_len
                            );

bool
kad_deq_and_handle_control_packet(
                                  KAD_SESSION* ks
                                  );

#endif // _KAD_H_
