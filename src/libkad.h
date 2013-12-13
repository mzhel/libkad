#ifndef _LIBKAD_H_
#define _LIBKAD_H_

typedef struct _kad_session KAD_SESSION;

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
kad_session_update(
                   KAD_SESSION* ks,
                   uint32_t now
                   );

bool
kad_timer(KAD_SESSION* ks);

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

#endif //_LIBKAD_H_
