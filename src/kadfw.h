#ifndef _KADFW_H_
#define _KADFW_H_

#define KAD_UDPFWCHECK_CLIENTS_TO_ASK 2
#define KAD_FIREWALL_CHECKS_SIMUL     4

#define FW_NODES_LOCK(fw)
#define FW_NODES_UNLOCK(fw)

typedef struct _kad_fw {
  bool udp_check_running;
  uint32_t udp_checks_finished_cnt;
  uint32_t udp_checks_running_cnt;
  uint32_t tcp_checks_running_cnt;
  LIST* extrn_port_asked_ips;
  LIST* extrn_ports;
  bool extrn_udp_port_valid;
  uint16_t extrn_udp_port;
  LIST* nodes_for_udp_check;
  LIST* nodes_used_for_udp_check;
  bool udp_firewalled;
  bool firewalled;
} KAD_FW;

typedef struct _udp_fw_check_node {
  KAD_NODE kn;
  bool answered;
  bool ext_port_answer;
  bool int_port_answer;
} UDP_FW_CHECK_NODE;

bool
kad_fw_init(
            KAD_FW* kfw 
            );

bool
kad_fw_free_nodes_for_udp_check(
                                KAD_FW* kfw
                               );

bool
kad_fw_destroy(
               KAD_FW* kfw
              );

bool
kad_fw_set_extrn_port(
                      KAD_FW* kfw,
                      uint32_t ip4_no,
                      uint32_t new_port
                     );

bool
kad_fw_get_extrn_port(
                      KAD_FW* kfw,
                      uint16_t* ext_prt_out
                     );

bool
kad_fw_extrn_port_valid(
                        KAD_FW* kfw
                       );

bool
kad_fw_udp_check_started(
                         KAD_FW* kfw
                        );

bool
kad_fw_udp_check_running(
                         KAD_FW* kfw
                        );

bool
kad_fw_add_node_for_udp_check(
                              KAD_FW* kfw,
                              void* kn
                              );

bool
kad_fw_firewalled(
                  KAD_FW* kfw
                 );

bool
kad_fw_firewalled_udp(
                      KAD_FW* kfw
                      );

bool
kad_fw_set_status(
                  KAD_FW* kfw,
                  bool firewalled
                 );

bool
kad_fw_set_status_udp(
                      KAD_FW* kfw,
                      bool firewalled
                     );

bool
kad_fw_need_more_udp_checks(
                            KAD_FW* kfw
                            );
bool
kad_fw_udp_check_request(
                         void* hks
                        );

bool
kad_fw_udp_check_response(
                          KAD_FW* fw,
                          bool already_known,
                          uint32_t ip4_no,
                          uint16_t int_port,
                          uint16_t inc_port,
                          bool* answ_to_int_port_out,
                          bool* answ_to_ext_port_out
                         );

bool
kad_fw_check_response(
                      KAD_FW* fw
                     );

bool
kad_fw_dec_checks_running(
                          KAD_FW* fw
                         );

bool
kad_fw_dec_checks_running_udp(
                              KAD_FW* fw
                             );

bool
kad_fw_add_source_for_inbound_tcp_check(
                                        void* hks,
                                        KAD_FW* fw,
                                        UINT128* id,
                                        uint32_t ip4_no,
                                        uint16_t tcp_port,
                                        uint16_t udp_port
                                       );

bool
kad_fw_need_more_tcp_checks(
                            KAD_FW* kfw
                            );

#endif // _KADFW_H_
