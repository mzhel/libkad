#ifndef _KADUSR_H_
#define _KADUSR_H_

bool
kadusr_init(
            KAD_SESSION* ks
           );

bool
kadusr_uninit(
              KAD_SESSION* ks
             );

bool
kadusr_set_local_ip(
                    KAD_SESSION* ks,
                    uint32_t loc_ip4_no
                   );

bool
kadusr_set_public_ip(
                     KAD_SESSION* ks,
                     uint32_t pub_ip4_no
                    );

bool
kadusr_set_nodes_count(
                       KAD_SESSION* ks,
                       uint32_t nodes_count
                      );

bool
kadusr_set_int_udp_port_no(
                           KAD_SESSION* ks,
                           uint32_t int_udp_port_no
                          );

bool
kadusr_set_ext_udp_port_no(
                           KAD_SESSION* ks,
                           uint32_t ext_udp_port_no
                          );

bool
kadusr_set_tcp_firewalled(
                          KAD_SESSION* ks,
                          bool firewalled
                         );

bool
kadusr_get_data(
                KAD_SESSION* ks,
                KAD_USER_DATA* kud
               );

#endif // _KADUSR_H_
