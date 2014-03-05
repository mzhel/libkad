#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <pthread.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <log.h>
#include <node.h>
#include <kbucket.h>
#include <routing.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadusr.h>

bool
kadusr_init(
            KAD_SESSION* ks
           )
{
  bool result = false;

  do {

    if (!ks) break;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_uninit(
              KAD_SESSION* ks
             )
{
  bool result = false;

  do {

    if (!ks) break;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_local_ip(
                    KAD_SESSION* ks,
                    uint32_t loc_ip4_no
                   )
{
  bool result = false;

  do {

    ks->kud.loc_ip4_no = loc_ip4_no;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_public_ip(
                     KAD_SESSION* ks,
                     uint32_t pub_ip4_no
                    )
{
  bool result = false;

  do {

    ks->kud.pub_ip4_no = pub_ip4_no;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_nodes_count(
                       KAD_SESSION* ks,
                       uint32_t nodes_count
                      )
{
  bool result = false;

  do {

    ks->kud.nodes_count = nodes_count;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_int_udp_port_no(
                           KAD_SESSION* ks,
                           uint32_t int_udp_port_no
                          )
{
  bool result = false;

  do {

    ks->kud.int_udp_port_no = int_udp_port_no;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_ext_udp_port_no(
                           KAD_SESSION* ks,
                           uint32_t ext_udp_port_no
                          )
{
  bool result = false;

  do {

    ks->kud.ext_udp_port_no = ext_udp_port_no;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_set_tcp_firewalled(
                          KAD_SESSION* ks,
                          bool firewalled
                         )
{
  bool result = false;

  do {

    ks->kud.tcp_firewalled = firewalled;

    result = true;

  } while (false);

  return result;
}

bool
kadusr_get_data(
                KAD_SESSION* ks,
                KAD_USER_DATA* kud
               )
{
  bool result = false;

  do {

    if (!ks || !kud) break;

    memcpy(kud, &ks->kud, sizeof(KAD_USER_DATA));

    result = true;

  } while (false);

  return result;
}
