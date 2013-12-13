#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <netdb.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <tag.h>
#include <protocols.h>
#include <packet.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadhlp.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <kad.h>
#include <random.h>
#include <ticks.h>
#include <cipher.h>
#include <comprs.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_kad_timer(void** state)
{
  KAD_SESSION* ks;
  uint32_t ip4_no;
  uint16_t port_no;
  void* pkt;
  uint32_t pkt_len;

  assert_true(kad_session_init(3001, 3002, "nodes.dat", &ks));

  kad_timer(ks);

  assert_true(kad_get_control_packet_to_send(
                                             ks,
                                             &ip4_no,
                                             &port_no,
                                             &pkt,
                                             &pkt_len
                                             )
  );

  assert_true(kad_control_packet_received(ks, kadses_get_pub_ip(ks), htons(ks->udp_port), pkt, pkt_len));

  mem_free(pkt);

  assert_true(kad_deq_and_handle_control_packet(ks));

  kad_session_uninit(ks);

}

void test_kad_packets(void** state)
{
  KAD_SESSION* ks1;
  KAD_SESSION* ks2;

  assert_true(kad_session_init(3001, 3002, "nodes.dat", &ks1));

  assert_true(kad_session_init(3003, 3004, "nodes.dat", &ks2));

  kad_session_uninit(ks1);

  kad_session_uninit(ks2);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kad_timer)
  };

  return run_tests(tests);
}
