#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <mem.h>
#include <random.h>
#include <list.h>
#include <queue.h>
#include <uint128.h>
#include <node.h>
#include <nodelist.h>
#include <pktasm.h>
#include <tag.h>
#include <packet.h>
#include <kadpkt.h>
#include <kadqpkt.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_kadqpkt_alloc_destroy(void** state)
{
  KAD_QUEUED_PACKET* qp = NULL;
  uint8_t pkt[10] = {0};
  void* ppkt = pkt;

  assert_true(kadqpkt_alloc(0, 0, ppkt, sizeof(pkt), &qp));

  assert_true(kadqpkt_destroy(qp));

}

void
test_kadqpkt_create_udp(void** state)
{
  KAD_QUEUED_PACKET* qp = NULL;
  uint8_t pkt[10] = {0};
  void* ppkt = pkt;
  UINT128 id;

  assert_true(kadqpkt_create_udp(&id, 0, 0, ppkt, sizeof(pkt), &qp));
}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kadqpkt_alloc_destroy)
  };

  return run_tests(tests);
}
