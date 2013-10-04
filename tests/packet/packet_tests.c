#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <mem.h>
#include <packet.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_packet_create_destroy(void** state)
{
  uint8_t data[5] = {1,2,3,4,5};
  KAD_PACKET* kp = NULL;

  assert_true(pkt_create(data, 5, PACKET_EMIT_TYPE_TCP, KADEMLIA2_PING, &kp));

  assert_true(pkt_destroy(kp));

}

void
test_packet_emit(void** state)
{
  uint8_t data[5] = {1,2,3,4,5};
  KAD_PACKET* kp = NULL;
  uint8_t* emit_buf;
  uint32_t io_bytes = 0;

  emit_buf = mem_alloc(20);

  assert_true(pkt_create(data, 5, PACKET_EMIT_TYPE_TCP, KADEMLIA2_PING, &kp));

  assert_true(pkt_emit(kp, emit_buf, 20, &io_bytes));

  assert_int_equal(7, io_bytes);

  assert_true(pkt_destroy(kp));

  mem_free(emit_buf);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_packet_create_destroy),
    unit_test(test_packet_emit)
  };

  return run_tests(tests);
}
