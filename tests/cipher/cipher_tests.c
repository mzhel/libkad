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
#include <cipher.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_cipher_encrypt_decrypt(void** state)
{
  char data[] = "Test message.";
  uint8_t* pkt = NULL;
  uint32_t pkt_len = 0;
  uint8_t* enc_pkt = NULL;
  uint32_t enc_pkt_len = 0;
  uint8_t* dec_pkt = NULL;
  uint32_t dec_pkt_len = 0;
  UINT128 id;
  uint32_t rcvr_key = 0;
  uint32_t sndr_key = 0;

  uint128_generate(&id);

  rcvr_key = random_uint32();

  sndr_key = random_uint32();

  pkt_len = strlen(data);

  pkt = mem_alloc(pkt_len);

  assert_true(pkt);

  strcpy((char*)pkt, data);

  assert_true(cipher_encrypt_packet(
                                    pkt,
                                    pkt_len,
                                    NULL,
                                    rcvr_key,
                                    sndr_key,
                                    &enc_pkt,
                                    &enc_pkt_len
                                    )
              );


  mem_free(pkt);

  mem_free(enc_pkt);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_cipher_encrypt_decrypt)
  };

  return run_tests(tests);
}
