#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <uint128.h>
#include <random.h>
#include <cmockery.h>

#include <log.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_uint128_from_buffer(void **state)
{
  uint8_t buf[UINT128_BYTES_COUNT];
  UINT128 ui128;

  for (uint8_t i = 0; i < UINT128_BYTES_COUNT; i++){

    buf[i] = i;

  }

  uint128_from_buffer(
                      &ui128,
                      buf,
                      sizeof(buf),
                      false
                      );

  LOG_DEBUG_UINT128("uint128:", (UINT128*)(&ui128));

  uint128_from_buffer(
                      &ui128,
                      buf,
                      sizeof(buf),
                      true
                      );

  LOG_DEBUG_UINT128("uint128:", (UINT128*)(&ui128));

}

void test_generate_uint128(void **state)
{
  UINT128 ui128;

  random_init();

  uint128_generate(&ui128);

  LOG_DEBUG_UINT128("Generated uint128", (&ui128));

}

void test_xor_uint128(void **state)
{
  UINT128 f;
  UINT128 s;
  UINT128 r;

  
  
}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_uint128_from_buffer)
  };

  return run_tests(tests);
}
