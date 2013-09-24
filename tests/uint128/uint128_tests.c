#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
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

  LOG_DEBUG_UINT128("uint128:", ((UINT128*)&ui128));

  uint128_from_buffer(
                      &ui128,
                      buf,
                      sizeof(buf),
                      true
                      );

  LOG_DEBUG_UINT128("uint128:", ((UINT128*)&ui128));

}

void test_uint128_generate(void **state)
{
  UINT128 ui128;

  random_init();

  uint128_generate(&ui128);

  LOG_DEBUG_UINT128("Generated uint128", ((UINT128*)&ui128));

}

void test_uint128_xor(void **state)
{
  uint8_t buffer[UINT128_BYTES_COUNT];
  UINT128 f;
  UINT128 s;
  UINT128 r;

  for (uint8_t i = 0; i < sizeof(buffer); i++) {

    buffer[i] = i;

  }

  uint128_from_buffer(&f, buffer, sizeof(buffer), false);

  uint128_from_buffer(&s, buffer, sizeof(buffer), false);

  uint128_xor(&f, &s, &r);

  LOG_DEBUG_UINT128("xor result:", ((UINT128*)&r));

  for (uint8_t i = 0; i < UINT128_DWORDS_COUNT; i++){

    assert_int_equal(r.data.dwordData[i], 0);

  }
  
}

void
test_uint128_set_bit_value(void** state)
{
  UINT128 f;
  uint32_t acc = 0;

  memset(&f, 0, sizeof(UINT128));

  for (uint8_t i = 0; i < UINT128_BYTES_COUNT * 8; i++) {

    uint128_set_bit_value(&f, i, 1);

    LOG_DEBUG_UINT128("uint128", ((UINT128*)&f));

    acc <<= 1;

    acc |= 1;

    assert_int_equal(f.data.dwordData[3 - i / 32], acc);

    if (acc == 0xffffffff) acc = 0;

  }
  
}

void
test_uint128_get_bit_string(void** state)
{
  UINT128 f;
  char buf[UINT128_BYTES_COUNT * 8 + 1];


  memset(&f, 0, sizeof(UINT128));

  memset(buf, 0, sizeof(buf));

  for (uint8_t i = 0; i < UINT128_BYTES_COUNT * 8; i++){

    uint128_set_bit_value(&f, i, 1);

    assert_int_equal(1, uint128_get_bit_string(&f, buf, sizeof(buf)));

    assert_int_equal(0x31, buf[UINT128_BYTES_COUNT * 8 - 1 - i]);

    LOG_DEBUG_UINT128("uint128", ((UINT128*)&f))

    LOG_DEBUG("%s", buf);

  }
  
}

void
test_uint128_get_bit_value(void** state)
{
  UINT128 f;

  memset(&f, 0, sizeof(f));

  for (uint8_t i = 0; i < (UINT128_BYTES_COUNT * 8); i++) {

    uint128_set_bit_value(&f, i, 1);

    LOG_DEBUG_UINT128("uint128", ((UINT128*)&f));
      
    assert_int_equal(uint128_get_bit_value(&f, i), 1);

  }

}

void
test_uint128_get_bit_value_reverse(void** state)
{
  UINT128 f;

  memset(&f, 0, sizeof(f));

  for (uint8_t i = 0; i < UINT128_BYTES_COUNT * 8; i++){
  
    uint128_set_bit_value(&f, i, 1);

    LOG_DEBUG_UINT128("uint128", ((UINT128*)&f));

    assert_int_equal(1, uint128_get_bit_value_reverse(&f, UINT128_BYTES_COUNT * 8 - 1 - i));

  }

}

void
test_uint128_set_bit_value_reverse(void** state)
{
  UINT128 f;

  memset(&f, 0, sizeof(f));
  
  for (uint8_t i = 0; i < UINT128_BYTES_COUNT * 8; i++){
  
    uint128_set_bit_value_reverse(&f, i, 1);

    LOG_DEBUG_UINT128("uint128", ((UINT128*)&f));

    assert_int_equal(1, uint128_get_bit_value_reverse(&f, i));

  }

}

void
test_uint128_compare(void** state)
{
  UINT128 f;
  UINT128 s;

  memset(&f, 0, sizeof(f));

  memset(&s, 0, sizeof(f));

  uint128_set_bit_value_reverse(&f, 2, 1);

  assert_int_equal(1, uint128_compare(&f, &s));

  uint128_set_bit_value_reverse(&s, 1, 1);

  assert_int_equal(0xff, uint128_compare(&f, &s));

}

void
test_uint128_shift_left(void** state)
{
  UINT128 f;
  UINT128 s;

  memset(&f, 0, sizeof(f));

  memset(&s, 0, sizeof(s));

  uint128_set_bit_value(&f, 0, 1);

  uint128_set_bit_value(&s, 5, 1);

  LOG_DEBUG_UINT128("before shift", ((UINT128*)&f));

  LOG_DEBUG_UINT128("before shift", ((UINT128*)&s));

  uint128_shift_left(&f, 6, NULL);

  uint128_shift_left(&s, 1, NULL);

  LOG_DEBUG_UINT128("after shift", ((UINT128*)&f));

  LOG_DEBUG_UINT128("after shift", ((UINT128*)&s));

  assert_int_equal(0, uint128_compare(&f, &s));

}

void
test_uint128_add(void** state)
{
  UINT128 f;
  UINT128 s;
  UINT128 r;

  memset(&f, 0, sizeof(f));

  memset(&s, 0, sizeof(s));

  f.data.dwordData[3] = 0xffffffff;

  s.data.dwordData[3] = 0xffffffff;

  uint128_add(&f, &s, &r);

  assert_int_equal(0xfffffffe, r.data.dwordData[3]);

  assert_int_equal(0x1, r.data.dwordData[2]);

  LOG_DEBUG_UINT128("f:", ((UINT128*)&f));

  LOG_DEBUG_UINT128("s:", ((UINT128*)&s));

  LOG_DEBUG_UINT128("r:", ((UINT128*)&r));

}

void
test_uint128_substract(void** state)
{
  UINT128 f;
  UINT128 s;
  UINT128 r;
  
  memset(&f, 0, sizeof(f));

  memset(&s, 0, sizeof(s));

  f.data.dwordData[3] = 1;

  s.data.dwordData[3] = 2;

  uint128_substract(&f, &s, &r);

  LOG_DEBUG_UINT128("sub res:", ((UINT128*)&r)); 

  for (uint8_t i = 0; i < UINT128_DWORDS_COUNT; i++){

    assert_int_equal(0xffffffff, r.data.dwordData[i]);

  }

}

void
test_uint128_copy_bits_be(void** state)
{
  UINT128 s;
  UINT128 d;
  UINT128 d2;

  uint128_init(&s, 0xff);

  uint128_zero_init(&d);

  uint128_copy_bits_be(&s, &d, 16, false);

  assert_int_equal(0xffff, d.data.wordData[1]);

  LOG_DEBUG_UINT128("dst", ((UINT128*)&d));

  uint128_copy_bits_be(&s, &d2, 32, true);

  assert_int_equal(0xffffffff, d2.data.dwordData[0]);

  LOG_DEBUG_UINT128("dst2", ((UINT128*)&d2));
}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_uint128_generate),
    unit_test(test_uint128_from_buffer),
    unit_test(test_uint128_xor),
    unit_test(test_uint128_set_bit_value),
    unit_test(test_uint128_get_bit_value),
    unit_test(test_uint128_get_bit_value_reverse),
    unit_test(test_uint128_set_bit_value_reverse),
    unit_test(test_uint128_get_bit_string),
    unit_test(test_uint128_compare),
    unit_test(test_uint128_shift_left),
    unit_test(test_uint128_add),
    unit_test(test_uint128_substract),
    unit_test(test_uint128_copy_bits_be)
  };

  return run_tests(tests);
}
