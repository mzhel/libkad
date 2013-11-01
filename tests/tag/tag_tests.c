#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <mem.h>
#include <tag.h>
#include <cmockery.h>
#include <log.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_tag_create_emit_read_destroy(void** state)
{
  TAG* tag = NULL;
  TAG* tag2 = NULL;
  uint8_t buf[1024];
  uint32_t bytes_emited = 0;
  uint32_t bytes_read = 0;

  memset(buf, 0, sizeof(buf));

  assert_true(tag_create(TAGTYPE_STRING, 0, L"TestTag",(uint64_t)"TestTagData", &tag));

  assert_true(tag_emit(tag, buf, sizeof(buf), NULL, &bytes_emited));

  assert_true(tag_read(buf, sizeof(buf), true, &tag2, NULL, &bytes_read));

  assert_memory_equal(tag, tag2, bytes_read);

  assert_true(tag_destroy(tag));

  assert_true(tag_destroy(tag2));

}

void
test_tag_create_emit_read_destroy2(void** state)
{
  TAG* tag = NULL;
  TAG* tag2 = NULL;
  uint8_t buf[1024];
  uint32_t bytes_emited = 0;
  uint32_t bytes_read = 0;

  memset(buf, 0, sizeof(buf));

  assert_true(tag_create(TAGTYPE_UINT64, 0, L"TestTag",100, &tag));

  assert_true(tag_emit(tag, buf, sizeof(buf), NULL, &bytes_emited));

  assert_true(tag_read(buf, sizeof(buf), true, &tag2, NULL, &bytes_read));

  assert_memory_equal(tag, tag2, bytes_read);

  assert_true(tag_destroy(tag));

  assert_true(tag_destroy(tag2));

}

void
test_tag_create_emit_read_destroy3(void** state)
{
  TAG* tag = NULL;
  TAG* tag2 = NULL;
  uint8_t buf[1024];
  uint32_t bytes_emited = 0;
  uint32_t bytes_read = 0;

  memset(buf, 0, sizeof(buf));

  assert_true(tag_create(TAGTYPE_UINT64, 1, NULL,100, &tag));

  assert_true(tag_emit(tag, buf, sizeof(buf), NULL, &bytes_emited));

  assert_true(tag_read(buf, sizeof(buf), true, &tag2, NULL, &bytes_read));

  assert_memory_equal(tag, tag2, bytes_read);

  assert_true(tag_destroy(tag));

  assert_true(tag_destroy(tag2));

}

void test_tag_string(void** state)
{
  TAG* tag = NULL;
  uint8_t buf[1024];
  uint32_t bytes_emited = 0;
  uint32_t bytes_read = 0;
  uint32_t len = 0;

  memset(buf, 0, sizeof(buf));

  assert_true(tag_create(TAGTYPE_STRING, 0, L"TestTag",(uint64_t)"TestTagData", &tag));

  assert_true(tag_string_get_len(tag, &len));

  assert_int_equal(11, len);

  assert_true(tag_string_get_data(tag, buf, sizeof(buf)));

  assert_memory_equal(buf, "TestTagData", strlen("TestTagData"));

  assert_true(tag_destroy(tag));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_tag_create_emit_read_destroy),
    unit_test(test_tag_create_emit_read_destroy2),
    unit_test(test_tag_create_emit_read_destroy3),
    unit_test(test_tag_string)
  };

  return run_tests(tests);
}
