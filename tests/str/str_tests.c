#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <wchar.h>
#include <memory.h>
#include <mem.h>
#include <str.h>
#include <cmockery.h>
#include <log.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_str_unicode_to_utf8(void** state)
{
  wchar_t uc_str[] = L"Example string!";
  wchar_t* uc_ptr = uc_str;

  size_t uc_str_len = 15;
  char* buf = NULL;
  char* p = NULL;
  uint32_t buf_len;

  buf_len = uc_str_len + 1;

  buf = mem_alloc(buf_len);

  p = buf;

  assert_true(str_unicode_to_utf8(uc_ptr, uc_str_len, p, buf_len));

  LOG_DEBUG("Converted string: %s", buf);

  mem_free(buf);

}

void
test_str_utf8_to_unicode(void** state)
{
  char str[] = "Example string!";
  size_t str_len = strlen(str);
  wchar_t* uc_str = NULL;
  size_t uc_str_len = str_len * 2;

  uc_str = (wchar_t*)mem_alloc(uc_str_len + 2);

  assert_true(str_utf8_to_unicode(str, str_len, uc_str, uc_str_len));

  mem_free(uc_str);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_str_unicode_to_utf8),
    unit_test(test_str_utf8_to_unicode)
  };

  return run_tests(tests);
}
