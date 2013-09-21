#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <uint128.h>
#include <cmockery.h>

void test_success(void **state)
{
}

void test_generate_uint128(void **state)
{

}

int main(int argc, char* argv[])
{

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_generate_uint128)
  };

  return run_tests(tests);
}
