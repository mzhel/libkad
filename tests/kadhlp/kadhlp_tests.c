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

void test_kadhlp_parse_nodes_dat(void** state)
{
  KAD_SESSION* ks;
  LIST* kn_lst = NULL;

  kad_session_init(0, 0, &ks);

  assert_true(kadhlp_parse_nodes_dat(ks, "nodes.dat", &kn_lst));

  list_destroy(kn_lst, true);

  kad_session_uninit(ks);

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_kadhlp_parse_nodes_dat)
  };

  return run_tests(tests);
}
