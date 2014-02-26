#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadhlp.h>
#include <kadsrch.h>
#include <kadqpkt.h>
#include <kad.h>
#include <ticks.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>
#include <random.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_nodes_dat(
               void** state
              )
{
  KAD_SESSION ks;
  LIST* kn_lst = NULL;

  do {

    kadhlp_parse_nodes_dat(&ks, "nodes.dat", &kn_lst);

    kadhlp_create_nodes_dat(kn_lst, "nodes.dat.1");

  } while (false);

}


int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[nodesdat] ");

  random_init(ticks_now_ms());

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_nodes_dat)
  };

  return run_tests(tests);
}

