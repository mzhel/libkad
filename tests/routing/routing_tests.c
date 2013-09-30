#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <node.h>
#include <list.h>
#include <mem.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <ticks.h>
#include <cmockery.h>
#include <log.h>

typedef uint32_t Agraphinfo_t;
typedef uint32_t Agnodeinfo_t;
typedef uint32_t Agedgeinfo_t;

#include <graphviz/graph.h>

void test_success(void **state)
{
  LOG_DEBUG("Successfull test.");
}

void
test_zone_create_destroy(void** state)
{
  ROUTING_ZONE* rz = NULL;
  UINT128 idx;

  uint128_zero_init(&idx);

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  assert_true(routing_destroy_zone(rz));
}

#define ROUTED_NODS_COUNT 1000 

void
create_and_fill_rz(
                   ROUTING_ZONE** rz_out,
                   LIST** zones_lst_out,
                   uint32_t* kn_count_calc_out
                  )
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  *rz_out = rz;

  if (kn_count_calc_out) *kn_count_calc_out = kn_count_calc;

  if (zones_lst_out) *zones_lst_out = zones_lst; else list_destroy(zones_lst, false);

}

void
walk_routing_zone(
                  ROUTING_ZONE* rz,
                  Agraph_t* g,
                  Agnode_t* n
                 )
{
  char* id_str = NULL;
  char* node_name = NULL;
  Agnode_t* n1 = NULL;

  do {

    id_str = (char*)mem_alloc(1024);

    node_name = mem_alloc(4096);

    uint128_get_bit_string(&rz->idx, id_str, 1024);

    sprintf(node_name, "%.4d\\n%s\\n", rz->level, id_str);

    if (rz->kb)

    for (uint32_t i = 0; i < rz->kb->nodes_count; i++){

      memset(id_str, 0, 1024);

      id_str[0] = '\\';

      id_str[1] = 'n';

      uint128_get_bit_string(&rz->kb->nodes[i]->dist, id_str + 2, 1022);

      strcat(node_name, id_str);

    }

    n1 = agnode(g, node_name);

    mem_free(id_str);

    mem_free(node_name);

    agset(n1, "shape", "box");

    if (!n){

      n = n1;

    } else {

      agedge(g, n, n1);

      n = n1;

    }

    if (rz->kb){

      

    } else {

      walk_routing_zone(rz->sub_zones[0], g, n);

      walk_routing_zone(rz->sub_zones[1], g, n);

    }

  } while (false);
}

void
test_routing_add_node(void** state)
{
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  Agraph_t* g;
  FILE* f;

  create_and_fill_rz(&rz, NULL, NULL);

  g = agopen("test", AGRAPH);

  agraphattr(g, "rankdir", "LR");

  agset(g, "landscape", "true");

  agnodeattr(g, "shape", "box");

  walk_routing_zone(rz, g, NULL);

  f = fopen("zones.dot", "w");

  agwrite(g, f);

  fclose(f);

  agclose(g);

  assert_true(routing_destroy_zone(rz));

}

void
test_routing_get_node_by_id(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t rand_idx = 0;
  KAD_NODE* rand_kn = NULL;


  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  rand_idx = random_uint32() % ROUTED_NODS_COUNT;

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (rand_idx == i){

      rand_kn = kn;

    }

     if (!routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) node_destroy(kn);

  }

  assert_true(routing_get_node_by_id(rz, &self_id, &rand_kn->id, &kn, true));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);
 
}

  void
test_routing_get_node_by_ip_port(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t rand_idx = 0;
  KAD_NODE* rand_kn = NULL;
  bool add_res = false;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  rand_idx = random_uint32() % ROUTED_NODS_COUNT;

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);
    
    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));
    
    add_res = routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true);

    if (!add_res) node_destroy(kn);

    if (rand_idx == i){

      if (add_res){

        kn->ip4_no = 5;

        kn->tcp_port_no = 5;

      } else {

        rand_idx++;

      }

    }

  }

  assert_true(routing_get_node_by_ip_port(rz, 5, 5, KAD_NODE_TCP_PORT, &kn, true));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);
 
}

void
test_routing_get_nodes_count(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;
  uint32_t kn_count_call = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  assert_true(routing_get_nodes_count(rz, &kn_count_call, true));

  assert_int_equal(kn_count_calc, kn_count_call);

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);

}

void
test_routing_get_closest_to(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;
  uint32_t kn_count_call = 0;
  LIST* kn_lst = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  // Generate target id for search
 
  uint128_generate(&id);

  uint128_xor(&self_id, &id, &dist);

  assert_true(routing_get_closest_to(rz, 3, 10, &id, &dist, false, &kn_lst, true));

  list_entries_count(kn_lst, &cnt);

  LOG_DEBUG("Entries count %d", cnt);

  uint128_zero_init(&dist);

  for (uint32_t i = 0; i < 10; i++){

    assert_true(list_entry_at_idx(kn_lst, i, (void**)&nle));

    assert_int_equal(0xff, uint128_compare(&dist, &nle->dist));

    uint128_copy(&nle->dist, &dist);

  }

  assert_true(list_destroy(kn_lst, true));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);

}

void
test_routing_get_random_node(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;
  uint32_t kn_count_call = 0;
  LIST* kn_lst = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  assert_true(routing_get_random_node(rz, 3, 0, &kn, true));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);

}

void
test_routing_get_entries_from_random_bucket(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;
  uint32_t kn_count_call = 0;
  LIST* kn_lst = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  assert_true(routing_get_entries_from_random_bucket(rz, &kn_lst, true));

  assert_true(routing_get_random_node(rz, 3, 0, &kn, true));

  assert_true(list_destroy(kn_lst, false));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);

}

void
test_routing_get_top_depth_entries(void** state)
{
  KAD_NODE* kn = NULL;
  UINT128 idx;
  UINT128 self_id;
  UINT128 id;
  UINT128 dist;
  ROUTING_ZONE* rz = NULL;
  LIST* zones_lst = NULL;
  uint32_t kn_count_calc = 0;
  uint32_t kn_count_call = 0;
  LIST* kn_lst = NULL;
  NODE_LIST_ENTRY* nle = NULL;
  uint32_t cnt = 0;

  uint128_zero_init(&idx);

  uint128_generate(&self_id);

  LOG_DEBUG_UINT128("self_id:", ((UINT128*)&self_id));

  assert_true(routing_create_zone(NULL, 0, &idx, &rz));

  for (uint32_t i = 0; i < ROUTED_NODS_COUNT; i++){

    uint128_generate(&id);

    uint128_xor(&self_id, &id, &dist);

    assert_true(node_create(&id, 0, 0, 0, 0, 1, 0, true, &dist, &kn));

    if (routing_add_node(&zones_lst, rz, kn, 0, false, NULL, true)) kn_count_calc++;

    else node_destroy(kn);

  }

  assert_true(routing_get_top_depth_entries(rz, 0, &kn_lst, true));

  assert_true(list_destroy(kn_lst, false));

  assert_true(routing_destroy_zone(rz));

  list_destroy(zones_lst, false);

}

void
test_routing_get_bootstrap_contacts(void** state)
{
  ROUTING_ZONE* rz = NULL;
  uint32_t nodes_cnt_calc = 0;
  LIST* kn_lst = NULL;

  create_and_fill_rz(&rz, NULL, &nodes_cnt_calc);

  assert_true(routing_get_bootstrap_contacts(rz, 10, &kn_lst, true));

  assert_true(list_destroy(kn_lst, false));

  assert_true(routing_destroy_zone(rz));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[Uint128] ");

  random_init();

  aginit();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_zone_create_destroy),
    unit_test(test_routing_add_node),
    unit_test(test_routing_get_node_by_id),
    unit_test(test_routing_get_node_by_ip_port),
    unit_test(test_routing_get_nodes_count),
    unit_test(test_routing_get_closest_to),
    unit_test(test_routing_get_random_node),
    unit_test(test_routing_get_entries_from_random_bucket),
    unit_test(test_routing_get_top_depth_entries),
    unit_test(test_routing_get_bootstrap_contacts)
  };

  return run_tests(tests);
}
