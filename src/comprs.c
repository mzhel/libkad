#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <kadqpkt.h>
#include <kadpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadhlp.h>
#include <random.h>
#include <protocols.h>
#include <cipher.h>
#include <mem.h>
#include <log.h>

bool
compress_is_packet_compressed(
                              uint8_t* pkt,
                              uint32_t pkt_len
                              )
{
  bool result = false;
  uint8_t proto = 0;

  do {

    if (!pkt || !pkt_len) break;

    proto = pkt[0];

    if (!proto != OP_KADEMLIAPACKEDPROT) break;

    result = true;

  } while (false);

  return result;
}

bool
compress_uncompress_packet(
                           KAD_SESSION* ks,
                           uint8_t* pkt,
                           uint32_t pkt_len,
                           uint8_t** unk_pkt_out,
                           uint32_t* unk_pkt_len_out
                          )
{
  bool result = false;
  uint8_t* unk_pkt = NULL;
  uint64_t unk_pkt_len = 0;

  do {

    if (!ks || !pkt || !pkt_len || !unk_pkt_out || !unk_pkt_len_out) break;

    if (!ks->zcbs.uncompress) break;

    unk_pkt_len = pkt_len * 10 + 300;

    unk_pkt = (uint8_t*)mem_alloc(unk_pkt_len);

    if (!unk_pkt){

      LOG_ERROR("Failed to allocate memory for uncompressed packet.");

      break;

    }

    if (0 != ks->zcbs.uncompress(unk_pkt + 2, &unk_pkt_len, pkt + 2, pkt_len - 2)){

      LOG_ERROR("Uncompress failed.");

      break;

    }

    unk_pkt[0] = OP_KADEMLIAHEADER;

    unk_pkt[1] = pkt[1];

    *unk_pkt_out = unk_pkt;

    *unk_pkt_len_out = (uint32_t)unk_pkt_len;

    result = true;

  } while (false);

  if (!result && unk_pkt) mem_free(unk_pkt);

  return result;
}

bool
compress_uncompress_block(
                          KAD_SESSION* ks,
                          uint8_t* block_data,
                          uint32_t block_data_len,
                          uint8_t** decomp_data_out,
                          uint32_t* decomp_len_out
                          )
{
  bool result = false;
  uint8_t* unk_data = NULL;
  uint64_t unk_data_len = 0;
  int res = 0;

  do {

    if (!ks || !block_data || !block_data_len || !decomp_data_out || !decomp_len_out) break;

    if (!ks->zcbs.uncompress) break;

    unk_data_len = block_data_len * 10 + 300;

    unk_data = (uint8_t*)mem_alloc(unk_data_len);

    if (!unk_data){

      LOG_ERROR("Failed to allocate memory for uncompressed packet.");

      break;

    }

    do {

      res = ks->zcbs.uncompress(unk_data, &unk_data_len, block_data, block_data_len);

      if (res == -5){

        unk_data_len *= 2;

        unk_data = mem_realloc(unk_data, unk_data_len);

      }

      if (res == 0) break;

    } while (true);

    if (0 != res){

      LOG_ERROR("Decompression failed.");

      break;

    }

    *decomp_len_out = (uint32_t)unk_data_len;

    *decomp_data_out = unk_data;

    result = true;

  } while (false);

  if (!result && unk_data) mem_free(unk_data);

  return result;
}
