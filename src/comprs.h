#ifndef _COMPRESS_H_
#define _COMPRESS_H_

bool
compress_is_packet_compressed(
                              uint8_t* pkt,
                              uint32_t pkt_len
                              );

bool
compress_uncompress_packet(
                           uint8_t* pkt,
                           uint32_t pkt_len,
                           uint8_t** unk_pkt_out,
                           uint32_t* unk_pkt_len_out
                           );

bool
compress_uncompress_block(
                          uint8_t* block_data,
                          uint32_t block_data_len,
                          uint8_t** decomp_data_out,
                          uint32_t* decomp_len_out
                          );

#endif // _COMPRESS_H_
