#ifndef _CIPHER_C_
#define _CIPHER_C_

#define CIPHER_HEADER_WITHOUT_PADDING_LEN 8

#define MAGICVALUE_UDP_SYNC_CLIENT 0x395f2ec1

bool
cipher_is_packet_encrypted(
                           uint8_t* pkt,
                           uint32_t pkt_len
                          );

bool
cipher_decrypt_packet(
                      uint8_t* pkt,
                      uint32_t pkt_len,
                      uint32_t ip4_no,
                      UINT128* self_id,
                      uint32_t self_udp_key,
                      uint8_t** pkt_out_ptr,
                      uint32_t* pkt_out_len_ptr,
                      uint32_t* rcvr_verify_key_out,
                      uint32_t* sndr_verify_key_out
                     );

bool
cipher_encrypt_packet(
                      uint8_t* pkt,
                      uint32_t pkt_len,
                      UINT128* id,
                      uint32_t rcvr_verify_key,
                      uint32_t sndr_verify_key,
                      uint8_t** pkt_out_ptr,
                      uint32_t* pkt_out_len_ptr
                     );



#endif // _CIPHER_C_
