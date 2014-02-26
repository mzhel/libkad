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

/*

            KAD packet encription.

            RC 4 key generation.

            rndKeyPart = RandomWord()

            if kadID == 0 && rcvrVerifyKey != 0

                rc4Key = md5(rcvrVerifyKey + rndKeyPart)

            else if kadId != 0

                rc4Key = md5(kadId + rndKeyPart);

            end

            semiRndMarker bits:
                                0 - kad network(0), other(1)
                                1 - rcvrVerifyKey used(1), other(0)


            Encrypted KAD packet.

            [0] - semi-random marker. 1 byte.
            [1] - random key part. 2 bytes.
            [3] - RC4 encrypted MAGICVALUE_UDP_SYNC_CLIENT. 4 bytes.
            [7] - RC4 encrypted  paddding length. 1 byte. Padding length is currently 0 so no padding bytes.
            [8] - RC4 encrypted rcvrVerifyKey. 4 bytes.
            [12] - RC4 encrypted senderVerifyKey. 4 bytes.
            [16] - RC4 encrypted data. data size.

*/

bool
cipher_is_packet_encrypted(
                           uint8_t* pkt,
                           uint32_t pkt_len
                          )
{
  bool result = false;
  uint8_t proto = 0;

  do {

    if (pkt_len < CIPHER_HEADER_WITHOUT_PADDING_LEN) break;

    proto = pkt[0];

    if (
        proto == OP_EMULEPROT ||
        proto == OP_KADEMLIAPACKEDPROT ||
        proto == OP_KADEMLIAHEADER ||
        proto == OP_UDPRESERVEDPROT1 ||
        proto == OP_UDPRESERVEDPROT2 ||
        proto == OP_PACKEDPROT
        ) break;

    result = true;

  } while (false);

  return result;
}

bool
cipher_decrypt_packet(
                      KAD_SESSION* ks,
                      uint8_t* pkt,
                      uint32_t pkt_len,
                      uint32_t ip4_no,
                      UINT128* self_id,
                      uint32_t self_udp_key,
                      uint8_t** pkt_out_ptr,
                      uint32_t* pkt_out_len_ptr,
                      uint32_t* rcvr_verify_key_out,
                      uint32_t* sndr_verify_key_out
                     )
{
  bool result = false;
  uint8_t* pkt_out = NULL;
  uint32_t pkt_out_len = 0;
  uint32_t rcvr_verify_key = 0;
  uint32_t sndr_verify_key = 0;
  uint8_t proto = 0;
  uint8_t key_data[18] = {0};
  uint8_t key_data_len = 0;
  bool rcvr_key_used = false;
  uint8_t md5_dgst[16];
  arc4_context rc4_ctx;
  uint8_t tries = 2;
  uint32_t magic_val = 0;
  uint8_t* p = NULL;
  bool decrypted = false;
  uint8_t pad_len = 0;
  uint8_t* pad_buf = NULL;

  do {

    if (!pkt || !pkt_len || !pkt_out_ptr || !pkt_out_len_ptr || !rcvr_verify_key_out || !sndr_verify_key_out) break;

    if (!ks->ccbs.md5 || !ks->ccbs.arc4_setup || !ks->ccbs.arc4_crypt) break;

    if (pkt_len < CIPHER_HEADER_WITHOUT_PADDING_LEN){

      LOG_ERROR("Packet length is too small for encrypted packet.");

      break;

    }

    memset(&rc4_ctx, 0, sizeof(rc4_ctx));

    memset(key_data, 0, sizeof(key_data));

    memset(md5_dgst, 0, sizeof(md5_dgst));

    pkt_out_len = pkt_len;

    proto = *pkt;

    if (!cipher_is_packet_encrypted(pkt, pkt_len)) break;

    while(tries--){

      if (proto & 2){

        // Using rcvr_verify_key

        LOG_DEBUG("using rcvr_verify_key");
        
        proto = 0; // proto for second try if first try was unsuccessfull.

        key_data_len = 6;

        rcvr_key_used = true;

        kadhlp_calc_udp_verify_key(ks, self_udp_key, ip4_no, (uint32_t*)key_data);

        memcpy(key_data + 4, pkt + 1, 2);

        LOG_DEBUG("key_data = %.8x%.4x", *(uint32_t*)key_data, *(uint16_t*)(key_data + 4));

      } else {

        // using node_id
        
        LOG_DEBUG("using id");

        LOG_DEBUG_UINT128("id: ", self_id);
        
        proto |= 2;

        key_data_len = 18;

        uint128_emit(self_id, key_data, key_data_len);

        memcpy(key_data + sizeof(UINT128), pkt + 1, 2);

      }

      ks->ccbs.md5((uint8_t*)&key_data, key_data_len, md5_dgst);

      ks->ccbs.arc4_setup(&rc4_ctx, md5_dgst, sizeof(md5_dgst));

      // Try to decrypt magic value.
      
      p = pkt + 3;

      magic_val = 0;

      ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(magic_val), p, (uint8_t*)&magic_val);

      if (magic_val == MAGICVALUE_UDP_SYNC_CLIENT){

        LOG_DEBUG("Magic value match.");

        decrypted = true;

        break;

      }

    }

    if (!decrypted) {

      LOG_ERROR("Magic value is wrong, this is not encrypted kad packet.");

      break;

    }

    pkt_out_len -= CIPHER_HEADER_WITHOUT_PADDING_LEN;

    p += 4;

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(pad_len), p, (uint8_t*)&pad_len);

    p++;

    if (pkt_out_len < pad_len){

      LOG_ERROR("Wrong kad packet, remaining packet len %.4x, padding len %.4x.", pkt_out_len, pad_len);

      break;

    }

    if (pad_len > 0){

      pad_buf = (uint8_t*)mem_alloc(pad_len);

      if (!pad_buf){

        LOG_ERROR("Failed to allocate memory for padding buffer.");

        break;

      }

      ks->ccbs.arc4_crypt(&rc4_ctx, pad_len, p, pad_buf);

      p += pad_len;

      pkt_out_len -= pad_len;

    }

    if (pkt_out_len < 8){

      LOG_ERROR("Length of the remainig data is insufficient.");

      break;

    }

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(rcvr_verify_key), p, (uint8_t*)&rcvr_verify_key);

    p += 4;

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(sndr_verify_key), p, (uint8_t*)&sndr_verify_key);

    p += 4;

    pkt_out_len -= 8;

    if (pkt_out_len){

      pkt_out = (uint8_t*)mem_alloc(pkt_out_len);

      if (!pkt_out){

        LOG_ERROR("Failed to allocate memory for decrypted packet.");

        break;

      }

      ks->ccbs.arc4_crypt(&rc4_ctx, pkt_out_len, p, pkt_out);

    }

    *rcvr_verify_key_out = rcvr_verify_key;

    *sndr_verify_key_out = sndr_verify_key;

    *pkt_out_len_ptr = pkt_out_len;

    *pkt_out_ptr = pkt_out;

    result = true;

  } while (false);

  if (pad_buf) mem_free(pad_buf);

  return result;
}

bool
cipher_encrypt_packet(
                      KAD_SESSION* ks,
                      uint8_t* pkt,
                      uint32_t pkt_len,
                      UINT128* id,
                      uint32_t rcvr_verify_key,
                      uint32_t sndr_verify_key,
                      uint8_t** pkt_out_ptr,
                      uint32_t* pkt_out_len_ptr
                      )
{
  bool result = false;
  uint8_t* pkt_out = NULL;
  uint32_t pkt_out_len = 0;
  uint16_t rand_part = 0;
  uint8_t key_data[18];
  uint8_t key_data_len = 0;
  uint8_t md5_dgst[16];
  arc4_context rc4_ctx;
  uint8_t semi_rnd_mrkr = 0;
  bool kad_rcvr_key_used = false;
  bool found = false;
  uint8_t* p = NULL;
  uint32_t magic_val = 0;
  uint8_t pad_len = 0;
  uint8_t rb = 0;
  uint32_t i = 0;

  do {

    if (!pkt || !pkt_len || !pkt_out_ptr || !pkt_out_len_ptr) break;

    if (!ks->ccbs.md5 || !ks->ccbs.arc4_setup || !ks->ccbs.arc4_crypt) break;

    memset(key_data, 0, sizeof(key_data));

    memset(md5_dgst, 0, sizeof(md5_dgst));

    memset(&rc4_ctx, 0, sizeof(rc4_ctx));

    pkt_out_len = 16 + pkt_len;

    LOG_DEBUG("pkt_out_len = %.8x", pkt_out_len);

    pkt_out = (uint8_t*)mem_alloc(pkt_out_len);

    if (!pkt_out){

      LOG_ERROR("Failed to allocate memory for encrypted buffer.");

      break;

    }

    rand_part = random_uint16();

    LOG_DEBUG("rand_part = %.4x", rand_part);

    // First try to use id the rcvr_verify_key
    
    if (!id && rcvr_verify_key){

      LOG_DEBUG("using rcvr_verify_key");

      key_data_len = 6;

      *(uint32_t*)key_data = rcvr_verify_key;

      *(uint16_t*)(key_data + 4) = rand_part;

      kad_rcvr_key_used = true;

    } else if (id){

      LOG_DEBUG("using id");

      key_data_len = 18;

      uint128_emit(id, key_data, key_data_len);

      LOG_DEBUG_UINT128("id: ", id);

      *(uint16_t*)(key_data + sizeof(UINT128)) = rand_part;

    } else {

      // Neither id or rcvr_verify_key.

      break;

    }

    ks->ccbs.md5((uint8_t*)&key_data, key_data_len, md5_dgst);

    ks->ccbs.arc4_setup(&rc4_ctx, md5_dgst, sizeof(md5_dgst));

    for (i = 0; i < 128; i++){

      semi_rnd_mrkr = random_uint8() & 0xfe;

      semi_rnd_mrkr = kad_rcvr_key_used?((semi_rnd_mrkr & 0xfe) | 0x02):(semi_rnd_mrkr & 0xfc);

      LOG_DEBUG("semi_rnd_mrkr = %.1x", semi_rnd_mrkr);

      switch(semi_rnd_mrkr){

        case OP_EMULEPROT:
        case OP_KADEMLIAPACKEDPROT:
        case OP_KADEMLIAHEADER:
        case OP_UDPRESERVEDPROT1:
        case OP_UDPRESERVEDPROT2:
        case OP_PACKEDPROT:

        break;

        default:

          found = true;

      }

      if (found) break;

    }

    if (i >= 128){

      // Something wrong with PRNG.

      break;

    }

    p = pkt_out;
    
    *p++ = semi_rnd_mrkr;

    *(uint16_t*)p = rand_part;

    p += 2;

    magic_val = MAGICVALUE_UDP_SYNC_CLIENT;

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(magic_val), (uint8_t*)&magic_val, p);

    p += sizeof(magic_val);

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(pad_len), (uint8_t*)&pad_len, p);

    p += sizeof(pad_len);

    for (uint32_t i = 0; i < pad_len; i++){

      rb = random_uint8();

      ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(rb), (uint8_t*)&rb, p + i);

    }

    p += pad_len;

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(rcvr_verify_key), (uint8_t*)&rcvr_verify_key, p);

    p += sizeof(rcvr_verify_key);

    ks->ccbs.arc4_crypt(&rc4_ctx, sizeof(sndr_verify_key), (uint8_t*)&sndr_verify_key, p);

    p += sizeof(sndr_verify_key);

    ks->ccbs.arc4_crypt(&rc4_ctx, pkt_len, pkt, p);

    *pkt_out_ptr = pkt_out;

    *pkt_out_len_ptr = pkt_out_len;

    result = true;

  } while (false);

  if (!result && pkt_out) mem_free(pkt_out);

  return result;
}
