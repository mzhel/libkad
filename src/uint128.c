#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <byteswap.h>

uint32_t
uint128_generate(UINT128* ui128)
{
  uint8_t i = 0;

  do {

    for (i = 0; i < UINT128_BYTES_COUNT; i++) {

      ui128->data.byteData[i] = random_uint8();

    }

  } while (false);

  return 1;

}

uint32_t
uint128_from_buffer(
                    UINT128* ui128,
                    uint8_t* buffer,
                    uint32_t bufferLen,
                    bool bigEndian // if set dwords in buffer treated as big endian
                    )
{
  uint32_t result = 0;

  do {

    if (!ui128 || !buffer) break;

    if (bufferLen < sizeof(UINT128)) break;

    if (bigEndian){

      for (uint8_t i = 0; i < bufferLen; i++){

        ui128->data.dwordData[i] = BSWAP32(((uint32_t*)buffer)[i]);

      }

    } else {
      
      memcpy(ui128, buffer, sizeof(UINT128));

    }

    result = 1;

  } while (false);

  return result;
}

uint32_t
uint128_xor(UINT128* first, UINT128* second, UINT128* xorRes)
{
  uint32_t result = 0;
  uint8_t i;

  do {

    if (!first || !second) break;

    if (!xorRes) xorRes = first;

    for (i = 0; i < UINT128_DWORDS_COUNT; i++){

      xorRes->data.dwordData[i] = first->data.dwordData[i] ^ second->data.dwordData[i];

    }

    result = 1;

  } while (false);

  return result;
}
