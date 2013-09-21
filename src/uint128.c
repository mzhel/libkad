#include <stdint.h>
#include <uint128.h>
#include <random.h>
#include <byteswap.h>

uint32_t
uint128_generate(UINT128* ui128)
{
  uint8_t i = 0;

  do {

    for (i = 0; i < UINT128_BYTES_COUNT; i++) {

      ui128->data.byteData[i] = random_byte();

    }

  } while (false);

}
