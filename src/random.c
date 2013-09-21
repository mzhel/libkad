#include <stdint.h>
#include <polarssl/havege.h>

static havege_state hs = {0};

void
random_init()
{
  havege_init(&hs);
}

uint32_t
random_uint32()
{
  return havege_rand(&hs);
}

uint16_t
random_uint16()
{
  return (uint16_t)havege_rand(&hs);
}

uint8_t
random_uint8()
{
  return (uint8_t)havege_rand(&hs);
}
