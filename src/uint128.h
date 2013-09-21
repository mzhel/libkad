#ifndef _UINT128_H_
#define _UINT128_H_

#define UINT128_BYTES_COUNT 16

#define UINT128_WORDS_COUNT UINT128_BYTES_COUNT / 2

#define UINT128_DWORDS_COUNT UINT128_WORDS_COUNT / 2

typedef struct _uint128 {
  union {
    uint32_t dwordData[UINT128_DWORDS_COUNT];
    uint16_t wordData[UINT128_WORDS_COUNT];
    uint8_t byteData[UINT128_BYTES_COUNT];
  } data;
} UINT128;

#endif // _UINT128_H_
