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

uint32_t
uint128_generate(UINT128* ui128);

uint32_t
uint128_from_buffer(
                    UINT128* ui128,
                    uint8_t* buffer,
                    uint32_t bufferLen,
                    bool bigEndian
                    );

uint32_t
uint128_xor(
            UINT128* first, 
            UINT128* second, 
            UINT128* xorRes
            );

#ifdef CONFIG_VERBOSE

#define LOG_DEBUG_UINT128(str, ui128) LOG_DEBUG("%s %.8x%.8x%.8x%.8x", str, ui128->data.dwordData[0], ui128->data.dwordData[1], ui128->data.dwordData[2], ui128->data.dwordData[3]);

#else

#define LOG_DEBUG_UINT128(str, id)

#endif

#endif // _UINT128_H_
