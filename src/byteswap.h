#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_

#define bswap16(x) ((uint16_t)(x << 8) | (uint16_t)(x >> 8))

#define bswap32(x) ((bswap16(x >> 16) | (bswap16((uint16_t)x)) << 16)

#define bswap64(x) ((bswap32(x >> 32)) | (bswap32((uint32_t)x)) < 32)

#endif // _BYTESWAP_H_
