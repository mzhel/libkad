#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <stdio.h>
#include <uint128.h>
#include <kadfile.h>
#include <mem.h>
#include <log.h>

bool
kadfile_open_read(
                  char* file_path,
                  uint32_t* len_out,
                  KAD_FILE** kf_out
                  )
{
  bool result = false;
  FILE* f = NULL;
  KAD_FILE* kf = NULL;

  do {

    if (!file_path || !kf_out) break;


    kf = (KAD_FILE*)mem_alloc(sizeof(KAD_FILE));

    if (!kf){

      LOG_ERROR("Failed to allocate memory or kad file.");

      break;

    }

    f = fopen(file_path, "rb");

    if (!f){

      LOG_ERROR("Failed to open file.");

      break;

    }

    fseek(f, 0, SEEK_END);

    kf->length = ftell(f);

    rewind(f);

    kf->f = f;

    if (len_out) *len_out = kf->length;

    *kf_out = kf;

    result = true;

  } while (false);

  if (!result && kf) mem_free(kf);

  return result;
}

bool
kadfile_close(
              KAD_FILE* kf
              )
{
  bool result = false;

  do {

    if (!kf) break;

    fclose(kf->f);

    mem_free(kf);

    result = true;

  } while (false);

  return result;
}

bool
kadfile_get_length(
                   KAD_FILE* kf,
                   uint32_t* len_out
                   )
{
  bool result = false;

  do {

    if (!kf || !len_out) break;

    *len_out = kf->length;

    result = true;

  } while (false);

  return result;
}

bool
kadfile_read_uint8(
                   KAD_FILE* kf,
                   uint8_t* ui8_out
                   )
{
  bool result = false;
  uint8_t ui8 = 0;

  do {

    if (!kf) break;

    if (1 != fread(&ui8, 1, 1, kf->f)) break;

    if (ui8_out) *ui8_out = ui8;

    result = true;

  } while (false);

  return result;
}

bool
kadfile_read_uint16(
                    KAD_FILE* kf,
                    uint16_t* ui16_out
                    )
{
  bool result = false;
  uint16_t ui16 = 0;

  do {

    if (!kf) break;

    if (2 != fread(&ui16, 1, 2, kf->f)) break;

    if (ui16_out) *ui16_out = ui16;

    result = true;

  } while (false);

  return result;
}

bool
kadfile_read_uint32(
                    KAD_FILE* kf,
                    uint32_t* ui32_out
                    )
{
  bool result = false;
  uint32_t ui32 = 0;

  do {

    if (!kf) break;

    if (4 != fread( &ui32, 1, 4, kf->f)) break;

    if (ui32_out) *ui32_out = ui32;

    result = true;

  } while (false);

  return result;
}

bool
kadfile_read_uint64(
                    KAD_FILE* kf,
                    uint64_t* ui64_out
                    )
{
  bool result = false;
  uint64_t ui64 = 0;

  do {

    if (!kf) break;

    if (4 != fread( &ui64, 1, 4, kf->f)) break;

    if (ui64_out) *ui64_out = ui64;

    result = true;

  } while (false);

  return result;
}

bool
kadfile_read_uint128(
                     KAD_FILE* kf,
                     UINT128* ui128_out
                     )
{
  bool result = false;

  do {

    if (!kf || !ui128_out) break;

    for (uint32_t i = 0; i < UINT128_DWORDS_COUNT; i++){

      kadfile_read_uint32(kf, &ui128_out->data.dwordData[i]);

    }

    result = true;

  } while (false);

  return result;
}
