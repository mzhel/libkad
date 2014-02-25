#ifndef _KADFILE_H_
#define _KADFILE_H_

typedef struct _kad_file {
  FILE* f;
  uint32_t length;
} KAD_FILE;

bool
kadfile_open_read(
                  char* file_path,
                  uint32_t* len_out,
                  KAD_FILE** kf_out
                  );

bool
kadfile_open_overwrite(
                       char* file_path,
                       KAD_FILE** kf_out
                      );

bool
kadfile_close(
              KAD_FILE* kf
              );

bool
kadfile_get_length(
                   KAD_FILE* kf,
                   uint32_t* len_out
                   );

bool
kadfile_read_uint8(
                   KAD_FILE* kf,
                   uint8_t* ui8_out
                   );

bool
kadfile_write_uint8(
                    KAD_FILE* kf,
                    uint8_t ui8
                   );

bool
kadfile_read_uint16(
                    KAD_FILE* kf,
                    uint16_t* ui16_out
                    );

bool
kadfile_write_uint16(
                     KAD_FILE* kf,
                     uint16_t ui16
                    );

bool
kadfile_read_uint32(
                    KAD_FILE* kf,
                    uint32_t* ui32_out
                    );

bool
kadfile_write_uint32(
                     KAD_FILE* kf,
                     uint32_t ui32
                    );

bool
kadfile_read_uint64(
                    KAD_FILE* kf,
                    uint64_t* ui64_out
                    );

bool
kadfile_write_uint64(
                     KAD_FILE* kf,
                     uint64_t ui64
                    );

bool
kadfile_read_uint128(
                     KAD_FILE* kf,
                     UINT128* ui128_out
                     );

bool
kadfile_write_uint128(
                      KAD_FILE* kf,
                      UINT128* ui128
                     );

#endif // _KADFILE_H_
