#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <str.h>
#include <log.h>

bool
str_unicode_to_utf8(
                    wchar_t* uc_str,
                    size_t uc_str_len,
                    char* res_buf,
                    size_t res_buf_len
                   )
{
  bool result = false;
  iconv_t ic = (iconv_t)-1;
  size_t uc_bytes_len = 0;

  do {

    if (!uc_str || !res_buf) break;

    uc_bytes_len = uc_str_len * 2;

    ic = iconv_open("UTF-8", "UTF-16LE");

    if (ic == (iconv_t)-1){

      LOG_ERROR("Failed to create iconv descriptor.");

      break;

    }

    if (-1 == iconv(ic, (char**)&uc_str, (size_t*)&uc_bytes_len, &res_buf, (size_t*)&res_buf_len)) {

      LOG_ERROR("iconv failed, error code %d.", errno);

      break;

    }

    result = true;

  } while (false);

  if (ic != (iconv_t)-1) iconv_close(ic);

  return result;
}

bool
str_utf8_to_unicode(
                    char* in_str,
                    size_t in_str_len,
                    wchar_t* out_buf,
                    size_t out_buf_len
                   )
{
  bool result = false;
  iconv_t ic = (iconv_t)-1;

  do {

    if (!in_str || !out_buf) break;

    ic = iconv_open("UTF-16LE", "UTF-8");

    if (ic == (iconv_t)-1){

      LOG_ERROR("Failed to create iconv descriptor.");

      break;

    }

    out_buf_len = out_buf_len *sizeof(wchar_t);

    if (-1 == iconv(ic, &in_str, &in_str_len, (char**)&out_buf, &out_buf_len)) {

      LOG_ERROR("iconv failed, error code %d.", errno);

      break;

    }

    result = true;

  } while (false);

  if (ic != (iconv_t)-1) iconv_close(ic);

  return result;
}

uint32_t
str_wide_len(
             char* str
            )
{
  uint32_t result = 0;

  while (*(uint16_t*)str != 0) {

    result++;

    str += 2;

  }

  return result;
}
