/*
 * This file Copyright (C) 2007-2014 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h> /* abs (), srand (), rand () */
#include <string.h> /* memcpy (), memmove (), memset (), strcmp (), strlen () */

#include <b64/cdecode.h>
#include <b64/cencode.h>

#include "transmission.h"
#include "crypto-utils.h"
#include "utils.h"

/***
****
***/

void
tr_dh_align_key (uint8_t * key_buffer,
                 size_t    key_size,
                 size_t    buffer_size)
{
  assert (key_size <= buffer_size);

  /* DH can generate key sizes that are smaller than the size of
     key buffer with exponentially decreasing probability, in which case
     the msb's of key buffer need to be zeroed appropriately. */
  if (key_size < buffer_size)
    {
      const size_t offset = buffer_size - key_size;
      memmove (key_buffer + offset, key_buffer, key_size);
      memset (key_buffer, 0, offset);
    }
}

/***
****
***/

bool
tr_sha1 (uint8_t    * hash,
         const void * data1,
         int          data1_length,
                      ...)
{
  tr_sha1_ctx_t sha;

  if ((sha = tr_sha1_init ()) == NULL)
    return false;

  if (tr_sha1_update (sha, data1, data1_length))
    {
      va_list vl;
      const void * data;

      va_start (vl, data1_length);
      while ((data = va_arg (vl, const void *)) != NULL)
        {
          const int data_length = va_arg (vl, int);
          assert (data_length >= 0);
          if (!tr_sha1_update (sha, data, data_length))
            break;
        }
      va_end (vl);

      /* did we reach the end of argument list? */
      if (data == NULL)
        return tr_sha1_final (sha, hash);
    }

  tr_sha1_final (sha, NULL);
  return false;
}

/***
****
***/

bool
tr_md5 (uint8_t    * hash,
        const void * data1,
        int          data1_length,
                     ...)
{
  tr_md5_ctx_t md5;

  if ((md5 = tr_md5_init ()) == NULL)
    return false;

  if (tr_md5_update (md5, data1, data1_length))
    {
      va_list vl;
      const void * data;

      va_start (vl, data1_length);
      while ((data = va_arg (vl, const void *)) != NULL)
        {
          const int data_length = va_arg (vl, int);
          assert (data_length >= 0);
          if (!tr_md5_update (md5, data, data_length))
            break;
        }
      va_end (vl);

      /* did we reach the end of argument list? */
      if (data == NULL)
        return tr_md5_final (md5, hash);
    }

  tr_md5_final (md5, NULL);
  return false;
}

/***
****
***/

int
tr_rand_int (int upper_bound)
{
  int noise;

  assert (upper_bound > 0);

  while (tr_rand_buffer (&noise, sizeof (noise)))
    {
      noise = abs(noise) % upper_bound;
      /* abs(INT_MIN) is undefined and could return negative value */
      if (noise >= 0)
        return noise;
    }

  /* fall back to a weaker implementation... */
  return tr_rand_int_weak (upper_bound);
}

int
tr_rand_int_weak (int upper_bound)
{
  static bool init = false;

  assert (upper_bound > 0);

  if (!init)
    {
      srand (tr_time_msec ());
      init = true;
    }

  return rand () % upper_bound;
}

/***
****
***/

char *
tr_ssha1 (const char * plain_text)
{
  enum { saltval_len = 8,
         salter_len  = 64 };
  static const char * salter = "0123456789"
                               "abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "./";

  size_t i;
  unsigned char salt[saltval_len];
  uint8_t sha[SHA_DIGEST_LENGTH];
  char buf[2 * SHA_DIGEST_LENGTH + saltval_len + 2];

  tr_rand_buffer (salt, saltval_len);
  for (i = 0; i < saltval_len; ++i)
    salt[i] = salter[salt[i] % salter_len];

  tr_sha1 (sha, plain_text, strlen (plain_text), salt, (size_t) saltval_len, NULL);
  tr_sha1_to_hex (&buf[1], sha);
  memcpy (&buf[1 + 2 * SHA_DIGEST_LENGTH], &salt, saltval_len);
  buf[1 + 2 * SHA_DIGEST_LENGTH + saltval_len] = '\0';
  buf[0] = '{'; /* signal that this is a hash. this makes saving/restoring easier */

  return tr_strdup (buf);
}

bool
tr_ssha1_matches (const char * ssha1,
                  const char * plain_text)
{
  char * salt;
  size_t saltlen;
  char * my_ssha1;
  uint8_t buf[SHA_DIGEST_LENGTH];
  bool result;
  const size_t sourcelen = strlen (ssha1);

  /* extract the salt */
  if (sourcelen < 2 * SHA_DIGEST_LENGTH - 1)
    return false;
  saltlen = sourcelen - 2 * SHA_DIGEST_LENGTH - 1;
  salt = tr_malloc (saltlen);
  memcpy (salt, ssha1 + 2 * SHA_DIGEST_LENGTH + 1, saltlen);

  /* hash pass + salt */
  my_ssha1 = tr_malloc (2 * SHA_DIGEST_LENGTH + saltlen + 2);
  tr_sha1 (buf, plain_text, strlen (plain_text), salt, saltlen, NULL);
  tr_sha1_to_hex (&my_ssha1[1], buf);
  memcpy (my_ssha1 + 1 + 2 * SHA_DIGEST_LENGTH, salt, saltlen);
  my_ssha1[1 + 2 * SHA_DIGEST_LENGTH + saltlen] = '\0';
  my_ssha1[0] = '{';

  result = strcmp (ssha1, my_ssha1) == 0;

  tr_free (my_ssha1);
  tr_free (salt);

  return result;
}

/***
****
***/

/* this base32 code converted from code by Robert Kaye and Gordon Mohr
 * and is public domain. see http://bitzi.com/publicdomain for more info */

static const char * const base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const int base32_lookup[] =
{
  0xFF,0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F, /* '0', '1', '2', '3', '4', '5', '6', '7' */
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, /* '8', '9', ':', ';', '<', '=', '>', '?' */
  0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06, /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G' */
  0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E, /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O' */
  0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16, /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W' */
  0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF, /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_' */
  0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06, /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g' */
  0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E, /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o' */
  0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16, /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w' */
  0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF  /* 'x', 'y', 'z', '{', '|', '}', '~', 'DEL' */
};

static const size_t base32_lookup_size = sizeof (base32_lookup) / sizeof (*base32_lookup);

void
tr_base32_encode (const void * input,
                  size_t       input_length,
                  void       * output,
                  size_t     * output_length)
{
  const uint8_t * input_bytes = (const uint8_t*) input;
  uint8_t       * output_bytes = (uint8_t*) output;

  const size_t my_output_length = (input_length * 8 + 4) / 5;

  if (output_length != NULL)
    *output_length = my_output_length;

  if (output == NULL)
    return;

  for (size_t i = 0, index = 0; i < input_length;)
    {
      size_t digit = 0;
      size_t curr_byte;

      curr_byte = input_bytes[i];

      /* Is the current digit going to span a byte boundary? */
      if (index > 3)
        {
          size_t next_byte;

          if (i + 1 < input_length)
            next_byte = input_bytes[i + 1];
          else
            next_byte = 0;

          digit = curr_byte & (0xFF >> index);
          index = (index + 5) % 8;
          digit <<= index;
          digit |= next_byte >> (8 - index);
          ++i;
        }
      else
        {
          digit = (curr_byte >> (8 - (index + 5))) & 0x1F;
          index = (index + 5) % 8;
          if (index == 0)
            ++i;
        }

      *output_bytes = (uint8_t) base32_chars[digit];
      ++output_bytes;
    }
}

void
tr_base32_decode (const void * input,
                  size_t       input_length,
                  void       * output,
                  size_t     * output_length)
{
  const uint8_t * input_bytes = (const uint8_t*) input;
  uint8_t       * output_bytes = (uint8_t*) output;

  while (input_length > 0 && input_bytes[input_length - 1] == '=')
    --input_length;

  const size_t my_output_length = input_length * 5 / 8;

  if (output_length != NULL)
    *output_length = my_output_length;

  if (output == NULL)
    return;

  memset (output, '\0', my_output_length);

  for (size_t i = 0, index = 0, offset = 0; i < input_length; ++i)
    {
      const size_t lookup = input_bytes[i] - '0';

      /* Skip chars outside the lookup table */
      if (lookup >= base32_lookup_size)
        continue;

      /* If this digit is not in the table, ignore it */
      const int digit = base32_lookup[lookup];
      if (digit == 0xFF)
        continue;

      if (index <= 3)
        {
          index = (index + 5) % 8;
          if (index == 0)
            {
              output_bytes[offset] |= digit;
              offset++;
              if (offset >= my_output_length)
                break;
            }
          else
            {
              output_bytes[offset] |= digit << (8 - index);
            }
        }
      else
        {
          index = (index + 5) % 8;
          output_bytes[offset] |= (digit >> index);
          offset++;

          if (offset >= my_output_length)
            break;
          output_bytes[offset] |= digit << (8 - index);
        }
    }
}

/***
****
***/

void *
tr_base64_encode (const void * input,
                  size_t       input_length,
                  size_t     * output_length)
{
  char * ret;

  if (input != NULL)
    {
      if (input_length != 0)
        {
          size_t ret_length = 4 * ((input_length + 2) / 3);
          base64_encodestate state;

#ifdef USE_SYSTEM_B64
          /* Additional space is needed for newlines if we're using unpatched libb64 */
          ret_length += ret_length / 72 + 1;
#endif

          ret = tr_new (char, ret_length + 8);

          base64_init_encodestate (&state);
          ret_length = base64_encode_block (input, input_length, ret, &state);
          ret_length += base64_encode_blockend (ret + ret_length, &state);

          if (output_length != NULL)
            *output_length = ret_length;

          ret[ret_length] = '\0';

          return ret;
        }
      else
        ret = tr_strdup ("");
    }
  else
    {
      ret = NULL;
    }

  if (output_length != NULL)
    *output_length = 0;

  return ret;
}

void *
tr_base64_encode_str (const char * input,
                      size_t     * output_length)
{
  return tr_base64_encode (input, input == NULL ? 0 : strlen (input), output_length);
}

void *
tr_base64_decode (const void * input,
                  size_t       input_length,
                  size_t     * output_length)
{
  char * ret;

  if (input != NULL)
    {
      if (input_length != 0)
        {
          size_t ret_length = input_length / 4 * 3;
          base64_decodestate state;

          ret = tr_new (char, ret_length + 8);

          base64_init_decodestate (&state);
          ret_length = base64_decode_block (input, input_length, ret, &state);

          if (output_length != NULL)
            *output_length = ret_length;

          ret[ret_length] = '\0';

          return ret;
        }
      else
        ret = tr_strdup ("");
    }
  else
    {
      ret = NULL;
    }

  if (output_length != NULL)
    *output_length = 0;

  return ret;
}

void *
tr_base64_decode_str (const char * input,
                      size_t     * output_length)
{
  return tr_base64_decode (input, input == NULL ? 0 : strlen (input), output_length);
}
