/*
 * This file Copyright (C) 2013-2014 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 */

#include <string.h>

#include "transmission.h"
#include "crypto.h"
#include "crypto-utils.h"

#include "libtransmission-test.h"

#include "crypto-test-ref.h"

static int
test_torrent_hash (void)
{
  tr_crypto a;
  uint8_t hash[SHA_DIGEST_LENGTH];
  uint8_t i;

  for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
    hash[i] = i;

  tr_cryptoConstruct (&a, NULL, true);

  check (!tr_cryptoHasTorrentHash (&a));
  check (tr_cryptoGetTorrentHash (&a) == NULL);

  tr_cryptoSetTorrentHash (&a, hash);
  check (tr_cryptoHasTorrentHash (&a));
  check (tr_cryptoGetTorrentHash (&a) != NULL);
  check (memcmp (tr_cryptoGetTorrentHash (&a), hash, SHA_DIGEST_LENGTH) == 0);

  tr_cryptoDestruct (&a);

  for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
    hash[i] = i + 1;

  tr_cryptoConstruct (&a, hash, false);

  check (tr_cryptoHasTorrentHash (&a));
  check (tr_cryptoGetTorrentHash (&a) != NULL);
  check (memcmp (tr_cryptoGetTorrentHash (&a), hash, SHA_DIGEST_LENGTH) == 0);

  tr_cryptoSetTorrentHash (&a, NULL);
  check (!tr_cryptoHasTorrentHash (&a));
  check (tr_cryptoGetTorrentHash (&a) == NULL);

  tr_cryptoDestruct (&a);

  return 0;
}

static int
test_encrypt_decrypt (void)
{
  tr_crypto a;
  tr_crypto_ b;
  uint8_t hash[SHA_DIGEST_LENGTH];
  const char test1[] = { "test1" };
  char buf11[sizeof (test1)], buf12[sizeof (test1)];
  const char test2[] = { "@#)C$@)#(*%bvkdjfhwbc039bc4603756VB3)" };
  char buf21[sizeof (test2)], buf22[sizeof (test2)];
  int i;

  for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
    hash[i] = (uint8_t)i;

  tr_cryptoConstruct (&a, hash, false);
  tr_cryptoConstruct_ (&b, hash, true);
  check (tr_cryptoComputeSecret (&a, tr_cryptoGetMyPublicKey_ (&b, &i)));
  check (tr_cryptoComputeSecret_ (&b, tr_cryptoGetMyPublicKey (&a, &i)));

  tr_cryptoEncryptInit (&a);
  tr_cryptoEncrypt (&a, sizeof (test1), test1, buf11);
  tr_cryptoDecryptInit_ (&b);
  tr_cryptoDecrypt_ (&b, sizeof (test1), buf11, buf12);
  check_streq (test1, buf12);

  tr_cryptoEncryptInit_ (&b);
  tr_cryptoEncrypt_ (&b, sizeof (test2), test2, buf21);
  tr_cryptoDecryptInit (&a);
  tr_cryptoDecrypt (&a, sizeof (test2), buf21, buf22);
  check_streq (test2, buf22);

  tr_cryptoDestruct_ (&b);
  tr_cryptoDestruct (&a);

  return 0;
}

static int
test_sha1 (void)
{
  uint8_t hash[SHA_DIGEST_LENGTH];
  uint8_t hash_[SHA_DIGEST_LENGTH];

  check (tr_sha1 (hash, "test", 4, NULL));
  check (tr_sha1_ (hash_, "test", 4, NULL));
  check (memcmp (hash, "\xa9\x4a\x8f\xe5\xcc\xb1\x9b\xa6\x1c\x4c\x08\x73\xd3\x91\xe9\x87\x98\x2f\xbb\xd3", SHA_DIGEST_LENGTH) == 0);
  check (memcmp (hash, hash_, SHA_DIGEST_LENGTH) == 0);

  check (tr_sha1 (hash, "1", 1, "22", 2, "333", 3, NULL));
  check (tr_sha1_ (hash_, "1", 1, "22", 2, "333", 3, NULL));
  check (memcmp (hash, "\x1f\x74\x64\x8e\x50\xa6\xa6\x70\x8e\xc5\x4a\xb3\x27\xa1\x63\xd5\x53\x6b\x7c\xed", SHA_DIGEST_LENGTH) == 0);
  check (memcmp (hash, hash_, SHA_DIGEST_LENGTH) == 0);

  return 0;
}

static int
test_ssha1 (void)
{
  const char * const test_data[] =
    {
      "test",
      "QNY)(*#$B)!_X$B !_B#($^!)*&$%CV!#)&$C!@$(P*)"
    };

  size_t i;

#define HASH_COUNT (16 * 1024)

  for (i = 0; i < sizeof (test_data) / sizeof (*test_data); ++i)
    {
      char * const phrase = tr_strdup (test_data[i]);
      char ** hashes = tr_new (char *, HASH_COUNT);
      size_t j;

      for (j = 0; j < HASH_COUNT; ++j)
        {
          hashes[j] = j % 2 == 0 ? tr_ssha1 (phrase) : tr_ssha1_ (phrase);

          check (hashes[j] != NULL);

          /* phrase matches each of generated hashes */
          check (tr_ssha1_matches (hashes[j], phrase));
          check (tr_ssha1_matches_ (hashes[j], phrase));
        }

      for (j = 0; j < HASH_COUNT; ++j)
        {
          size_t k;

          /* all hashes are different */
          for (k = 0; k < HASH_COUNT; ++k)
            check (k == j || strcmp (hashes[j], hashes[k]) != 0);
        }

      /* exchange two first chars */
      phrase[0] ^= phrase[1];
      phrase[1] ^= phrase[0];
      phrase[0] ^= phrase[1];

      for (j = 0; j < HASH_COUNT; ++j)
        {
          /* changed phrase doesn't match the hashes */
          check (!tr_ssha1_matches (hashes[j], phrase));
          check (!tr_ssha1_matches_ (hashes[j], phrase));
        }

      for (j = 0; j < HASH_COUNT; ++j)
        tr_free (hashes[j]);

      tr_free (hashes);
      tr_free (phrase);
    }

#undef HASH_COUNT

  return 0;
}

static int
test_random (void)
{
  int i;

  /* test that tr_rand_int () stays in-bounds */
  for (i = 0; i < 100000; ++i)
    {
      const int val = tr_rand_int (100);
      check (val >= 0);
      check (val < 100);
    }

  return 0;
}

static bool
base64_eq (const char * a,
           const char * b)
{
  for (; ; ++a, ++b)
    {
      while (*a == '\r' || *a == '\n')
        ++a;
      while (*b == '\r' || *b == '\n')
        ++b;
      if (*a == '\0' || *b == '\0' || *a != *b)
        break;
    }

  return *a == *b;
}

static int
test_base32 (void)
{
  struct test_case
  {
    const char * decoded_text;
    size_t       decoded_text_size;
    const char * encoded_text;
    size_t       encoded_text_size;
  }
  const test_cases[] =
  {
    { "YOYO!", 5, "LFHVSTZB", 8 },
    { "per aspera ad astra", 19, "OBSXEIDBONYGK4TBEBQWIIDBON2HEYI=", 32 },
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
      "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
      "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
      "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
      "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
      "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
      "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
      "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
      "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
      "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
      "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
      "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
      "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
      "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff", 256,
      "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T"
      "4P2AIFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L5QGCYTDMRSWMZ3INFVGW3DNNZXXA4LSON2HK5TXPB4XU634"
      "PV7H7AEBQKBYJBMGQ6EITCULRSGY5D4QSGJJHFEVS2LZRGM2TOOJ3HU7UCQ2FI5EUWTKPKFJVKV2ZLNOV6YLDMVTWS23NN5YXG5L"
      "XPF5X274BQOCYPCMLRWHZDE4VS6MZXHM7UGR2LJ5JVOW27MNTWW33TO55X7A4HROHZHF43T6R2PK5PWO33XP6DY7F47U6X3PP6HZ"
      "7L57Z7P674======", 416 }
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (*test_cases); ++i)
    {
      const struct test_case * c = &test_cases[i];
      size_t expected_size;
      char buffer[512];
      size_t buffer_size;

      expected_size = c->encoded_text_size;

      /* encoder doesn't pad the output */
      while (c->encoded_text[expected_size - 1] == '=')
        --expected_size;

      tr_base32_encode (c->decoded_text, c->decoded_text_size, NULL, &buffer_size);
      check_uint_eq (expected_size, buffer_size);

      tr_base32_encode (c->decoded_text, c->decoded_text_size, buffer, &buffer_size);
      check_uint_eq (expected_size, buffer_size);
      check (memcmp (c->encoded_text, buffer, buffer_size) == 0);

      expected_size = c->decoded_text_size;

      tr_base32_decode (c->encoded_text, c->encoded_text_size, NULL, &buffer_size);
      check_uint_eq (expected_size, buffer_size);

      tr_base32_decode (c->encoded_text, c->encoded_text_size, buffer, &buffer_size);
      check_uint_eq (expected_size, buffer_size);
      check (memcmp (c->decoded_text, buffer, buffer_size) == 0);
    }

  return 0;
}

static int
test_base64 (void)
{
  size_t len;
  char * in, * out;
  size_t i;

  out = tr_base64_encode_str ("YOYO!", &len);
  check_uint_eq (strlen (out), len);
  check (base64_eq ("WU9ZTyE=", out));
  in = tr_base64_decode_str (out, &len);
  check_uint_eq (5, len);
  check_streq ("YOYO!", in);
  tr_free (in);
  tr_free (out);

  out = tr_base64_encode ("", 0, &len);
  check_uint_eq (0, len);
  check_streq ("", out);
  tr_free (out);
  out = tr_base64_decode ("", 0, &len);
  check_uint_eq (0, len);
  check_streq ("", out);
  tr_free (out);

  out = tr_base64_encode (NULL, 0, &len);
  check_uint_eq (0, len);
  check (out == NULL);
  out = tr_base64_decode (NULL, 0, &len);
  check_uint_eq (0, len);
  check (out == NULL);

#define MAX_BUF_SIZE 1024

  for (i = 1; i <= MAX_BUF_SIZE; ++i)
    {
      size_t j;
      char buf[MAX_BUF_SIZE + 1];

      for (j = 0; j < i; ++j)
        buf[j] = (char) tr_rand_int_weak (256);

      out = tr_base64_encode (buf, j, &len);
      check_uint_eq (strlen (out), len);
      in = tr_base64_decode (out, len, &len);
      check_uint_eq (j, len);
      check (memcmp (in, buf, len) == 0);
      tr_free (in);
      tr_free (out);

      for (j = 0; j < i; ++j)
        buf[j] = (char)(1 + tr_rand_int_weak (255));
      buf[j] = '\0';

      out = tr_base64_encode_str (buf, &len);
      check_uint_eq (strlen (out), len);
      in = tr_base64_decode_str (out, &len);
      check_uint_eq (j, len);
      check_streq (in, buf);
      tr_free (in);
      tr_free (out);
    }

#undef MAX_BUF_SIZE

  return 0;
}

int
main (void)
{
  const testFunc tests[] = { test_torrent_hash,
                             test_encrypt_decrypt,
                             test_sha1,
                             test_ssha1,
                             test_random,
                             test_base32,
                             test_base64 };

  return runTests (tests, NUM_TESTS (tests));
}
