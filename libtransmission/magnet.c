/*
 * This file Copyright (C) 2010-2014 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 */

#include <assert.h>
#include <string.h> /* strchr () */
#include <stdio.h> /* sscanf () */

#include "transmission.h"
#include "crypto-utils.h" /* tr_hex_to_sha1 () */
#include "magnet.h"
#include "variant.h"
#include "web.h"

/***
****
***/

#define MAX_TRACKERS 64
#define MAX_WEBSEEDS 64

tr_magnet_info *
tr_magnetParse (const char * uri)
{
  bool got_checksum = false;
  int trCount = 0;
  int wsCount = 0;
  char * tr[MAX_TRACKERS];
  char * ws[MAX_WEBSEEDS];
  char * displayName = NULL;
  uint8_t sha1[SHA_DIGEST_LENGTH];
  tr_magnet_info * info = NULL;

  if (uri != NULL && memcmp (uri, "magnet:?", 8) == 0)
    {
      const char * walk;

      for (walk=uri+8; walk && *walk;)
        {
          const char * key = walk;
          const char * delim = strchr (key, '=');
          const char * val = delim == NULL ? NULL : delim + 1;
          const char * next = strchr (delim == NULL ? key : val, '&');
          size_t keylen, vallen;

          if (delim != NULL)
            keylen = (size_t) (delim - key);
          else if (next != NULL)
            keylen = (size_t) (next - key);
          else
            keylen = strlen (key);

          if (val == NULL)
            vallen = 0;
          else if (next != NULL)
            vallen = (size_t) (next - val);
          else
            vallen = strlen (val);

          if (keylen == 2 && memcmp (key, "xt", 2) == 0 && val != NULL && memcmp (val, "urn:btih:", 9) == 0)
            {
              const char * hash = val + 9;
              const size_t hashlen = vallen - 9;

              if (hashlen == 40)
                {
                  tr_hex_to_sha1 (sha1, hash);
                  got_checksum = true;
                }
              else if (hashlen == 32)
                {
                  tr_base32_decode (hash, hashlen, sha1, NULL);
                  got_checksum = true;
                }
            }

          if (vallen > 0 && keylen == 2 && memcmp (key, "dn", 2) == 0)
            displayName = tr_http_unescape (val, vallen);

          if ((vallen > 0) && (trCount < MAX_TRACKERS))
            {
              int i;
              if (keylen == 2 && memcmp (key, "tr", 2) == 0)
                tr[trCount++] = tr_http_unescape (val, vallen);
              else if ((sscanf (key, "tr.%d=", &i) == 1) && (i >= 0)) /* ticket #3341 and #5134 */
                tr[trCount++] = tr_http_unescape (val, vallen);
            }

          if (vallen > 0 && keylen == 2 && memcmp (key, "ws", 2) == 0 && wsCount < MAX_WEBSEEDS)
            ws[wsCount++] = tr_http_unescape (val, vallen);

          walk = next != NULL ? next + 1 : NULL;
        }
    }

  if (got_checksum)
    {
      info = tr_new0 (tr_magnet_info, 1);
      info->displayName = displayName;
      info->trackerCount = trCount;
      info->trackers = tr_memdup (tr, sizeof (char*) * trCount);
      info->webseedCount = wsCount;
      info->webseeds = tr_memdup (ws, sizeof (char*) * wsCount);
      memcpy (info->hash, sha1, sizeof (uint8_t) * SHA_DIGEST_LENGTH);
    }

  return info;
}

void
tr_magnetFree (tr_magnet_info * info)
{
  if (info != NULL)
    {
      int i;

      for (i=0; i<info->trackerCount; ++i)
        tr_free (info->trackers[i]);
      tr_free (info->trackers);

      for (i=0; i<info->webseedCount; ++i)
        tr_free (info->webseeds[i]);
      tr_free (info->webseeds);

      tr_free (info->displayName);
      tr_free (info);
    }
}

void
tr_magnetCreateMetainfo (const tr_magnet_info * info, tr_variant * top)
{
  int i;
  tr_variant * d;
  tr_variantInitDict (top, 4);

  /* announce list */
  if (info->trackerCount == 1)
    {
      tr_variantDictAddStr (top, TR_KEY_announce, info->trackers[0]);
    }
  else
    {
      tr_variant * trackers = tr_variantDictAddList (top, TR_KEY_announce_list, info->trackerCount);
      for (i=0; i<info->trackerCount; ++i)
        tr_variantListAddStr (tr_variantListAddList (trackers, 1), info->trackers[i]);
    }

  /* webseeds */
  if (info->webseedCount > 0)
    {
      tr_variant * urls = tr_variantDictAddList (top, TR_KEY_url_list, info->webseedCount);
      for (i=0; i<info->webseedCount; ++i)
        tr_variantListAddStr (urls, info->webseeds[i]);
    }

  /* nonstandard keys */
  d = tr_variantDictAddDict (top, TR_KEY_magnet_info, 2);
  tr_variantDictAddRaw (d, TR_KEY_info_hash, info->hash, 20);
  if (info->displayName != NULL)
    tr_variantDictAddStr (d, TR_KEY_display_name, info->displayName);
}


