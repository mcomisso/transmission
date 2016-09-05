/*
 * This file Copyright (C) 2013-2014 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transmission.h"
#include "session.h"
#include "session-id.h"
#include "utils.h"
#include "version.h"

#undef VERBOSE
#include "libtransmission-test.h"

static int
testPeerId (void)
{
    int i;
    uint8_t peer_id[PEER_ID_LEN+1];

    for (i = 0; i < 100000; ++i)
    {
        int j;
        int val = 0;

        tr_peerIdInit (peer_id);

        check (strlen ((char*)peer_id) == PEER_ID_LEN);
        check (memcmp (peer_id, PEERID_PREFIX, 8) == 0);

        for (j = 8; j < PEER_ID_LEN; ++j)
        {
            char tmp[2] = { (char)peer_id[j], '\0' };
            val += strtoul (tmp, NULL, 36);
        }

        check ((val % 36) == 0);
    }

    return 0;
}

static int
test_session_id (void)
{
  tr_session_id_t session_id;
  const char * session_id_str;

  session_id = tr_session_id_new ();
  check (session_id != NULL);

  session_id_str = tr_session_id_get_current (session_id);
  check (session_id_str != NULL);
  check (strlen (session_id_str) == 48);

  check (tr_session_id_is_local (session_id_str));

  check (!tr_session_id_is_local (NULL));
  check (!tr_session_id_is_local (""));
  check (!tr_session_id_is_local ("test"));

  tr_session_id_free (session_id);
  return 0;
}

int
main (void)
{
  const testFunc tests[] = { testPeerId,
                             test_session_id };

  return runTests (tests, NUM_TESTS (tests));
}
