/*
 * This file Copyright (C) 2016 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 */

#if defined (_WIN32)
 #define HAVE_SEMAPHORES
 #define HAVE_WIN32_SEMAPHORES
#elif defined (HAVE_SEMAPHORE_H)
 #define HAVE_SEMAPHORES
 #define HAVE_POSIX_SEMAPHORES
#endif

#include <assert.h>
#include <string.h>
#include <time.h>

#if defined (HAVE_POSIX_SEMAPHORES)
 #include <errno.h>
 #include <fcntl.h>
 #include <semaphore.h>
 #define SEMAPHORE_NAME_PREFIX "/tr-"
 #define BAD_SEMAPHORE SEM_FAILED
 typedef sem_t * tr_semaphore_t;
#elif defined (HAVE_WIN32_SEMAPHORES)
 #include <windows.h>
 #define SEMAPHORE_NAME_PREFIX "Global\\tr-"
 #define BAD_SEMAPHORE NULL
 typedef HANDLE tr_semaphore_t;
#endif

#include "transmission.h"
#include "crypto-utils.h"
#include "log.h"
#include "session-id.h"
#include "utils.h"

#define SESSION_ID_SIZE         48
#define SESSION_ID_DURATION_SEC (60 * 60) /* expire in an hour */

struct tr_session_id
{
  char   * current_value;
  char   * previous_value;
  time_t   expires_at;

#if defined (HAVE_SEMAPHORES)
  tr_semaphore_t current_semaphore;
  tr_semaphore_t previous_semaphore;
#endif
};

static char *
generate_new_session_id_value (void)
{
  const char   pool[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const size_t pool_size = sizeof (pool) - 1;

  char * buf = tr_new (char, SESSION_ID_SIZE + 1);

  tr_rand_buffer (buf, SESSION_ID_SIZE);
  for (size_t i = 0; i < SESSION_ID_SIZE; ++i)
    buf[i] = pool[(unsigned char) buf[i] % pool_size];
  buf[SESSION_ID_SIZE] = '\0';

  return buf;
}

#if defined (HAVE_SEMAPHORES)

static char *
get_session_id_semaphore_name (const char * session_id)
{
  uint8_t session_id_md5[MD5_DIGEST_LENGTH];
  tr_md5 (session_id_md5, session_id, (int) strlen (session_id), NULL);

#ifndef NDEBUG
  size_t session_id_md5_base32_size;
  tr_base32_encode (session_id_md5, sizeof (session_id_md5), NULL, &session_id_md5_base32_size);
  assert (session_id_md5_base32_size == 26);
#endif

  char session_id_md5_base32[26 + 1];
  tr_base32_encode (session_id_md5, sizeof (session_id_md5), session_id_md5_base32, NULL);
  session_id_md5_base32[26] = '\0';

  return tr_strdup_printf (SEMAPHORE_NAME_PREFIX "%s", session_id_md5_base32);
}

static tr_semaphore_t
create_session_id_semaphore (const char * session_id)
{
  if (session_id == NULL)
    return BAD_SEMAPHORE;

  char           * semaphore_name = get_session_id_semaphore_name (session_id);
  tr_semaphore_t   semaphore;
  char           * error_message = NULL;

#if defined (HAVE_POSIX_SEMAPHORES)

  semaphore = sem_open (semaphore_name, O_CREAT | O_EXCL, 0666, 0);

  if (semaphore == BAD_SEMAPHORE)
    {
      const int error_code = errno;
      error_message = tr_strdup_printf ("sem_open(%s) failed (%d): %s", semaphore_name, error_code, tr_strerror (error_code));
    }

#elif defined (HAVE_WIN32_SEMAPHORES)

  semaphore = CreateSemaphoreA (NULL, 0, 1, semaphore_name);

  const DWORD error_code = GetLastError ();
  if (semaphore == BAD_SEMAPHORE || error_code == ERROR_ALREADY_EXISTS)
    {
      char * tmp_message = tr_win32_format_message (error_code);
      error_message = tr_strdup_printf ("CreateSemaphore(%s) failed (0x%08x): %s", semaphore_name, error_code, tmp_message);
      tr_free (tmp_message);

      if (semaphore != BAD_SEMAPHORE)
        {
          CloseHandle (semaphore);
          semaphore = BAD_SEMAPHORE;
        }
    }

#endif

  if (error_message != NULL)
    {
      tr_logAddError ("Unable to create session semaphore: %s", error_message);
      tr_free (error_message);
    }

  tr_free (semaphore_name);
  return semaphore;
}

static void
destroy_semaphore (tr_semaphore_t semaphore)
{
  if (semaphore == BAD_SEMAPHORE)
    return;

#if defined (HAVE_POSIX_SEMAPHORES)
  sem_close (semaphore);
#elif defined (HAVE_WIN32_SEMAPHORES)
  CloseHandle (semaphore);
#endif
}

#endif

tr_session_id_t
tr_session_id_new (void)
{
  return tr_new0 (struct tr_session_id, 1);
}

void
tr_session_id_free (tr_session_id_t session_id)
{
  if (session_id == NULL)
    return;

#if defined (HAVE_SEMAPHORES)

  destroy_semaphore (session_id->previous_semaphore);
  destroy_semaphore (session_id->current_semaphore);

#endif

  tr_free (session_id->previous_value);
  tr_free (session_id->current_value);
  tr_free (session_id);
}

const char *
tr_session_id_get_current (tr_session_id_t session_id)
{
  const time_t now = tr_time ();

  if (session_id->current_value == NULL || now >= session_id->expires_at)
    {
      tr_free (session_id->previous_value);
      session_id->previous_value = session_id->current_value;
      session_id->current_value = generate_new_session_id_value ();

#if defined (HAVE_SEMAPHORES)

      destroy_semaphore (session_id->previous_semaphore);
      session_id->previous_semaphore = session_id->current_semaphore;
      session_id->current_semaphore = create_session_id_semaphore (session_id->current_value);

#endif

      session_id->expires_at = now + SESSION_ID_DURATION_SEC;
    }

  return session_id->current_value;
}

bool
tr_session_id_is_local (const char * session_id)
{
  bool ret = false;

  if (session_id != NULL)
    {
#if defined (HAVE_SEMAPHORES)

      char           * semaphore_name = get_session_id_semaphore_name (session_id);
      tr_semaphore_t   semaphore;
      char           * error_message = NULL;

#if defined (HAVE_POSIX_SEMAPHORES)

      semaphore = sem_open (semaphore_name, 0);

      if (semaphore == BAD_SEMAPHORE)
        {
          const int error_code = errno;
          if (error_code != ENOENT)
            {
              error_message = tr_strdup_printf ("sem_open(%s) failed (%d): %s", semaphore_name, error_code, tr_strerror (error_code));
            }
        }

#elif defined (HAVE_WIN32_SEMAPHORES)

      semaphore = OpenSemaphoreA (SYNCHRONIZE, FALSE, semaphore_name);

      if (semaphore == BAD_SEMAPHORE)
        {
          const DWORD error_code = GetLastError ();
          if (error_code != ERROR_FILE_NOT_FOUND)
            {
              char * tmp_message = tr_win32_format_message (error_code);
              error_message = tr_strdup_printf ("OpenSemaphore(%s) failed (0x%08x): %s", semaphore_name, error_code, tmp_message);
              tr_free (tmp_message);
            }
        }

#endif

      if (semaphore != BAD_SEMAPHORE)
        {
          destroy_semaphore (semaphore);
          ret = true;
        }
      else if (error_message != NULL)
        {
          tr_logAddError ("Unable to open session semaphore: %s", error_message);
          tr_free (error_message);
        }

      tr_free (semaphore_name);

#endif
    }

  return ret;
}
