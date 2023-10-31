/*
 * Copyright © 2023 Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Alexander Larsson <alexl@redhat.com>
 */

#include <config.h>

#include "utils.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <unistd.h>

void
free_keys (GList *keys)
{
  for (GList *l = keys; l != NULL; l = l->next)
    EVP_PKEY_free (l->data);
  g_list_free (keys);
}

static const char *
get_ssl_error_reason (void)
{
  unsigned long e = ERR_get_error ();
  return ERR_reason_error_string (e);
}

static gboolean
fail_ssl_with_val_v (GError **error, int errval, const gchar *format, va_list args)
{
  g_autofree char *msg = g_strdup_vprintf (format, args);
  g_set_error (error, G_FILE_ERROR, errval, "%s: %s", msg, get_ssl_error_reason ());
  return FALSE;
}

static gboolean
fail_ssl_with_val (GError **error, int errval, const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  fail_ssl_with_val_v (error, errval, msg, args);
  va_end (args);

  return FALSE;
}

static gboolean
fail_ssl (GError **error, const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  fail_ssl_with_val_v (error, G_FILE_ERROR_FAILED, msg, args);
  va_end (args);

  return FALSE;
}

EVP_PKEY *
load_pub_key (const char *path, GError **error)
{
  g_autoptr (FILE) file = NULL;

  file = fopen (path, "rb");
  if (file == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't load key %s: %s",
                   path, strerror (errno));
      return NULL;
    }

  g_autoptr (EVP_PKEY) pkey = PEM_read_PUBKEY (file, NULL, NULL, NULL);
  if (pkey == NULL)
    {
      fail_ssl_with_val (error, G_FILE_ERROR_INVAL, "Can't parse public key %s", path);
      return NULL;
    }

  g_info ("Loaded public key '%s'", path);

  return g_steal_pointer (&pkey);
}

EVP_PKEY *
load_priv_key (const char *path, GError **error)
{
  g_autoptr (FILE) file = NULL;

  file = fopen (path, "rb");
  if (file == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't load key %s: %s",
                   path, strerror (errno));
      return NULL;
    }

  g_autoptr (EVP_PKEY) pkey = PEM_read_PrivateKey (file, NULL, NULL, NULL);
  if (pkey == NULL)
    {
      fail_ssl_with_val (error, G_FILE_ERROR_INVAL, "Can't parse private key %s", path);
      return NULL;
    }

  g_info ("Loaded private key '%s'", path);

  return g_steal_pointer (&pkey);
}

gboolean
load_pub_keys_from_dir (const char *key_dir, GList **out_keys, GError **error)
{
  GList *keys = NULL;

  g_autoptr (GError) my_error = NULL;
  g_autoptr (GDir) dir = g_dir_open (key_dir, 0, &my_error);
  if (dir == NULL)
    {
      if (g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        {
          *out_keys = NULL;
          return TRUE;
        }

      g_propagate_prefixed_error (error, my_error, "Can't enumerate key dir %s: ", key_dir);
      return FALSE;
    }

  const char *filename;
  while ((filename = g_dir_read_name (dir)) != NULL)
    {
      g_autofree char *path = g_build_filename (key_dir, filename, NULL);

      g_autoptr (EVP_PKEY) pkey = load_pub_key (path, &my_error);
      if (pkey == NULL)
        {
          if (!g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)
              && !g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_ISDIR))
            {
              g_propagate_error (error, g_steal_pointer (&my_error));
              return FALSE;
            }
          g_clear_error (&my_error);
        }
      else
        {
          keys = g_list_prepend (keys, g_steal_pointer (&pkey));
        }
    }

  *out_keys = keys;
  return TRUE;
}

guchar *
make_sign_blob (const char *rel_path, int type, const guchar *content, gsize content_len,
                gsize *out_size, GError **error)
{
  gsize rel_path_len = strlen (rel_path);
  gsize to_sign_len = 1 + rel_path_len + 1 + content_len;
  g_autofree guchar *to_sign = g_malloc (to_sign_len);

  guchar *dst = to_sign;
  if (type == S_IFREG)
    *dst++ = 0;
  else if (type == S_IFLNK)
    *dst++ = 1;
  else
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "Unsupported file type");
      return NULL;
    }

  memcpy (dst, rel_path, rel_path_len);
  dst += rel_path_len;
  *dst++ = 0;
  memcpy (dst, content, content_len);
  dst += content_len;

  *out_size = to_sign_len;
  return g_steal_pointer (&to_sign);
}

gboolean
validate_data (const char *rel_path, int type, guchar *content, gsize content_len, char *sig,
               gsize sig_size, GList *pub_keys, GError **error)
{
  gsize to_sign_len;
  g_autofree guchar *to_sign
      = make_sign_blob (rel_path, type, content, content_len, &to_sign_len, NULL);
  if (to_sign == NULL)
    return FALSE;

  gboolean valid = FALSE;
  for (GList *l = pub_keys; l != NULL; l = l->next)
    {
      EVP_PKEY *key = l->data;

      g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
      if (!ctx)
        return fail_ssl (error, "Can't init context");

      if (EVP_DigestVerifyInit (ctx, NULL, NULL, NULL, key) == 0)
        return fail_ssl (error, "Can't initialzie digest verify operation");

      int res = EVP_DigestVerify (ctx, (unsigned char *)sig, sig_size, (unsigned char *)to_sign,
                                  to_sign_len);
      if (res == 1)
        {
          valid = TRUE;
          break;
        }
      else if (res != 0)
        return fail_ssl (error, "Error validating digest");
    }

  return valid;
}

gboolean
load_file_data_for_sign (const char *path, struct stat *st, int *type_out, guchar **content_out,
                         gsize *content_len_out, GError **error)
{

  struct stat st_buf;
  if (st == NULL)
    {
      int res = lstat (path, &st_buf);
      if (res < 0)
        {
          g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't stat %s: %s",
                       path, strerror (errno));
          return FALSE;
        }
      st = &st_buf;
    }

  int type = st->st_mode & S_IFMT;
  if (type != S_IFREG && type != S_IFLNK)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Unsupported file tye %s",
                   path);
      return FALSE;
    }

  g_autofree char *content = NULL;
  gsize content_len = 0;

  if (type == S_IFREG)
    {
      if (!g_file_get_contents (path, &content, &content_len, error))
        return FALSE;
    }
  else
    {
      content = g_file_read_link (path, error);
      if (content == NULL)
        return FALSE;
      content_len = strlen (content);
    }

  if (type_out)
    *type_out = type;
  *content_out = (guchar *)g_steal_pointer (&content);
  *content_len_out = content_len;

  return TRUE;
}

gboolean
sign_data (int type, const char *rel_path, const guchar *content, gsize content_len, EVP_PKEY *pkey,
           guchar **signature_out, gsize *signature_len_out, GError **error)
{
  gsize to_sign_len;
  g_autofree guchar *to_sign
      = make_sign_blob (rel_path, type, content, content_len, &to_sign_len, error);
  if (to_sign == NULL)
    return FALSE;

  g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
  if (!ctx)
    return fail_ssl (error, "Can't init context");

  if (EVP_DigestSignInit (ctx, NULL, NULL, NULL, pkey) == 0)
    return fail_ssl (error, "Can't initialize signature operation");

  gsize signature_len = 0;
  if (EVP_DigestSign (ctx, NULL, &signature_len, to_sign, to_sign_len) == 0)
    return fail_ssl (error, "Error getting signature size");

  g_autofree guchar *signature = g_malloc (signature_len);
  if (EVP_DigestSign (ctx, signature, &signature_len, to_sign, to_sign_len) == 0)
    return fail_ssl (error, "Error signing data");

  *signature_out = g_steal_pointer (&signature);
  *signature_len_out = signature_len;

  return TRUE;
}

gboolean
has_path_prefix (const char *str, const char *prefix)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*str == '/')
        str++;
      while (*prefix == '/')
        prefix++;

      /* No more prefix path elements? Done! */
      if (*prefix == 0)
        return TRUE;

      /* Compare path element */
      while (*prefix != 0 && *prefix != '/')
        {
          if (*str != *prefix)
            return FALSE;
          str++;
          prefix++;
        }

      /* Matched prefix path element,
         must be entire str path element */
      if (*str != '/' && *str != 0)
        return FALSE;
    }
}

int
write_to_fd (int fd, const guchar *content, gsize len)
{
  gssize res;

  while (len > 0)
    {
      res = write (fd, content, len);
      if (res < 0 && errno == EINTR)
        continue;
      if (res <= 0)
        {
          if (res == 0) /* Unexpected short write, should not happen when writing to a file */
            errno = ENOSPC;
          return -1;
        }
      len -= res;
      content += res;
    }

  return 0;
}
