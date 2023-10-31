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

#include "config.h"
#include "main.h"

int
cmd_blob (int argc, char *argv[])
{
  g_autoptr (GError) error = NULL;

  if (argc == 1)
    help_error ("No input files given");

  if (argc > 2)
    help_error ("Only one file argument supported");

  g_autofree char *path = g_canonicalize_filename (argv[1], NULL);
  g_autofree char *dirname = g_path_get_dirname (path);

  g_autofree char *rel_path
      = opt_get_relative_path (path, opt_path_relative ? opt_path_relative : dirname);
  if (rel_path == NULL)
    {
      g_printerr ("File '%s' not inside relative dir\n", path);
      return EXIT_FAILURE;
    }

  int type;
  g_autofree guchar *content = NULL;
  gsize content_len = 0;
  if (!load_file_data_for_sign (path, NULL, &type, &content, &content_len, NULL, &error))
    {
      g_printerr ("Failed to load '%s': %s\n", path, error->message);
      return EXIT_FAILURE;
    }

  gsize blob_size;
  g_autofree guchar *blob
      = make_sign_blob (rel_path, type, content, content_len, &blob_size, &error);
  if (blob == NULL)
    {
      g_printerr ("%s\n", error->message);
      return EXIT_FAILURE;
    }

  int res = write_to_fd (1, blob, blob_size);
  if (res < 0)
    {
      g_printerr ("%s\n", strerror (errno));
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}
