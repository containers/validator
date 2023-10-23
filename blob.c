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

  struct stat st;
  int res = lstat (path, &st);
  if (res < 0)
    {
      g_printerr ("Can't access '%s': %s\n", path, strerror (errno));
      return EXIT_FAILURE;
    }

  int type = st.st_mode & S_IFMT;

  g_autofree char *rel_path
      = opt_get_relative_path (path, opt_path_relative ? opt_path_relative : dirname);
  if (rel_path == NULL)
    {
      g_printerr ("File '%s' not inside relative dir\n", path);
      return EXIT_FAILURE;
    }

  g_autofree guchar *content = NULL;
  gsize content_len = 0;
  if (!load_file_data_for_sign (path, &st, NULL, &content, &content_len, &error))
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

  res = write_to_fd (1, blob, blob_size);
  if (res < 0)
    {
      g_printerr ("%s\n", strerror (errno));
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}
