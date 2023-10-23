#include "config.h"
#include "main.h"

#include <unistd.h>

static gboolean
install (const char *path, const char *relative_to, const char *destination_dir, gboolean toplevel)
{
  struct stat st;
  gboolean success = TRUE;

  int res = lstat (path, &st);
  if (res < 0)
    {
      g_printerr ("Can't access '%s': %s\n", path, strerror (errno));
      return FALSE;
    }

  int type = st.st_mode & S_IFMT;
  if (type == S_IFREG || type == S_IFLNK)
    {
      g_autofree char *sig_path = g_strconcat (path, ".sig", NULL);

      g_autofree char *signature = NULL;
      gsize signature_len = 0;

      g_autoptr (GError) error = NULL;
      if (!g_file_get_contents (sig_path, &signature, &signature_len, &error))
        {
          if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            g_printerr ("No signature for '%s'\n", path);
          else
            g_printerr ("Failed to load '%s': %s\n", sig_path, error->message);
          return FALSE;
        }

      g_autofree guchar *content = NULL;
      gsize content_len = 0;
      if (!load_file_data_for_sign (path, &st, NULL, &content, &content_len, &error))
        {
          g_printerr ("Failed to load '%s': %s\n", path, error->message);
          return FALSE;
        }

      g_autofree char *rel_path = opt_get_relative_path (path, relative_to);
      if (rel_path == NULL)
        {
          g_printerr ("File '%s' not inside relative dir\n", path);
          return FALSE;
        }

      g_autoptr (GError) validate_error = NULL;
      if (!validate_data (rel_path, type, content, content_len, signature, signature_len,
                          opt_public_keys, &validate_error))
        {
          if (validate_error)
            g_printerr ("Signature of '%s' (as '%s') is invalid: %s\n", path, rel_path,
                        validate_error->message);
          else
            g_printerr ("Signature of '%s' (as '%s') is invalid\n", path, rel_path);
          return FALSE;
        }

      g_autofree char *basename = g_path_get_basename (path);
      g_autofree char *destination_file = g_build_filename (destination_dir, basename, NULL);

      if (!opt_force && g_file_test (destination_file, G_FILE_TEST_EXISTS))
        {
          g_info ("File '%s' already exist, ignoring", destination_file);
          return TRUE;
        }

      if (type == S_IFLNK)
        {
          (void)unlink (destination_file);
          res = symlink ((char *)content, destination_file);
          if (res < 0)
            {
              g_printerr ("Can't create symlink '%s': %s\n", destination_file, strerror (errno));
              return FALSE;
            }
        }
      else
        {
          if (!g_file_set_contents (destination_file, (char *)content, content_len, &error))
            {
              g_printerr ("Can't write '%s': %s\n", destination_file, error->message);
              return FALSE;
            }
        }
      g_info ("Installed file '%s'", destination_file);
    }
  else if (type == S_IFDIR)
    {
      g_autoptr (GError) dir_error = NULL;
      g_autoptr (GDir) dir = g_dir_open (path, 0, &dir_error);
      if (dir == NULL)
        {
          if (g_error_matches (dir_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            return TRUE;

          g_printerr ("Failed to open dir '%s': %s\n", path, strerror (errno));
          return FALSE;
        }

      g_autofree char *basename = g_path_get_basename (path);
      g_autofree char *destination_subdir
          = g_build_filename (destination_dir, toplevel ? NULL : basename, NULL);

      if (!toplevel)
        {
          res = mkdir (destination_subdir, 0755);
          if (res < 0)
            {
              if (errno != EEXIST)
                {
                  g_printerr ("Can't create directory '%s': %s\n", destination_subdir,
                              strerror (errno));
                  return FALSE;
                }
            }
          else
            g_info ("Created directory '%s'", destination_subdir);
        }

      const char *child;
      while ((child = g_dir_read_name (dir)) != NULL)
        {
          if (g_str_has_suffix (child, ".sig"))
            continue; /* Skip existing signatures */

          g_autofree char *child_path = g_build_filename (path, child, NULL);
          if (!install (child_path, relative_to, destination_subdir, FALSE))
            success = FALSE;
        }
    }
  else
    {
      g_printerr ("Can't validate '%s' due to unsupported file type'\n", path);
      success = FALSE;
    }

  return success;
}

int
cmd_install (int argc, char *argv[])
{
  g_autoptr (GError) error = NULL;

  if (argc == 1)
    help_error ("No source files given");

  if (argc == 2)
    help_error ("No destination given");

  const char *destination = argv[argc - 1];

  gboolean res = TRUE;
  for (gsize i = 1; i < argc - 1; i++)
    {
      g_autofree char *path = g_canonicalize_filename (argv[i], NULL);

      if (g_file_test (path, G_FILE_TEST_IS_DIR))
        {
          if (!opt_recursive)
            {
              g_printerr ("error: '%s' is a directory and not in recursive mode\n", path);
              return EXIT_FAILURE;
            }

          if (!install (path, opt_path_relative ? opt_path_relative : path, destination, TRUE))
            res = FALSE;
        }
      else
        {
          g_autofree char *dirname = g_path_get_dirname (path);

          if (!install (path, dirname, destination, TRUE))
            res = FALSE;
        }
    }

  return res ? 0 : 1;
}
