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

#include <glib.h>
#include <stdarg.h>

#include <sys/stat.h>

#include "main.h"

gboolean opt_recursive;
gboolean opt_force;
char *opt_key;
char **opt_keys;
char **opt_key_dirs;
char *opt_path_prefix;
char *opt_path_relative;
char *opt_config;
static int opt_verbose;
static gboolean opt_help;
static gboolean opt_version;

/* Computed */
GList *opt_public_keys;
EVP_PKEY *opt_private_key;

static gboolean
opt_verbose_cb (const gchar *option_name, const gchar *value, gpointer data, GError **error)
{
  opt_verbose++;
  return TRUE;
}

GOptionEntry global_entries[]
    = { { "verbose", 'v', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, &opt_verbose_cb,
          "Show debug information", NULL },
        { "help", '?', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &opt_help, NULL, NULL },
        { "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print version information and exit",
          NULL },
        { NULL } };

GOptionEntry privkey_entries[]
    = { { "key", 0, 0, G_OPTION_ARG_FILENAME, &opt_key, "Private key to sign with", "FILE" },
        { NULL } };

GOptionEntry pubkey_entries[] = { { "key", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_keys,
                                    "Public key to validate with", "FILE" },
                                  { "key-dir", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_key_dirs,
                                    "Directory of public keys to validate with", "FILE" },
                                  { NULL } };

GOptionEntry sign_entries[]
    = { { "recursive", 'r', 0, G_OPTION_ARG_NONE, &opt_recursive, "Sign files recursively", NULL },
        { "relative-to", 0, 0, G_OPTION_ARG_FILENAME, &opt_path_relative,
          "Sign relative to this directory", NULL },
        { "path-prefix", 'p', 0, G_OPTION_ARG_FILENAME, &opt_path_prefix,
          "Add prefix to signed paths", NULL },
        { "force", 'f', 0, G_OPTION_ARG_NONE, &opt_force, "Force signatures (replace existing)",
          NULL },
        { NULL } };

GOptionEntry validate_entries[]
    = { { "relative-to", 0, 0, G_OPTION_ARG_FILENAME, &opt_path_relative,
          "Validate relative to this directory", NULL },
        { "recursive", 'r', 0, G_OPTION_ARG_NONE, &opt_recursive, "Validate files recursively",
          NULL },
        { NULL } };

GOptionEntry install_entries[] = { { "recursive", 'r', 0, G_OPTION_ARG_NONE, &opt_recursive,
                                     "Install files recursively", NULL },
                                   { "path-prefix", 'p', 0, G_OPTION_ARG_FILENAME, &opt_path_prefix,
                                     "Add prefix to validated path", NULL },
                                   { "relative-to", 0, 0, G_OPTION_ARG_FILENAME, &opt_path_relative,
                                     "Validate relative to this directory", NULL },
                                   {
                                       "force",
                                       'f',
                                       0,
                                       G_OPTION_ARG_NONE,
                                       &opt_force,
                                       "Replace existing files",
                                   },
                                   { NULL } };

GOptionEntry blob_entries[] = { { "relative-to", 0, 0, G_OPTION_ARG_FILENAME, &opt_path_relative,
                                  "Paths relative to this directory", NULL },
                                { "path-prefix", 'p', 0, G_OPTION_ARG_FILENAME, &opt_path_prefix,
                                  "Add prefix to relative paths", NULL },
                                { NULL } };

static void
message_handler (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message,
                 gpointer user_data)
{
  g_printerr ("%s\n", message);
}

void
help_error (const char *error_msg_fmt, ...)
{
  va_list args;

  va_start (args, error_msg_fmt);
  g_autofree char *error_msg = g_strdup_vprintf (error_msg_fmt, args);
  va_end (args);

  g_printerr ("%s\n"
              "\n"
              "See '%s --help' for usage.\n",
              error_msg, g_get_prgname ());
  exit (1);
}

static void
read_private_key (void)
{
  if (opt_key == NULL)
    help_error ("No private key given");

  g_autoptr (GError) error = NULL;
  opt_private_key = load_priv_key (opt_key, &error);
  if (opt_private_key == NULL)
    {
      g_printerr ("Can't load key: %s\n", error->message);
      exit (EXIT_FAILURE);
    }
}

static void
read_public_keys (void)
{
  if (opt_keys == NULL && opt_key_dirs == NULL)
    help_error ("No --key or --key-dirs argument given given");

  for (int i = 0; opt_keys != NULL && opt_keys[i] != NULL; i++)
    {
      const char *key_path = opt_keys[i];
      g_autoptr (GError) error = NULL;
      g_autoptr (EVP_PKEY) key = load_pub_key (key_path, &error);
      if (key == NULL)
        {
          g_printerr ("error: %s\n", error->message);
          exit (EXIT_FAILURE);
        }

      opt_public_keys = g_list_append (opt_public_keys, g_steal_pointer (&key));
    }

  for (int i = 0; opt_key_dirs != NULL && opt_key_dirs[i] != NULL; i++)
    {
      const char *key_dir_path = opt_key_dirs[i];

      GList *dir_keys;
      g_autoptr (GError) error = NULL;
      if (!load_pub_keys_from_dir (key_dir_path, &dir_keys, &error))
        {
          g_printerr ("error: %s\n", error->message);
          exit (EXIT_FAILURE);
        }

      opt_public_keys = g_list_concat (opt_public_keys, dir_keys);
    }
}

static const char *
extract_command (int *argc, char **argv)
{
  const char *command = NULL;
  int in, out;

  for (in = 1, out = 1; in < *argc; in++, out++)
    {
      /* The non-option is the command, take it out of the arguments */
      if (argv[in][0] != '-')
        {
          if (command == NULL)
            {
              command = argv[in];
              out--;
              continue;
            }
        }

      argv[out] = argv[in];
    }

  *argc = out;
  argv[out] = NULL;

  return command;
}

static void
canonicalize_opts (void)
{
  if (opt_path_relative)
    {
      g_autofree char *old = g_steal_pointer (&opt_path_relative);
      opt_path_relative = g_canonicalize_filename (old, NULL);
    }

  if (opt_path_prefix)
    {
      g_autofree char *canonical = g_canonicalize_filename (opt_path_prefix, "/");
      free (opt_path_prefix);
      /* Skip initial slash */
      opt_path_prefix = g_strdup (canonical + 1);
    }
}

enum
{
  COMMAND_PRIVKEY = 1 << 0,
  COMMAND_PUBKEYS = 1 << 1,
};

struct CommandInfo
{
  const char *name;
  GOptionEntry *entries;
  int flags;
  int (*cmd) (int argc, char *argv[]);
  const char *usage;
};

static struct CommandInfo commands[] = {
  { "sign", sign_entries, COMMAND_PRIVKEY, cmd_sign, "sign FILE [FILE...]" },
  { "validate", validate_entries, COMMAND_PUBKEYS, cmd_validate, "validate FILE [FILE...]" },
  { "install", install_entries, COMMAND_PUBKEYS, cmd_install,
    "install SOURCE [SOURCE..] DESTINATION" },
  { "blob", blob_entries, 0, cmd_blob, "blob FILE" },
};

static struct CommandInfo *
find_command (const char *name)
{
  for (int i = 0; i < G_N_ELEMENTS (commands); i++)
    {
      if (strcmp (commands[i].name, name) == 0)
        return &commands[i];
    }
  return NULL;
}

char *
opt_get_relative_path (const char *path, const char *relative_to, const char *optional_path_prefix)
{
  if (!has_path_prefix (path, relative_to))
    return NULL;

  const char *rel_path = path + strlen (relative_to);
  while (*rel_path == '/')
    rel_path++;

  if (optional_path_prefix)
    return g_build_filename (optional_path_prefix, rel_path, NULL);

  return g_strdup (rel_path);
}

int
main (int argc, char *argv[])
{
  g_set_prgname (argv[0]);

  g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING, message_handler,
                     NULL);

  const char *command_name = extract_command (&argc, argv);
  struct CommandInfo *command = NULL;
  if (command_name != NULL)
    {
      command = find_command (command_name);
      if (command == NULL)
        help_error ("Unsupported command '%s'", command_name);
    }

  g_autoptr (GOptionContext) context
      = g_option_context_new (command ? command->usage : "COMMAND ...");

  g_option_context_set_summary (context, "Available commands:\n"
                                         "  sign         Sign files\n"
                                         "  validate     Validate files\n"
                                         "  install      Install validated files\n"
                                         "  blob         Output blob for external signing\n");
  g_option_context_add_main_entries (context, global_entries, NULL);

  if (command != NULL)
    {
      g_option_context_add_main_entries (context, command->entries, NULL);
      if (command->flags & COMMAND_PRIVKEY)
        g_option_context_add_main_entries (context, privkey_entries, NULL);
      if (command->flags & COMMAND_PUBKEYS)
        g_option_context_add_main_entries (context, pubkey_entries, NULL);
    }

  g_autoptr (GError) error = NULL;
  if (!g_option_context_parse (context, &argc, &argv, &error))
    help_error (error->message);

  if (opt_verbose > 0)
    g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, message_handler, NULL);

  if (opt_verbose > 1)
    g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, message_handler, NULL);

  if (opt_version)
    {
      g_print ("%s\n", PACKAGE_STRING);
      return EXIT_SUCCESS;
    }

  if (command == NULL)
    help_error ("No command given");

  if (command->flags & COMMAND_PRIVKEY)
    read_private_key ();

  if (command->flags & COMMAND_PUBKEYS)
    read_public_keys ();

  canonicalize_opts ();

  return command->cmd (argc, argv);
}
