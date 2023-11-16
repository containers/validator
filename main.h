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

#include "utils.h"
#include <glib.h>

extern gboolean opt_recursive;
extern gboolean opt_force;
extern char *opt_key;
extern char **opt_keys;
extern char **opt_key_dirs;
extern char **opt_configs;
extern char **opt_config_dirs;
extern char *opt_path_prefix;
extern char *opt_path_relative;

/* Computed */
extern GList *opt_public_keys;
extern EVP_PKEY *opt_private_key;

int cmd_sign (int argc, char *argv[]);
int cmd_validate (int argc, char *argv[]);
int cmd_install (int argc, char *argv[]);
int cmd_blob (int argc, char *argv[]);

void help_error (const char *error_msg_fmt, ...);
char *opt_get_relative_path (const char *path, const char *relative_to,
                             const char *optional_path_prefix);

GList *read_public_keys (const char **keys, const char **key_dirs);
