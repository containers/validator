#include "utils.h"
#include <glib.h>

extern gboolean opt_recursive;
extern gboolean opt_force;
extern char *opt_key;
extern char **opt_keys;
extern char **opt_key_dirs;
extern char *opt_path_prefix;
extern char *opt_path_relative;

/* Computed */
extern GList *opt_public_keys;
extern EVP_PKEY *opt_private_key;

int cmd_sign (int argc, char *argv[]);
int cmd_validate (int argc, char *argv[]);
int cmd_install (int argc, char *argv[]);

void help_error (const char *error_msg_fmt, ...);
char *opt_get_relative_path (const char *path, const char *relative_to);
