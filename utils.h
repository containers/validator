#include <glib.h>

#include <openssl/evp.h>
#include <sys/stat.h>

#define VALIDATOR_SIGNATURE_MAGIC "VALIDTR\001"
#define VALIDATOR_SIGNATURE_MAGIC_LEN 8

G_DEFINE_AUTOPTR_CLEANUP_FUNC (FILE, fclose)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_MD_CTX, EVP_MD_CTX_free)

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__ ({ \
    long int __result; \
    do \
      __result = (long int)(expression); \
    while (__result == -1L && errno == EINTR); \
    __result; \
  }))
#endif

static inline int
steal_fd (int *fdp)
{
  int fd = *fdp;
  *fdp = -1;
  return fd;
}

static inline void
close_fd (int *fdp)
{
  int errsv;

  g_assert (fdp);

  int fd = steal_fd (fdp);
  if (fd >= 0)
    {
      errsv = errno;
      if (close (fd) < 0)
        g_assert (errno != EBADF);
      errno = errsv;
    }
}

#define autofd __attribute__ ((cleanup (close_fd)))

void oom (void);
gboolean has_path_prefix (const char *str, const char *prefix);
void free_keys (GList *keys);
EVP_PKEY *load_priv_key (const char *path, GError **error);
EVP_PKEY *load_pub_key (const char *path, GError **error);
gboolean load_pub_keys_from_dir (const char *key_dir, GList **out_keys, GError **error);
gboolean validate_data (const char *rel_path, int type, guchar *content, gsize content_size,
                        char *sig, gsize sig_size, GList *pub_keys, GError **error);
guchar *make_sign_blob (const char *rel_path, int type, const guchar *content, gsize content_len,
                        gsize *out_size, GError **error);
gboolean sign_data (int type, const char *rel_path, const guchar *data, gsize data_len,
                    EVP_PKEY *pkey, guchar **signature_out, gsize *signature_len_out,
                    GError **error);
gboolean load_file_data_for_sign (const char *path, struct stat *st, int *type_out,
                                  guchar **content_out, gsize *content_len_out, int *fd_out,
                                  GError **error);
int write_to_fd (int fd, const guchar *content, gsize len);
int copy_fd (int from_fd, int to_fd);
