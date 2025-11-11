// audit_logger.c
// Build: gcc -fPIC -shared -o audit_logger.so audit_logger.c -ldl -lcrypto
// Usage: LD_PRELOAD=./audit_logger.so ./test_audit
// All comments are in English as requested.

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <limits.h>   // for PATH_MAX
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// ---- Spec constants ----
// Operation: 0=created, 1=opened, 2=written, 3=closed
#define OP_CREATED 0
#define OP_OPENED  1
#define OP_WRITTEN 2
#define OP_CLOSED  3

// Log path (system-wide). Can be overridden with AUDIT_LOG_PATH for testing.
static const char *DEFAULT_LOG_PATH = "/tmp/access_audit.log";

// ---- Real function pointers ----
static FILE *(*real_fopen)(const char *path, const char *mode) = NULL;
static size_t (*real_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static int (*real_fclose)(FILE *stream) = NULL;

// ---- Small map from FILE* to absolute path and creation flag ----
typedef struct FileMap {
    FILE *fp;
    char path[PATH_MAX];
    int was_created; // 1 if this stream corresponds to a newly created file
    struct FileMap *next;
} FileMap;

static FileMap *g_head = NULL;

// Prevent re-entrancy while we append to the log (avoid recursion into our fwrite).
static __thread int in_logger = 0;

// ---- Helpers ----
static const char* audit_log_path() {
    const char *env = getenv("AUDIT_LOG_PATH");
    return env && *env ? env : DEFAULT_LOG_PATH;
}

static void map_insert(FILE *fp, const char *abs_path, int was_created) {
    FileMap *node = (FileMap *)malloc(sizeof(FileMap));
    if (!node) return;
    node->fp = fp;
    strncpy(node->path, abs_path ? abs_path : "", sizeof(node->path)-1);
    node->path[sizeof(node->path)-1] = '\0';
    node->was_created = was_created;
    node->next = g_head;
    g_head = node;
}

static FileMap* map_find(FILE *fp) {
    for (FileMap *p = g_head; p; p = p->next) {
        if (p->fp == fp) return p;
    }
    return NULL;
}

static void map_remove(FILE *fp) {
    FileMap *prev = NULL;
    for (FileMap *p = g_head; p; prev = p, p = p->next) {
        if (p->fp == fp) {
            if (prev) prev->next = p->next;
            else g_head = p->next;
            free(p);
            return;
        }
    }
}

// Compute SHA-256 hex digest of a file path. Returns 1 on success, 0 on failure.
// On failure, out_hex is set to "-" string.
static int sha256_file(const char *path, char out_hex[65]) {
    out_hex[0] = '\0';
    if (!path || !*path) {
        strcpy(out_hex, "-");
        return 0;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        strcpy(out_hex, "-");
        return 0;
    }

    unsigned char buf[8192];
    unsigned char md[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        strcpy(out_hex, "-");
        return 0;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        strcpy(out_hex, "-");
        return 0;
    }
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        if (EVP_DigestUpdate(ctx, buf, (size_t)r) != 1) {
            EVP_MD_CTX_free(ctx);
            close(fd);
            strcpy(out_hex, "-");
            return 0;
        }
    }
    close(fd);
    if (r < 0) {
        EVP_MD_CTX_free(ctx);
        strcpy(out_hex, "-");
        return 0;
    }
    if (EVP_DigestFinal_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        strcpy(out_hex, "-");
        return 0;
    }
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(out_hex + (i*2), "%02x", md[i]);
    }
    out_hex[64] = '\0';
    return 1;
}

// Format UTC date and time as separate fields.
// date_out: YYYY-MM-DD, time_out: HH:MM:SS
static void utc_datetime(char date_out[11], char time_out[9]) {
    time_t now = time(NULL);
    struct tm g;
    gmtime_r(&now, &g);
    strftime(date_out, 11, "%Y-%m-%d", &g);
    strftime(time_out, 9, "%H:%M:%S", &g);
}

// Append one line to log using low-level write() to avoid recursion.
// Format: UID|PID|Filename|Date|Time|Operation|Denied|Hash\n
static void log_event(const char *filename, int operation, int denied, const char *hash_hex) {
    if (in_logger) return; // avoid recursion just in case
    in_logger = 1;

    char date[11], tbuf[9];
    utc_datetime(date, tbuf);

    uid_t uid = getuid();
    pid_t pid = getpid();
    const char *path = filename ? filename : "-";

    char line[PATH_MAX + 256];
    int n = snprintf(line, sizeof(line), "%u|%d|%s|%s|%s|%d|%d|%s\n",
                     (unsigned)uid, (int)pid, path, date, tbuf, operation, denied,
                     (hash_hex && *hash_hex) ? hash_hex : "-");

    int fd = open(audit_log_path(), O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) {
        ssize_t written = write(fd, line, (size_t)n);
        if (written < 0) {
            perror("write");
        }
        close(fd);
    }
    in_logger = 0;
}

// Determine if fopen mode attempts to create/truncate a file.
// We treat "w", "w+", "a", "a+", "x", "x+" as creation intents.
static int mode_creates_file(const char *mode) {
    if (!mode) return 0;
    // If 'x' or 'w' or 'a' present then it's a creation or truncation intent
    if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, 'x')) return 1;
    return 0;
}

// Resolve absolute path safely (returns input if realpath fails).
static void resolve_abs_path(const char *path, char out[PATH_MAX]) {
    out[0] = '\0';
    if (!path) { strcpy(out, "-"); return; }
    char *rp = realpath(path, NULL);
    if (rp) {
        strncpy(out, rp, PATH_MAX-1);
        out[PATH_MAX-1] = '\0';
        free(rp);
    } else {
        // If realpath fails (e.g., file doesn't exist yet), build from cwd
        if (path[0] == '/') {
            strncpy(out, path, PATH_MAX-1);
            out[PATH_MAX-1] = '\0';
        } else {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                if (snprintf(out, PATH_MAX, "%s/%s", cwd, path) >= PATH_MAX) {
                    fprintf(stderr, "Warning: path too long, truncating.\n");
                    out[PATH_MAX - 1] = '\0';
                }
            } else {
                strncpy(out, path, PATH_MAX-1);
                out[PATH_MAX-1] = '\0';
            }
        }
    }
}

// ---- Interposed functions ----
FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    if (!real_fwrite) {
        real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }
    if (!real_fclose) {
        real_fclose = dlsym(RTLD_NEXT, "fclose");
    }

    // Prepare info for logging
    char abs_path[PATH_MAX];
    resolve_abs_path(path, abs_path);

    struct stat st;
    int existed_before = (stat(abs_path, &st) == 0);

    FILE *fp = real_fopen(path, mode);

    int denied = 0;
    if (!fp) {
        // If fopen failed, check errno to mark denied
        if (errno == EACCES || errno == EPERM) {
            denied = 1;
        }
        // Hash may not be available; still log the attempt
        char hash_hex[65]; strcpy(hash_hex, "-");
        int op = (mode_creates_file(mode) && !existed_before) ? OP_CREATED : OP_OPENED;
        log_event(abs_path, op, denied, hash_hex);
        return NULL;
    }

    // Success: decide if created or opened
    int is_creation = (!existed_before && mode_creates_file(mode)) ? 1 : 0;
    map_insert(fp, abs_path, is_creation);

    // Compute hash after open (likely same as before); for created file, it might be empty file
    char hash_hex[65];
    if (is_creation) {
        // For brand new empty file, hash of empty file (if present on disk). Compute anyway.
        sha256_file(abs_path, hash_hex);
        log_event(abs_path, OP_CREATED, 0, hash_hex);
    } else {
        sha256_file(abs_path, hash_hex);
        log_event(abs_path, OP_OPENED, 0, hash_hex);
    }
    return fp;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!real_fwrite) {
        real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }
    size_t written = real_fwrite(ptr, size, nmemb, stream);

    // After write attempt, log the event for this stream if we can resolve the path
    FileMap *m = map_find(stream);
    char hash_hex[65]; hash_hex[0] = '\0';
    int denied = 0;

    if (written < nmemb) {
        // Likely an error occurred. If it's permission-related, mark denied.
        if (errno == EACCES || errno == EPERM) {
            denied = 1;
        }
    }
    if (m) {
        // Try to flush to ensure the bytes are on disk for hashing
        fflush(stream);
        sha256_file(m->path, hash_hex);
        log_event(m->path, OP_WRITTEN, denied, hash_hex[0] ? hash_hex : "-");
    } else {
        // Unknown stream; log with "-"
        log_event("-", OP_WRITTEN, denied, "-");
    }
    return written;
}

int fclose(FILE *stream) {
    if (!real_fclose) {
        real_fclose = dlsym(RTLD_NEXT, "fclose");
    }

    // Capture path before closing
    FileMap *m = map_find(stream);
    char path[PATH_MAX]; path[0] = '\0';
    if (m) {
        strncpy(path, m->path, sizeof(path)-1);
        path[sizeof(path)-1] = '\0';
    } else {
        strncpy(path, "-", sizeof(path)-1);
        path[sizeof(path)-1] = '\0';
    }

    int rc = real_fclose(stream);

    // After close, compute hash (file closed; we can still hash by path)
    char hash_hex[65];
    sha256_file((m ? m->path : NULL), hash_hex);
    log_event((m ? m->path : "-"), OP_CLOSED, 0, hash_hex);

    if (m) map_remove(stream);
    return rc;
}
