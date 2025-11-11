// test_audit.c
// Build: gcc -o test_audit test_audit.c
// Run with: LD_PRELOAD=./audit_logger.so ./test_audit
// Generates a variety of file operations including denied accesses.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static void write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "a+");
    if (!f) {
        // Intentionally not fatal; we want to generate denied events too.
        return;
    }
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

int main(void) {
    printf("Running test_audit...\n");

    // 1) Create several files and write to them
    write_text("example1.txt", "hello 1\n");
    write_text("example2.txt", "hello 2\n");
    write_text("example1.txt", "append more\n");

    // 2) Open existing file for reading (should be 'opened' event)
    FILE *fr = fopen("example1.txt", "r");
    if (fr) fclose(fr);

    // 3) Create file then remove permissions and attempt read/write to trigger denied
    const char *no_perm = "no_perm.txt";
    write_text(no_perm, "secret\n");
    chmod(no_perm, 0000); // remove all permissions

    FILE *f_try_r = fopen(no_perm, "r");
    if (f_try_r) fclose(f_try_r);
    FILE *f_try_w = fopen(no_perm, "a");
    if (f_try_w) {
        // On some systems, open may succeed due to umask or fs; attempt write anyway.
        size_t wr = fwrite("x", 1, 1, f_try_w);
        (void)wr;
        fclose(f_try_w);
    }

    // 4) Try to open a likely-protected path to ensure denied
    FILE *froot = fopen("/root/should_not_exist_or_access.txt", "r");
    if (froot) fclose(froot);

    // 5) Extra: generate multiple denied files to simulate suspicious user behavior
    for (int i = 0; i < 7; ++i) {
        char name[64];
        snprintf(name, sizeof(name), "noaccess_%d.txt", i);
        // create file and write something
        FILE *fw = fopen(name, "w");
        if (fw) {
            fwrite("data\n", 1, 5, fw);
            fclose(fw);
        }
        // remove all permissions
        chmod(name, 0000);

        // try to open for reading (should be denied)
        FILE *fr2 = fopen(name, "r");
        if (fr2) fclose(fr2);

        // try to open for writing (should be denied)
        FILE *fw2 = fopen(name, "a");
        if (fw2) {
            fwrite("x", 1, 1, fw2);
            fclose(fw2);
        }
    }

    printf("test_audit completed.\n");
    return 0;
}
