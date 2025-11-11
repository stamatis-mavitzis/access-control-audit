// audit_monitor.c
// Build: gcc -o audit_monitor audit_monitor.c
// Analyzes access_audit.log produced by audit_logger.so.
//
// Log format per line (pipe-separated):
// UID|PID|Filename|Date|Time|Operation|Denied|Hash
//
// Features:
//   -s               : Detect suspicious users (UIDs) with >5 distinct denied files
//   -i <filename>    : Analyze file activity for a given filename (absolute or partial)
// If called with invalid options, prints usage help.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LOG_PATH_ENV "AUDIT_LOG_PATH"

typedef struct Line {
    unsigned int uid;
    int pid;
    char *filename;
    char date[11];
    char time[9];
    int op;
    int denied;
    char *hash;
} Line;

static const char* log_path() {
    const char *env = getenv(LOG_PATH_ENV);
    if (env && *env)
        return env;
    return "access_audit.log"; // fallback: local file
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1]=='\n' || s[n-1]=='\r')) { s[--n]='\0'; }
}

static int parse_line(char *line, Line *out) {
    // Tokenize by '|'
    // Expect 8 fields
    char *fields[8];
    int idx = 0;
    char *p = strtok(line, "|");
    while (p && idx < 8) {
        fields[idx++] = p;
        p = strtok(NULL, "|");
    }
    if (idx != 8) return 0;

    out->uid = (unsigned int)strtoul(fields[0], NULL, 10);
    out->pid = atoi(fields[1]);
    out->filename = fields[2];
    strncpy(out->date, fields[3], sizeof(out->date)-1);
    out->date[sizeof(out->date)-1] = '\0';
    strncpy(out->time, fields[4], sizeof(out->time)-1);
    out->time[sizeof(out->time)-1] = '\0';
    out->op = atoi(fields[5]);
    out->denied = atoi(fields[6]);
    out->hash = fields[7];
    trim_newline(out->hash);
    return 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Audit Log Monitor\n"
        "Usage:\n"
        "  %s -s\n"
        "  %s -i <filename>\n\n"
        "Options:\n"
        "  -s            Detect suspicious users (>5 distinct denied files)\n"
        "  -i <filename> Analyze activity for given file (absolute or partial path)\n",
        prog, prog);
}

typedef struct StrNode {
    char *s;
    struct StrNode *next;
} StrNode;

typedef struct HashNode {
    char *h;
    struct HashNode *next;
} HashNode;

typedef struct UserInfo {
    unsigned int uid;
    StrNode *denied_files; // set of filenames (distinct)
    struct UserInfo *next;
} UserInfo;

typedef struct FileUserInfo {
    unsigned int uid;
    int write_count;
    HashNode *hashes; // set of unique hashes when op==2
    struct FileUserInfo *next;
} FileUserInfo;

static int str_in_set(StrNode *head, const char *s) {
    for (StrNode *p=head; p; p=p->next) if (strcmp(p->s, s)==0) return 1;
    return 0;
}
static void str_add_unique(StrNode **head, const char *s) {
    if (str_in_set(*head, s)) return;
    StrNode *n = (StrNode*)malloc(sizeof(StrNode));
    n->s = strdup(s);
    n->next = *head;
    *head = n;
}
static int hash_in_set(HashNode *head, const char *h) {
    for (HashNode *p=head; p; p=p->next) if (strcmp(p->h, h)==0) return 1;
    return 0;
}
static void hash_add_unique(HashNode **head, const char *h) {
    if (!h || !*h || strcmp(h, "-")==0) return;
    if (hash_in_set(*head, h)) return;
    HashNode *n = (HashNode*)malloc(sizeof(HashNode));
    n->h = strdup(h);
    n->next = *head;
    *head = n;
}

static UserInfo* get_or_add_user(UserInfo **head, unsigned int uid) {
    for (UserInfo *p=*head; p; p=p->next) if (p->uid == uid) return p;
    UserInfo *n = (UserInfo*)malloc(sizeof(UserInfo));
    n->uid = uid;
    n->denied_files = NULL;
    n->next = *head;
    *head = n;
    return n;
}

static FileUserInfo* get_or_add_file_user(FileUserInfo **head, unsigned int uid) {
    for (FileUserInfo *p=*head; p; p=p->next) if (p->uid == uid) return p;
    FileUserInfo *n = (FileUserInfo*)malloc(sizeof(FileUserInfo));
    n->uid = uid;
    n->write_count = 0;
    n->hashes = NULL;
    n->next = *head;
    *head = n;
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *lp = log_path();
    FILE *f = fopen(lp, "r");
    if (!f) {
        fprintf(stderr, "Error: cannot open log file at %s\n", lp);
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        char buf[8192];
        UserInfo *users = NULL;
        while (fgets(buf, sizeof(buf), f)) {
            Line ln;
            char tmp[8192];
            strncpy(tmp, buf, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1]='\0';
            if (!parse_line(tmp, &ln)) continue;
            if (ln.denied == 1) {
                UserInfo *ui = get_or_add_user(&users, ln.uid);
                str_add_unique(&ui->denied_files, ln.filename);
            }
        }
        int found = 0;
        for (UserInfo *p=users; p; p=p->next) {
            int count = 0;
            for (StrNode *s=p->denied_files; s; s=s->next) count++;
            if (count > 5) {
                printf("%u\n", p->uid);
                found = 1;
            }
        }
        if (!found) printf("(no suspicious users found)\n");
        fclose(f);
        return 0;
    } 
    else if (strcmp(argv[1], "-i") == 0) {
        if (argc != 3) { usage(argv[0]); fclose(f); return 1; }
        const char *target = argv[2];
        char buf[8192];
        FileUserInfo *users = NULL;
        while (fgets(buf, sizeof(buf), f)) {
            Line ln;
            char tmp[8192];
            strncpy(tmp, buf, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1]='\0';
            if (!parse_line(tmp, &ln)) continue;
            if (!strstr(ln.filename, target)) continue; // substring match

            FileUserInfo *fu = get_or_add_file_user(&users, ln.uid);
            if (ln.op == 2) { // written
                fu->write_count += 1;
                hash_add_unique(&fu->hashes, ln.hash);
            }
        }
        int any = 0;
        for (FileUserInfo *p=users; p; p=p->next) {
            any = 1;
            int unique_mods = 0;
            for (HashNode *h=p->hashes; h; h=h->next) unique_mods++;
            printf("UID %u: writes=%d, unique_modifications=%d\n",
                   p->uid, p->write_count, unique_mods);
        }
        if (!any) printf("(no activity found for file)\n");
        fclose(f);
        return 0;
    } 
    else {
        usage(argv[0]);
        fclose(f);
        return 1;
    }
}
