#include "log.h"

#include <cjson/cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
    LOG_TARGET_MAX = 256,
    LOG_SOURCE_MAX = 128,
};

static const char *event_name(LogEvent event) {
    static const char *const names[] = {
        [LOG_EVENT_MASTER_SETUP] = "master_password_setup",
        [LOG_EVENT_LOGIN]        = "login",
        [LOG_EVENT_LIST_FILES]   = "list_files",
        [LOG_EVENT_FILE_ENCRYPT] = "file_encrypt",
        [LOG_EVENT_FILE_DECRYPT] = "file_decrypt",
        [LOG_EVENT_FILE_DELETE]  = "file_delete",
    };
    const size_t idx = (size_t)event;
    return (idx < sizeof names / sizeof names[0] && names[idx] != nullptr) ? names[idx] : "unknown";
}

static void copy_sanitized(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) return;
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        dst[i] = iscntrl((unsigned char)src[i]) ? '?' : src[i];
    }
    dst[i] = '\0';
}

static void write_all(int fd, const char *buf, size_t len) {
    for (size_t done = 0; done < len;) {
        const ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (n == 0) return;
        done += (size_t)n;
    }
}

void log_audit_event(const SfmConfig *cfg, LogEvent event, LogOutcome outcome, const char *target) {
    if (cfg == nullptr || cfg->log_path[0] == '\0') return;

    const uid_t uid = geteuid();
    char timestamp[32], source[LOG_SOURCE_MAX], safe_target[LOG_TARGET_MAX] = {}, user_id[32], tty[64];

    const time_t now = time(nullptr);
    struct tm utc_tm;
    if (now == (time_t)-1 || gmtime_r(&now, &utc_tm) == nullptr ||
        strftime(timestamp, sizeof timestamp, "%Y-%m-%dT%H:%M:%SZ", &utc_tm) == 0) {
        (void)snprintf(timestamp, sizeof timestamp, "1970-01-01T00:00:00Z");
    }

    if (isatty(STDIN_FILENO) && ttyname_r(STDIN_FILENO, tty, sizeof tty) == 0) {
        copy_sanitized(tty, sizeof tty, tty);
        (void)snprintf(source, sizeof source, "local:%s", tty);
    } else {
        (void)snprintf(source, sizeof source, "local");
    }

    if (target != nullptr && target[0] != '\0') {
        const char *slash = strrchr(target, '/');
        copy_sanitized(safe_target, sizeof safe_target, (slash != nullptr) ? slash + 1 : target);
    }

    (void)snprintf(user_id, sizeof user_id, "uid=%u", (unsigned int)uid);

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) return;

    const bool ok =
        cJSON_AddStringToObject(root, "timestamp", timestamp) != nullptr &&
        cJSON_AddStringToObject(root, "event", event_name(event)) != nullptr &&
        cJSON_AddStringToObject(root, "user", user_id) != nullptr &&
        cJSON_AddStringToObject(root, "source", source) != nullptr &&
        cJSON_AddStringToObject(root, "outcome", outcome == LOG_OUTCOME_SUCCESS ? "success" : "failure") != nullptr &&
        (safe_target[0] == '\0' || cJSON_AddStringToObject(root, "target", safe_target) != nullptr);

    char *line = ok ? cJSON_PrintUnformatted(root) : nullptr;
    cJSON_Delete(root);
    if (line == nullptr) return;

    const int fd = open(cfg->log_path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == uid) {
            write_all(fd, line, strlen(line));
            write_all(fd, "\n", 1);
        }
        (void)close(fd);
    }
    free(line);
}