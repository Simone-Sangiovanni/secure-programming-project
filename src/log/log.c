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

#define LOG_TARGET_MAX 256
#define LOG_SOURCE_MAX 128

static const char *event_to_string(LogEvent event) {
    switch (event) {
        case LOG_EVENT_MASTER_SETUP: return "master_password_setup";
        case LOG_EVENT_LOGIN:        return "login";
        case LOG_EVENT_LIST_FILES:   return "list_files";
        case LOG_EVENT_FILE_ENCRYPT: return "file_encrypt";
        case LOG_EVENT_FILE_DECRYPT: return "file_decrypt";
        case LOG_EVENT_FILE_DELETE:  return "file_delete";
    }
    return "unknown";
}

static const char *outcome_to_string(LogOutcome outcome) {
    return (outcome == LOG_OUTCOME_SUCCESS) ? "success" : "failure";
}

/**
 * @brief Formats the current UTC time as ISO-8601 (YYYY-MM-DDTHH:MM:SSZ).
 */
static bool format_utc_timestamp(char *buf, size_t size) {
    const time_t now = time(nullptr);
    if (now == (time_t)-1) return false;

    struct tm utc_tm;
    if (gmtime_r(&now, &utc_tm) == nullptr) return false;

    return strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &utc_tm) > 0;
}

/**
 * @brief Builds the source identifier ("local" or "local:<tty>").
 */
static void build_source_id(char *buf, size_t size) {
    char tty_buf[64];
    if (isatty(STDIN_FILENO) && ttyname_r(STDIN_FILENO, tty_buf, sizeof tty_buf) == 0) {
        for (size_t i = 0; tty_buf[i] != '\0'; i++) {
            if (iscntrl((unsigned char)tty_buf[i])) {
                tty_buf[i] = '?';
            }
        }
        (void)snprintf(buf, size, "local:%s", tty_buf);
    } else {
        (void)snprintf(buf, size, "local");
    }
}

/**
 * @brief Extracts the basename of @p raw_target and strips control characters
 *        to prevent log injection or directory layout leakage.
 */
static void sanitize_target_basename(const char *raw_target, char *out, size_t out_size) {
    if (out_size == 0) return;
    out[0] = '\0';
    if (raw_target == nullptr || raw_target[0] == '\0') return;

    const char *slash = strrchr(raw_target, '/');
    const char *base = (slash != nullptr) ? slash + 1 : raw_target;

    size_t j = 0;
    for (size_t i = 0; base[i] != '\0' && j + 1 < out_size; i++) {
        const unsigned char c = (unsigned char)base[i];
        out[j++] = iscntrl(c) ? '?' : (char)c;
    }
    out[j] = '\0';
}

void log_audit_event(const SfmConfig *cfg,
                     LogEvent event,
                     LogOutcome outcome,
                     const char *target) {
    if (cfg == nullptr || cfg->log_path[0] == '\0') return;

    char timestamp[32];
    if (!format_utc_timestamp(timestamp, sizeof timestamp)) {
        (void)snprintf(timestamp, sizeof timestamp, "1970-01-01T00:00:00Z");
    }

    char user_id[32];
    (void)snprintf(user_id, sizeof user_id, "uid=%u", (unsigned int)geteuid());

    char source_id[LOG_SOURCE_MAX];
    build_source_id(source_id, sizeof source_id);

    char safe_target[LOG_TARGET_MAX];
    sanitize_target_basename(target, safe_target, sizeof safe_target);

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) return;

    bool ok = cJSON_AddStringToObject(root, "timestamp", timestamp) != nullptr &&
              cJSON_AddStringToObject(root, "event", event_to_string(event)) != nullptr &&
              cJSON_AddStringToObject(root, "user", user_id) != nullptr &&
              cJSON_AddStringToObject(root, "source", source_id) != nullptr &&
              cJSON_AddStringToObject(root, "outcome", outcome_to_string(outcome)) != nullptr;

    if (ok && safe_target[0] != '\0') {
        ok = cJSON_AddStringToObject(root, "target", safe_target) != nullptr;
    }

    if (!ok) {
        cJSON_Delete(root);
        return;
    }

    char *line = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (line == nullptr) return;

    // Open without following symlinks and verify ownership on the open descriptor.
    const int fd = open(cfg->log_path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        free(line);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid()) {
        const size_t len = strlen(line);
        size_t done = 0;
        bool write_ok = true;
        while (done < len) {
            const ssize_t w = write(fd, line + done, len - done);
            if (w < 0) {
                if (errno == EINTR) continue;
                write_ok = false;
                break;
            }
            done += (size_t)w;
        }
        if (write_ok) {
            const char nl = '\n';
            (void)write(fd, &nl, 1);
        }
    }

    (void)close(fd);
    free(line);
}
