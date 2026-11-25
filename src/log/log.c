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

static const char *event_to_string(LogEvent event) {
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

/** @brief Copies @p src into @p dst, replacing control characters with '?'. */
static void copy_sanitized(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) return;
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        dst[i] = iscntrl((unsigned char)src[i]) ? '?' : src[i];
    }
    dst[i] = '\0';
}

/** @brief Formats current UTC time as ISO-8601, falling back to Unix epoch. */
static void format_utc_timestamp(char *buf, size_t size) {
    const time_t now = time(nullptr);
    struct tm utc_tm;
    if (now == (time_t)-1 || gmtime_r(&now, &utc_tm) == nullptr ||
        strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &utc_tm) == 0) {
        (void)snprintf(buf, size, "1970-01-01T00:00:00Z");
    }
}

/** @brief Builds the source identifier ("local" or "local:<tty>"). */
static void build_source_id(char *buf, size_t size) {
    char tty[64];
    if (isatty(STDIN_FILENO) && ttyname_r(STDIN_FILENO, tty, sizeof tty) == 0) {
        copy_sanitized(tty, sizeof tty, tty);
        (void)snprintf(buf, size, "local:%s", tty);
    } else {
        (void)snprintf(buf, size, "local");
    }
}

/** @brief Extracts the sanitized basename of @p raw_target (empty if none). */
static void sanitize_target_basename(const char *raw_target, char *out, size_t out_size) {
    if (out_size == 0) return;
    out[0] = '\0';
    if (raw_target == nullptr || raw_target[0] == '\0') return;
    const char *slash = strrchr(raw_target, '/');
    copy_sanitized(out, out_size, (slash != nullptr) ? slash + 1 : raw_target);
}

/** @brief Serializes an audit record to a compact JSON string (caller frees). */
static char *build_json_line(const char *timestamp, LogEvent event, uid_t uid,
                             const char *source, LogOutcome outcome, const char *target) {
    char user_id[32];
    (void)snprintf(user_id, sizeof user_id, "uid=%u", (unsigned int)uid);

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) return nullptr;

    const char *outcome_str = (outcome == LOG_OUTCOME_SUCCESS) ? "success" : "failure";
    const bool ok =
        cJSON_AddStringToObject(root, "timestamp", timestamp) != nullptr &&
        cJSON_AddStringToObject(root, "event", event_to_string(event)) != nullptr &&
        cJSON_AddStringToObject(root, "user", user_id) != nullptr &&
        cJSON_AddStringToObject(root, "source", source) != nullptr &&
        cJSON_AddStringToObject(root, "outcome", outcome_str) != nullptr &&
        (target[0] == '\0' || cJSON_AddStringToObject(root, "target", target) != nullptr);

    char *line = ok ? cJSON_PrintUnformatted(root) : nullptr;
    cJSON_Delete(root);
    return line;
}

/** @brief Writes @p len bytes of @p buf to @p fd, retrying on EINTR. */
static bool write_all(int fd, const char *buf, size_t len) {
    for (size_t done = 0; done < len;) {
        const ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        done += (size_t)n;
    }
    return true;
}

/** @brief Appends @p line + '\n' to @p path if it is a regular file owned by @p uid. */
static void append_log_line(const char *path, uid_t uid, const char *line) {
    // Open without following symlinks and verify ownership on the open descriptor.
    const int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == uid &&
        write_all(fd, line, strlen(line))) {
        (void)write_all(fd, "\n", 1);
    }
    (void)close(fd);
}

void log_audit_event(const SfmConfig *cfg, LogEvent event, LogOutcome outcome, const char *target) {
    if (cfg == nullptr || cfg->log_path[0] == '\0') return;

    const uid_t uid = geteuid();
    char timestamp[32], source[LOG_SOURCE_MAX], safe_target[LOG_TARGET_MAX];
    format_utc_timestamp(timestamp, sizeof timestamp);
    build_source_id(source, sizeof source);
    sanitize_target_basename(target, safe_target, sizeof safe_target);

    char *line = build_json_line(timestamp, event, uid, source, outcome, safe_target);
    if (line == nullptr) return;

    append_log_line(cfg->log_path, uid, line);
    free(line);
}
