#include "config.h"
#include <cjson/cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONFIG_MAX_FILE_SIZE (64L * 1024L)  // 64 KiB - max config file size allowed
#define CONFIG_DEFAULT_KDF   "argon2id"

/* ---------- helpers (private to this file) ---------- */

static bool copy_str(char *dst, size_t dst_size, const char *src) {
    const int n = snprintf(dst, dst_size, "%s", src);
    return n >= 0 && (size_t)n < dst_size;
}

static bool copy_json_field(char *dst, size_t dst_size, const cJSON *item) {
    return copy_str(dst, dst_size, cJSON_IsString(item) ? item->valuestring : "");
}

static ConfigStatus read_file(const char *path, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == nullptr) {
        return (errno == ENOENT) ? CONFIG_ERR_NOT_FOUND : CONFIG_ERR_IO;
    }
    if (fseek(f, 0, SEEK_END) != 0) { (void)fclose(f); return CONFIG_ERR_IO; }
    const long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return CONFIG_ERR_IO;
    }
    if (size > CONFIG_MAX_FILE_SIZE) { (void)fclose(f); return CONFIG_ERR_INVALID; }

    char *buf = malloc((size_t)size + 1);
    if (buf == nullptr) { (void)fclose(f); return CONFIG_ERR_IO; }

    const size_t got = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    if (got != (size_t)size) { free(buf); return CONFIG_ERR_IO; }

    buf[size] = '\0';
    *out = buf;
    *out_len = (size_t)size;
    return CONFIG_OK;
}

/* ---------- public API (full contract documented in config.h) ---------- */

bool config_is_first_run(const SfmConfig *cfg) {
    if (cfg == nullptr) return true;
    return cfg->salt[0] == '\0' || cfg->verifier[0] == '\0';
}

ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path,
                                 const char *vault_path, const char *log_path) {
    if (cfg == nullptr || config_path == nullptr || vault_path == nullptr || log_path == nullptr) {
        return CONFIG_ERR_ARGS;
    }
    SfmConfig tmp = {};  // C23: zero-initialises every field
    if (!copy_str(tmp.kdf, sizeof tmp.kdf, CONFIG_DEFAULT_KDF) ||
        !copy_str(tmp.vault_path, sizeof tmp.vault_path, vault_path) ||
        !copy_str(tmp.log_path, sizeof tmp.log_path, log_path) ||
        !copy_str(tmp.config_path, sizeof tmp.config_path, config_path)) {
        return CONFIG_ERR_INVALID;
    }
    *cfg = tmp;
    return CONFIG_OK;
}

ConfigStatus load_config(const char *file_path, SfmConfig *cfg) {
    if (file_path == nullptr || cfg == nullptr) return CONFIG_ERR_ARGS;

    char *data = nullptr;
    size_t length = 0;
    const ConfigStatus rs = read_file(file_path, &data, &length);
    if (rs != CONFIG_OK) return rs;

    cJSON *json = cJSON_ParseWithLength(data, length);
    free(data);
    if (json == nullptr) return CONFIG_ERR_PARSE;

    // Fill a temporary struct so cfg is never left half-written.
    SfmConfig tmp = {};
    const bool ok =
        copy_json_field(tmp.kdf, sizeof tmp.kdf,
                        cJSON_GetObjectItemCaseSensitive(json, "kdf")) &&
        copy_json_field(tmp.salt, sizeof tmp.salt,
                        cJSON_GetObjectItemCaseSensitive(json, "salt")) &&
        copy_json_field(tmp.verifier, sizeof tmp.verifier,
                        cJSON_GetObjectItemCaseSensitive(json, "verifier")) &&
        copy_json_field(tmp.vault_path, sizeof tmp.vault_path,
                        cJSON_GetObjectItemCaseSensitive(json, "vault")) &&
        copy_json_field(tmp.log_path, sizeof tmp.log_path,
                        cJSON_GetObjectItemCaseSensitive(json, "log")) &&
        copy_str(tmp.config_path, sizeof tmp.config_path, file_path);

    cJSON_Delete(json);
    if (!ok) return CONFIG_ERR_INVALID;

    // Reject a partially populated credential state (salt without verifier or vice versa).
    const bool has_salt = (tmp.salt[0] != '\0');
    const bool has_verifier = (tmp.verifier[0] != '\0');
    if (has_salt != has_verifier) {
        return CONFIG_ERR_PARSE;
    }

    *cfg = tmp;
    return CONFIG_OK;
}

ConfigStatus save_config(const char *file_path, const SfmConfig *cfg) {
    if (file_path == nullptr || cfg == nullptr) return CONFIG_ERR_ARGS;

    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) return CONFIG_ERR_IO;
    if (!cJSON_AddStringToObject(json, "kdf", cfg->kdf) ||
        !cJSON_AddStringToObject(json, "salt", cfg->salt) ||
        !cJSON_AddStringToObject(json, "verifier", cfg->verifier) ||
        !cJSON_AddStringToObject(json, "vault", cfg->vault_path) ||
        !cJSON_AddStringToObject(json, "log", cfg->log_path)) {
        cJSON_Delete(json);
        return CONFIG_ERR_IO;
    }
    char *text = cJSON_Print(json);
    cJSON_Delete(json);
    if (text == nullptr) return CONFIG_ERR_IO;

    const char *slash = strrchr(file_path, '/');
    const int dir_len = (slash != nullptr) ? (int)(slash - file_path + 1) : 0;
    char tmp_path[4096 + 32];
    const int n = snprintf(tmp_path, sizeof tmp_path, "%.*s.sfm-tmp-XXXXXX", dir_len, file_path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) { free(text); return CONFIG_ERR_IO; }

    const int fd = mkstemp(tmp_path);
    if (fd < 0) { free(text); return CONFIG_ERR_IO; }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

    const size_t len = strlen(text);
    bool ok = true;
    size_t done = 0;
    while (done < len) {
        const ssize_t w = write(fd, text + done, len - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        done += (size_t)w;
    }
    free(text);

    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp_path, file_path) != 0) ok = false;

    if (!ok) {
        (void)unlink(tmp_path);
        return CONFIG_ERR_IO;
    }
    return CONFIG_OK;
}
