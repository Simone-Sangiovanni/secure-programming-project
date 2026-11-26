#include "config.h"

#include <cjson/cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../validate/validate.h"

#define CONFIG_MAX_FILE_SIZE (64L * 1024L)
#define CONFIG_DEFAULT_KDF   "argon2id"

static bool copy_str(char *dst, size_t dst_size, const char *src) {
    const int n = snprintf(dst, dst_size, "%s", src);
    return n >= 0 && (size_t)n < dst_size;
}

static bool read_json_str(const cJSON *json, const char *key, char *dst, size_t dst_size) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    return copy_str(dst, dst_size, cJSON_IsString(item) ? item->valuestring : "");
}

static void strip_trailing_slashes(char *path) {
    for (size_t len = strlen(path); len > 1 && path[len - 1] == '/'; len--) {
        path[len - 1] = '\0';
    }
}

static ConfigStatus read_file(const char *path, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == nullptr) return (errno == ENOENT) ? CONFIG_ERR_NOT_FOUND : CONFIG_ERR_IO;

    ConfigStatus status = CONFIG_ERR_IO;
    char *buf = nullptr;
    if (fseek(f, 0, SEEK_END) == 0) {
        const long size = ftell(f);
        if (size > CONFIG_MAX_FILE_SIZE) {
            status = CONFIG_ERR_INVALID;
        } else if (size >= 0 && fseek(f, 0, SEEK_SET) == 0) {
            buf = malloc((size_t)size + 1);
            if (buf != nullptr && fread(buf, 1, (size_t)size, f) == (size_t)size) {
                buf[size] = '\0';
                *out = buf;
                *out_len = (size_t)size;
                buf = nullptr;
                status = CONFIG_OK;
            }
        }
    }
    free(buf);
    (void)fclose(f);
    return status;
}

static ConfigStatus write_atomic(const char *file_path, const char *text) {
    const char *slash = strrchr(file_path, '/');
    const int dir_len = (slash != nullptr) ? (int)(slash - file_path + 1) : 0;

    char tmp_path[VALIDATE_PATH_MAX + 32];
    const int n = snprintf(tmp_path, sizeof tmp_path, "%.*s.sfm-tmp-XXXXXX", dir_len, file_path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) return CONFIG_ERR_IO;

    const int fd = mkstemp(tmp_path);
    if (fd < 0) return CONFIG_ERR_IO;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

    const size_t len = strlen(text);
    bool ok = true;
    for (size_t done = 0; done < len;) {
        const ssize_t w = write(fd, text + done, len - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        done += (size_t)w;
    }

    if (ok && (fsync(fd) != 0 || close(fd) != 0)) {
        (void)unlink(tmp_path);
        return CONFIG_ERR_IO;
    }
    if (!ok) {
        (void)close(fd);
        (void)unlink(tmp_path);
        return CONFIG_ERR_IO;
    }
    if (rename(tmp_path, file_path) != 0) {
        (void)unlink(tmp_path);
        return CONFIG_ERR_IO;
    }
    return CONFIG_OK;
}

bool config_is_first_run(const SfmConfig *cfg) {
    return cfg == nullptr || cfg->salt[0] == '\0' || cfg->verifier[0] == '\0';
}

ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path,
                                 const char *vault_path, const char *log_path) {
    if (cfg == nullptr || config_path == nullptr || vault_path == nullptr || log_path == nullptr) {
        return CONFIG_ERR_ARGS;
    }

    SfmConfig tmp = {};
    if (!copy_str(tmp.kdf, sizeof tmp.kdf, CONFIG_DEFAULT_KDF) ||
        !copy_str(tmp.vault_path, sizeof tmp.vault_path, vault_path) ||
        !copy_str(tmp.log_path, sizeof tmp.log_path, log_path) ||
        !copy_str(tmp.config_path, sizeof tmp.config_path, config_path)) {
        return CONFIG_ERR_INVALID;
    }
    strip_trailing_slashes(tmp.vault_path);
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

    SfmConfig tmp = {};
    const bool ok =
        read_json_str(json, "kdf",      tmp.kdf,         sizeof tmp.kdf) &&
        read_json_str(json, "salt",     tmp.salt,        sizeof tmp.salt) &&
        read_json_str(json, "verifier", tmp.verifier,    sizeof tmp.verifier) &&
        read_json_str(json, "vault",    tmp.vault_path,  sizeof tmp.vault_path) &&
        read_json_str(json, "log",      tmp.log_path,    sizeof tmp.log_path) &&
        read_json_str(json, "config",   tmp.config_path, sizeof tmp.config_path);
    cJSON_Delete(json);
    if (!ok) return CONFIG_ERR_INVALID;

    if (tmp.config_path[0] == '\0') {
        if (!copy_str(tmp.config_path, sizeof tmp.config_path, file_path)) return CONFIG_ERR_INVALID;
    } else if (strcmp(tmp.config_path, file_path) != 0) {
        return CONFIG_ERR_INVALID;
    }

    if (tmp.vault_path[0] != '/' || validate_has_traversal(tmp.vault_path) ||
        validate_absolute_path(tmp.log_path) != VALIDATE_OK ||
        validate_absolute_path(tmp.config_path) != VALIDATE_OK) {
        return CONFIG_ERR_INVALID;
    }
    strip_trailing_slashes(tmp.vault_path);

    if ((tmp.salt[0] != '\0') != (tmp.verifier[0] != '\0')) return CONFIG_ERR_PARSE;

    *cfg = tmp;
    return CONFIG_OK;
}

ConfigStatus save_config(const char *file_path, const SfmConfig *cfg) {
    if (file_path == nullptr || cfg == nullptr) return CONFIG_ERR_ARGS;

    const char *cfg_path = (cfg->config_path[0] != '\0') ? cfg->config_path : file_path;
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) return CONFIG_ERR_IO;

    if (!cJSON_AddStringToObject(json, "kdf", cfg->kdf) ||
        !cJSON_AddStringToObject(json, "salt", cfg->salt) ||
        !cJSON_AddStringToObject(json, "verifier", cfg->verifier) ||
        !cJSON_AddStringToObject(json, "vault", cfg->vault_path) ||
        !cJSON_AddStringToObject(json, "log", cfg->log_path) ||
        !cJSON_AddStringToObject(json, "config", cfg_path)) {
        cJSON_Delete(json);
        return CONFIG_ERR_IO;
    }

    char *text = cJSON_Print(json);
    cJSON_Delete(json);
    if (text == nullptr) return CONFIG_ERR_IO;

    const ConfigStatus status = write_atomic(file_path, text);
    free(text);
    return status;
}