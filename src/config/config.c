#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#define CONFIG_MAX_FILE_SIZE (64L * 1024L) // 64 Kb - max config file size allowed
#define CONFIG_DEFAULT_KDF   "argon2id"
#define CONFIG_DEFAULT_VAULT "sfm_vault"
#define CONFIG_DEFAULT_LOG   "sfm.log"



/* ---------- helpers (private to this file) ---------- */



/**
 * @brief Copies a C string into a fixed-size buffer, refusing to truncate.
 *
 * Uses snprintf, which always NUL-terminates and returns the length the
 * output would have had. If that length does not fit, the copy is reported
 * as a failure instead of being silently cut.
 *
 * @param dst      Destination buffer.
 * @param dst_size Size of @p dst in bytes (including the terminator).
 * @param src      NUL-terminated source string. Must not be NULL.
 * @return true if the whole string was copied, false on error or truncation.
 */
static bool copy_str(char *dst, size_t dst_size, const char *src) {
    const int n = snprintf(dst, dst_size, "%s", src);
    return n >= 0 && (size_t)n < dst_size;
}

/**
 * @brief Copies the value of a cJSON string item into a fixed-size buffer.
 *
 * cJSON_IsString() is NULL-safe, so a missing key (item == NULL) or a value
 * of the wrong type both result in an empty string rather than a crash.
 *
 * @param dst      Destination buffer.
 * @param dst_size Size of @p dst in bytes.
 * @param item     Item returned by cJSON_GetObjectItemCaseSensitive(), or NULL.
 * @return true on success, false if the string does not fit in @p dst.
 */
static bool copy_json_field(char *dst, size_t dst_size, const cJSON *item) {
    return copy_str(dst, dst_size, cJSON_IsString(item) ? item->valuestring : "");
}

/**
 * @brief Reads a whole file into a newly allocated, NUL-terminated buffer.
 *
 * The size is found with fseek/ftell, checked against CONFIG_MAX_FILE_SIZE,
 * and the file is read in one fread call. On any failure nothing is
 * allocated and the outputs are left untouched.
 *
 * @param path    File to read.
 * @param out     Receives the buffer. The caller must free() it.
 * @param out_len Receives the file size in bytes (without the terminator).
 * @return CONFIG_OK on success; CONFIG_ERR_NOT_FOUND if the file does not
 *         exist; CONFIG_ERR_INVALID if it exceeds the size limit;
 *         CONFIG_ERR_IO for any other failure.
 */
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
    (void)fclose(f);  // read-only file: a close failure loses no data
    if (got != (size_t)size) { free(buf); return CONFIG_ERR_IO; }

    buf[size] = '\0';
    *out = buf;
    *out_len = (size_t)size;
    return CONFIG_OK;
}



/* ---------- public API (full contract documented in config.h) ---------- */



/**
 * @brief Implementation of config_is_first_run().
 *
 * An empty C string has '\0' as its first byte, so testing index 0 is the
 * cheapest emptiness check. A NULL config is treated as "first run".
 */
bool config_is_first_run(const SfmConfig *cfg) {
    if (cfg == nullptr) return true;
    return cfg->salt[0] == '\0' || cfg->verifier[0] == '\0';
}

/**
 * @brief Implementation of config_set_defaults().
 *
 * Builds the defaults in a zeroed temporary struct and copies it to @p cfg
 * only if every field fitted, so @p cfg is never left partially initialised.
 */
ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path) {
    if (cfg == nullptr || config_path == nullptr) return CONFIG_ERR_ARGS;

    SfmConfig tmp = {};  // C23: zero-initialises every field
    if (!copy_str(tmp.kdf, sizeof tmp.kdf, CONFIG_DEFAULT_KDF) ||
        !copy_str(tmp.vault_path, sizeof tmp.vault_path, CONFIG_DEFAULT_VAULT) ||
        !copy_str(tmp.log_path, sizeof tmp.log_path, CONFIG_DEFAULT_LOG) ||
        !copy_str(tmp.config_path, sizeof tmp.config_path, config_path)) {
        return CONFIG_ERR_INVALID;
    }

    *cfg = tmp;
    return CONFIG_OK;
}

/**
 * @brief Implementation of load_config().
 *
 * Steps: read the file (size-limited) -> parse JSON -> copy each known key
 * into a temporary struct -> commit to @p cfg. The JSON tree and the raw
 * text are freed on every path. config_path is taken from @p file_path, not
 * from the JSON.
 */
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

    *cfg = tmp;
    return CONFIG_OK;
}

/**
 * @brief Implementation of save_config().
 *
 * Steps: build a cJSON object -> pretty-print it to a heap string -> write
 * the string to the file. Both the fputs and the fclose results are checked,
 * because fclose can report write errors that were buffered.
 *
 * TODO(security): not atomic and uses default file permissions.
 */
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

    // TODO(security): write to a temp file + rename() for atomic replace,
    //                 and create the file with 0600 permissions.
    FILE *f = fopen(file_path, "wb");
    if (f == nullptr) { free(text); return CONFIG_ERR_IO; }

    const bool wrote = fputs(text, f) >= 0;
    const bool closed = fclose(f) == 0;  // fclose can report deferred write errors
    free(text);

    return (wrote && closed) ? CONFIG_OK : CONFIG_ERR_IO;
}