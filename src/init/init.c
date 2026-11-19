#define _POSIX_C_SOURCE 200809L  // openat, mkdirat, fchmod, getpwuid_r, O_NOFOLLOW

#include "init.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Unsigned octal constants (no signed int in bitwise operations).
#define DIR_MODE   ((mode_t)0700)  // drwx------  owner only
#define FILE_MODE  ((mode_t)0600)  // -rw-------  owner only
#define MODE_BITS  07777U          // permission bits + setuid/setgid/sticky

// Names of the files, and their default locations relative to the home directory.
#define CONFIG_NAME     "sfm.config"
#define LOG_NAME        "sfm.log"
#define REL_CONFIG_FILE ".config/sfm/" CONFIG_NAME
#define REL_LOG_FILE    ".local/state/sfm/" LOG_NAME
#define REL_VAULT_DIR   ".local/share/sfm/vault"

/**
 * One folder on the way down from the home directory.
 *
 * owned == false: a standard parent folder (".config", ".local", ...). It is
 *                 created if missing, but if it exists it is accepted as is
 *                 (symlinks allowed) and its permissions are not touched.
 * owned == true:  a folder that belongs to sfm. It must be a real folder (no
 *                 symlink), owned by the current user, and is forced to 0700.
 */
typedef struct {
    const char *name;
    bool owned;
} DirStep;

static const DirStep CONFIG_CHAIN[] = {{".config", false}, {"sfm", true}};

/* ---------- helpers (private to this file) ---------- */

static InitStatus get_home(char *out, size_t size) {
    const char *home = getenv("HOME");

    char pw_buffer[4096];
    struct passwd pwd;
    struct passwd *found = nullptr;
    if (home == nullptr || home[0] == '\0') {
        if (getpwuid_r(geteuid(), &pwd, pw_buffer, sizeof pw_buffer, &found) != 0 ||
            found == nullptr || found->pw_dir == nullptr) {
            return INIT_ERR_NO_HOME;
        }
        home = found->pw_dir;
    }
    if (home[0] != '/') return INIT_ERR_BAD_HOME;

    const int n = snprintf(out, size, "%s", home);
    if (n < 0 || (size_t)n >= size) return INIT_ERR_PATH_TOO_LONG;

    size_t len = (size_t)n;
    while (len > 0 && out[len - 1] == '/') out[--len] = '\0';
    if (len == 0) return INIT_ERR_BAD_HOME;
    return INIT_OK;
}

static bool join_path(char *out, size_t size, const char *home, const char *relative) {
    const int n = snprintf(out, size, "%s/%s", home, relative);
    return n >= 0 && (size_t)n < size;
}

static void close_fd(int fd) {
    if (fd >= 0) (void)close(fd);
}

static InitStatus open_dir_step(int parent_fd, const DirStep *step, int *out_fd) {
    if (mkdirat(parent_fd, step->name, DIR_MODE) != 0 && errno != EEXIST) return INIT_ERR_MKDIR;

    const int fd = openat(parent_fd, step->name,
                          step->owned ? (O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                                      : (O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd < 0) return (errno == ELOOP || errno == ENOTDIR) ? INIT_ERR_NOT_DIR : INIT_ERR_ACCESS;

    if (step->owned) {
        struct stat st;
        if (fstat(fd, &st) != 0) { close_fd(fd); return INIT_ERR_ACCESS; }
        if (st.st_uid != geteuid()) { close_fd(fd); return INIT_ERR_OWNER; }
        if ((st.st_mode & MODE_BITS) != DIR_MODE && fchmod(fd, DIR_MODE) != 0) {
            close_fd(fd);
            return INIT_ERR_PERMS;
        }
    }

    *out_fd = fd;
    return INIT_OK;
}

static InitStatus ensure_chain(int base_fd, const DirStep *steps, size_t count, int *out_fd) {
    int parent = base_fd;
    for (size_t i = 0; i < count; i++) {
        int fd = -1;
        const InitStatus st = open_dir_step(parent, &steps[i], &fd);
        if (parent != base_fd) close_fd(parent);
        if (st != INIT_OK) return st;
        parent = fd;
    }
    *out_fd = parent;
    return INIT_OK;
}

static InitStatus verify_file(int dir_fd, const char *name) {
    const int fd = openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return (errno == ELOOP) ? INIT_ERR_NOT_FILE : INIT_ERR_ACCESS;

    struct stat st;
    InitStatus result = INIT_OK;
    if (fstat(fd, &st) != 0) {
        result = INIT_ERR_ACCESS;
    } else if (!S_ISREG(st.st_mode)) {
        result = INIT_ERR_NOT_FILE;
    } else if (st.st_uid != geteuid()) {
        result = INIT_ERR_OWNER;
    } else if ((st.st_mode & MODE_BITS) != FILE_MODE && fchmod(fd, FILE_MODE) != 0) {
        result = INIT_ERR_PERMS;
    }

    close_fd(fd);
    return result;
}

static InitStatus ensure_empty_file(int dir_fd, const char *name) {
    const int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, FILE_MODE);
    if (fd >= 0) {
        close_fd(fd);
    } else if (errno != EEXIST) {
        return INIT_ERR_CREATE;
    }
    return verify_file(dir_fd, name);
}

static InitStatus ensure_config_file(int dir_fd, const SfmPaths *paths) {
    const int fd = openat(dir_fd, CONFIG_NAME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
        close_fd(fd);
    } else if (errno == ENOENT) {
        SfmConfig cfg;
        if (config_set_defaults(&cfg, paths->config_file, paths->vault_dir, paths->log_file) != CONFIG_OK ||
            save_config(paths->config_file, &cfg) != CONFIG_OK) {
            return INIT_ERR_CONFIG;
        }
    } else {
        return (errno == ELOOP) ? INIT_ERR_NOT_FILE : INIT_ERR_ACCESS;
    }
    return verify_file(dir_fd, CONFIG_NAME);
}

static bool has_traversal(const char *path, size_t len) {
    return strstr(path, "/../") != nullptr ||
           strstr(path, "/./") != nullptr ||
           (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
           (len >= 2 && strcmp(path + len - 2, "/.") == 0);
}

/**
 * @brief Walks an arbitrary configured absolute directory path from "/",
 *        creating any missing directories (0700) and enforcing O_NOFOLLOW,
 *        owner UID, and 0700 permissions on newly created directories, "sfm" /
 *        "vault" directories, and optionally the final leaf directory.
 */
static InitStatus ensure_configured_dir(const char *dir_path, bool enforce_leaf, int *out_dir_fd) {
    if (dir_path == nullptr || dir_path[0] != '/') return INIT_ERR_BAD_HOME;
    const size_t raw_len = strlen(dir_path);
    if (raw_len == 0 || has_traversal(dir_path, raw_len)) return INIT_ERR_BAD_HOME;

    char copy[INIT_PATH_MAX];
    const int n = snprintf(copy, sizeof copy, "%s", dir_path);
    if (n < 0 || (size_t)n >= sizeof copy) return INIT_ERR_PATH_TOO_LONG;

    size_t len = (size_t)n;
    while (len > 1 && copy[len - 1] == '/') {
        copy[--len] = '\0';
    }

    int parent_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) return INIT_ERR_ACCESS;

    if (strcmp(copy, "/") == 0) {
        if (enforce_leaf) {
            close_fd(parent_fd);
            return INIT_ERR_OWNER;
        }
        if (out_dir_fd != nullptr) {
            *out_dir_fd = parent_fd;
        } else {
            close_fd(parent_fd);
        }
        return INIT_OK;
    }

    const char *comps[INIT_PATH_MAX / 2];
    size_t comp_count = 0;
    char *p = copy + 1;
    while (*p != '\0') {
        while (*p == '/') p++;
        if (*p == '\0') break;
        comps[comp_count++] = p;
        while (*p != '\0' && *p != '/') p++;
        if (*p == '/') {
            *p = '\0';
            p++;
        }
    }

    if (comp_count == 0) {
        close_fd(parent_fd);
        return INIT_ERR_BAD_HOME;
    }

    for (size_t i = 0; i < comp_count; i++) {
        const char *comp = comps[i];
        const bool is_leaf = (i + 1 == comp_count);
        const bool is_sfm_named = (strcmp(comp, "sfm") == 0 || strcmp(comp, "vault") == 0);

        bool created = false;
        if (mkdirat(parent_fd, comp, DIR_MODE) == 0) {
            created = true;
        } else if (errno != EEXIST) {
            close_fd(parent_fd);
            return INIT_ERR_MKDIR;
        }

        const bool must_own = created || is_sfm_named || (is_leaf && enforce_leaf);
        const int flags = must_own ? (O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                                   : (O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        const int fd = openat(parent_fd, comp, flags);
        close_fd(parent_fd);
        if (fd < 0) {
            return (errno == ELOOP || errno == ENOTDIR) ? INIT_ERR_NOT_DIR : INIT_ERR_ACCESS;
        }

        if (must_own) {
            struct stat st;
            if (fstat(fd, &st) != 0) {
                close_fd(fd);
                return INIT_ERR_ACCESS;
            }
            if (!S_ISDIR(st.st_mode)) {
                close_fd(fd);
                return INIT_ERR_NOT_DIR;
            }
            if (st.st_uid != geteuid()) {
                close_fd(fd);
                return INIT_ERR_OWNER;
            }
            if ((st.st_mode & MODE_BITS) != DIR_MODE && fchmod(fd, DIR_MODE) != 0) {
                close_fd(fd);
                return INIT_ERR_PERMS;
            }
        }

        parent_fd = fd;
    }

    if (out_dir_fd != nullptr) {
        *out_dir_fd = parent_fd;
    } else {
        close_fd(parent_fd);
    }
    return INIT_OK;
}

/* ---------- public API (full contract documented in init.h) ---------- */

InitStatus init_prepare_config(SfmPaths *paths) {
    if (paths == nullptr) return INIT_ERR_ARGS;
    if (geteuid() == 0) return INIT_ERR_ROOT;

    char home[INIT_PATH_MAX];
    InitStatus st = get_home(home, sizeof home);
    if (st != INIT_OK) return st;

    SfmPaths result;
    if (!join_path(result.config_file, sizeof result.config_file, home, REL_CONFIG_FILE) ||
        !join_path(result.log_file, sizeof result.log_file, home, REL_LOG_FILE) ||
        !join_path(result.vault_dir, sizeof result.vault_dir, home, REL_VAULT_DIR)) {
        return INIT_ERR_PATH_TOO_LONG;
    }

    const int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0) return INIT_ERR_BAD_HOME;

    int config_fd = -1;
    st = ensure_chain(home_fd, CONFIG_CHAIN, sizeof CONFIG_CHAIN / sizeof CONFIG_CHAIN[0], &config_fd);
    if (st == INIT_OK) st = ensure_config_file(config_fd, &result);

    close_fd(config_fd);
    close_fd(home_fd);

    if (st == INIT_OK) *paths = result;
    return st;
}

InitStatus init_ensure_storage(const SfmConfig *cfg) {
    if (cfg == nullptr) return INIT_ERR_ARGS;
    if (geteuid() == 0) return INIT_ERR_ROOT;

    if (cfg->vault_path[0] != '/' || cfg->log_path[0] != '/') {
        return INIT_ERR_BAD_HOME;
    }

    const size_t log_len = strlen(cfg->log_path);
    if (log_len == 0 || cfg->log_path[log_len - 1] == '/' || has_traversal(cfg->log_path, log_len)) {
        return INIT_ERR_BAD_HOME;
    }

    // 1. Recreate or verify the configured vault directory (0700, owner check).
    InitStatus st = ensure_configured_dir(cfg->vault_path, true, nullptr);
    if (st != INIT_OK) return st;

    // 2. Split cfg->log_path into parent directory + file name, then recreate/verify both.
    const char *last_slash = strrchr(cfg->log_path, '/');
    if (last_slash == nullptr) return INIT_ERR_BAD_HOME;

    const char *log_name = last_slash + 1;
    if (log_name[0] == '\0' || strcmp(log_name, ".") == 0 || strcmp(log_name, "..") == 0) {
        return INIT_ERR_NOT_FILE;
    }

    char log_dir[INIT_PATH_MAX];
    if (last_slash == cfg->log_path) {
        log_dir[0] = '/';
        log_dir[1] = '\0';
    } else {
        const size_t dir_len = (size_t)(last_slash - cfg->log_path);
        if (dir_len >= sizeof log_dir) return INIT_ERR_PATH_TOO_LONG;
        memcpy(log_dir, cfg->log_path, dir_len);
        log_dir[dir_len] = '\0';
    }

    int log_dir_fd = -1;
    st = ensure_configured_dir(log_dir, false, &log_dir_fd);
    if (st != INIT_OK) return st;

    st = ensure_empty_file(log_dir_fd, log_name);
    close_fd(log_dir_fd);
    return st;
}

InitStatus init_setup(SfmPaths *paths) {
    const InitStatus st = init_prepare_config(paths);
    if (st != INIT_OK) return st;

    SfmConfig cfg;
    if (load_config(paths->config_file, &cfg) != CONFIG_OK) {
        return INIT_ERR_CONFIG;
    }
    return init_ensure_storage(&cfg);
}

const char *init_strerror(InitStatus status) {
    switch (status) {
        case INIT_OK:                return "ok";
        case INIT_ERR_ARGS:          return "invalid arguments (internal error)";
        case INIT_ERR_ROOT:          return "sfm must not run as root (files created in a user's home would belong to root)";
        case INIT_ERR_NO_HOME:       return "cannot determine the home directory ($HOME is unset and the user has no entry)";
        case INIT_ERR_BAD_HOME:      return "the home directory is not an absolute path to a directory";
        case INIT_ERR_PATH_TOO_LONG: return "a path is too long (the home directory path is too long)";
        case INIT_ERR_MKDIR:         return "cannot create a folder";
        case INIT_ERR_ACCESS:        return "cannot open a folder or file (permissions?)";
        case INIT_ERR_NOT_DIR:       return "expected a folder but found something else (symlinks are refused)";
        case INIT_ERR_NOT_FILE:      return "expected a regular file but found something else (symlinks are refused)";
        case INIT_ERR_OWNER:         return "a folder or file belongs to another user";
        case INIT_ERR_PERMS:         return "cannot set the required permissions (0700 folders, 0600 files)";
        case INIT_ERR_CREATE:        return "cannot create a file";
        case INIT_ERR_CONFIG:        return "cannot write the default configuration file";
    }
    return "unknown error";
}