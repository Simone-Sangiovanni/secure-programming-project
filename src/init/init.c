#define _POSIX_C_SOURCE 200809L  // openat, mkdirat, fchmod, getpwuid_r, O_NOFOLLOW

#include "init.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR_MODE   ((mode_t)0700)  // drwx------ (owner only)
#define FILE_MODE  ((mode_t)0600)  // -rw------- (owner only)
#define MODE_BITS  07777U          // permission + special mode bits

#define CONFIG_NAME     "sfm.config"
#define REL_CONFIG_DIR  ".config/sfm"
#define REL_CONFIG_FILE REL_CONFIG_DIR "/" CONFIG_NAME
#define REL_LOG_FILE    ".local/state/sfm/sfm.log"
#define REL_VAULT_DIR   ".local/share/sfm/vault"

/* ---------- internal helpers ---------- */

static bool has_traversal(const char *path, size_t len) {
    return strstr(path, "/../") != nullptr || strstr(path, "/./") != nullptr ||
           (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
           (len >= 2 && strcmp(path + len - 2, "/.") == 0);
}

static InitStatus get_home(char *out, size_t size) {
    const char *home = getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
        char pw_buf[4096];
        struct passwd pwd;
        struct passwd *found = nullptr;
        if (getpwuid_r(geteuid(), &pwd, pw_buf, sizeof pw_buf, &found) != 0 ||
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
    return (len == 0 || has_traversal(out, len)) ? INIT_ERR_BAD_HOME : INIT_OK;
}

static bool join_path(char *out, size_t size, const char *base, const char *rel) {
    const int n = snprintf(out, size, "%s/%s", base, rel);
    return n >= 0 && (size_t)n < size;
}

/**
 * Opens or creates a single directory component relative to @p parent_fd.
 * When @p enforce_own is true (or the directory was newly created), symlinks
 * are refused (O_NOFOLLOW), owner UID is verified, and mode 0700 is enforced.
 */
static InitStatus open_or_create_dir(int parent_fd, const char *name, bool enforce_own, int *out_fd) {
    const bool created = (mkdirat(parent_fd, name, DIR_MODE) == 0);
    if (!created && errno != EEXIST) return INIT_ERR_MKDIR;

    const bool must_own = created || enforce_own;
    const int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | (must_own ? O_NOFOLLOW : 0);
    const int fd = openat(parent_fd, name, flags);
    if (fd < 0) return (errno == ELOOP || errno == ENOTDIR) ? INIT_ERR_NOT_DIR : INIT_ERR_ACCESS;

    if (must_own) {
        struct stat st;
        InitStatus err = INIT_OK;
        if (fstat(fd, &st) != 0) err = INIT_ERR_ACCESS;
        else if (st.st_uid != geteuid()) err = INIT_ERR_OWNER;
        else if ((st.st_mode & MODE_BITS) != DIR_MODE && fchmod(fd, DIR_MODE) != 0) err = INIT_ERR_PERMS;

        if (err != INIT_OK) {
            close(fd);
            return err;
        }
    }

    *out_fd = fd;
    return INIT_OK;
}

/**
 * Walks slash-separated components in @p rel_path starting from @p base_fd.
 * Enforces ownership, no-symlink, and 0700 modes on newly created directories,
 * "sfm"/"vault" directories, and (when @p enforce_leaf is true) the final leaf.
 */
static InitStatus walk_dir(int base_fd, bool close_base, const char *rel_path,
                           bool enforce_leaf, int *out_fd) {
    char buf[INIT_PATH_MAX];
    const int n = snprintf(buf, sizeof buf, "%s", rel_path);
    if (n < 0 || (size_t)n >= sizeof buf) {
        if (close_base) close(base_fd);
        return INIT_ERR_PATH_TOO_LONG;
    }

    int parent_fd = base_fd;
    bool owns_parent = close_base;
    char *p = buf;
    while (*p == '/') p++;

    while (*p != '\0') {
        char *comp = p;
        while (*p != '\0' && *p != '/') p++;
        while (*p == '/') *p++ = '\0';

        if (strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
            if (owns_parent) close(parent_fd);
            return INIT_ERR_BAD_HOME;
        }

        const bool is_leaf = (*p == '\0');
        const bool is_sfm = (strcmp(comp, "sfm") == 0 || strcmp(comp, "vault") == 0);
        const bool enforce_own = is_sfm || (is_leaf && enforce_leaf);

        int fd = -1;
        const InitStatus st = open_or_create_dir(parent_fd, comp, enforce_own, &fd);
        if (owns_parent) close(parent_fd);
        if (st != INIT_OK) return st;

        parent_fd = fd;
        owns_parent = true;
    }

    if (out_fd != nullptr) *out_fd = parent_fd;
    else if (owns_parent) close(parent_fd);
    return INIT_OK;
}

/** Walks an absolute directory path from "/" and optionally returns its fd. */
static InitStatus ensure_abs_dir(const char *dir_path, bool enforce_leaf, int *out_fd) {
    if (dir_path == nullptr || dir_path[0] != '/') return INIT_ERR_BAD_HOME;

    const size_t len = strlen(dir_path);
    if (len == 0 || has_traversal(dir_path, len)) return INIT_ERR_BAD_HOME;
    if (len >= INIT_PATH_MAX) return INIT_ERR_PATH_TOO_LONG;

    const int root_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) return INIT_ERR_ACCESS;

    const char *rel = dir_path + 1;
    while (*rel == '/') rel++;
    if (*rel == '\0') {
        if (enforce_leaf) {
            close(root_fd);
            return INIT_ERR_OWNER;
        }
        if (out_fd != nullptr) *out_fd = root_fd;
        else close(root_fd);
        return INIT_OK;
    }

    return walk_dir(root_fd, true, rel, enforce_leaf, out_fd);
}

/** Verifies an open file descriptor is regular, owner-matched, and mode 0600, then closes it. */
static InitStatus verify_file_fd(int fd) {
    struct stat st;
    InitStatus status = INIT_OK;
    if (fstat(fd, &st) != 0) status = INIT_ERR_ACCESS;
    else if (!S_ISREG(st.st_mode)) status = INIT_ERR_NOT_FILE;
    else if (st.st_uid != geteuid()) status = INIT_ERR_OWNER;
    else if ((st.st_mode & MODE_BITS) != FILE_MODE && fchmod(fd, FILE_MODE) != 0) status = INIT_ERR_PERMS;

    close(fd);
    return status;
}

static InitStatus verify_file(int dir_fd, const char *name) {
    const int fd = openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return (errno == ELOOP) ? INIT_ERR_NOT_FILE : INIT_ERR_ACCESS;
    return verify_file_fd(fd);
}

static InitStatus ensure_empty_file(int dir_fd, const char *name) {
    const int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, FILE_MODE);
    if (fd >= 0) close(fd);
    else if (errno != EEXIST) return INIT_ERR_CREATE;
    return verify_file(dir_fd, name);
}

static InitStatus ensure_config_file(int dir_fd, const SfmPaths *paths) {
    const int fd = openat(dir_fd, CONFIG_NAME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) return verify_file_fd(fd);
    if (errno != ENOENT) return (errno == ELOOP) ? INIT_ERR_NOT_FILE : INIT_ERR_ACCESS;

    SfmConfig cfg;
    if (config_set_defaults(&cfg, paths->config_file, paths->vault_dir, paths->log_file) != CONFIG_OK ||
        save_config(paths->config_file, &cfg) != CONFIG_OK) {
        return INIT_ERR_CONFIG;
    }
    return verify_file(dir_fd, CONFIG_NAME);
}

/* ---------- public API ---------- */

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
    st = walk_dir(home_fd, false, REL_CONFIG_DIR, true, &config_fd);
    if (st == INIT_OK) {
        st = ensure_config_file(config_fd, &result);
        close(config_fd);
    }
    close(home_fd);

    if (st == INIT_OK) *paths = result;
    return st;
}

InitStatus init_ensure_storage(const SfmConfig *cfg) {
    if (cfg == nullptr) return INIT_ERR_ARGS;
    if (geteuid() == 0) return INIT_ERR_ROOT;

    if (cfg->vault_path[0] != '/' || cfg->log_path[0] != '/') return INIT_ERR_BAD_HOME;

    const size_t log_len = strlen(cfg->log_path);
    if (log_len == 0 || cfg->log_path[log_len - 1] == '/' || has_traversal(cfg->log_path, log_len)) {
        return INIT_ERR_BAD_HOME;
    }

    InitStatus st = ensure_abs_dir(cfg->vault_path, true, nullptr);
    if (st != INIT_OK) return st;

    const char *last_slash = strrchr(cfg->log_path, '/');
    char log_dir[INIT_PATH_MAX];
    const size_t dir_len = (last_slash == cfg->log_path) ? 1U : (size_t)(last_slash - cfg->log_path);
    if (dir_len >= sizeof log_dir) return INIT_ERR_PATH_TOO_LONG;
    memcpy(log_dir, cfg->log_path, dir_len);
    log_dir[dir_len] = '\0';

    int log_dir_fd = -1;
    st = ensure_abs_dir(log_dir, false, &log_dir_fd);
    if (st != INIT_OK) return st;

    st = ensure_empty_file(log_dir_fd, last_slash + 1);
    close(log_dir_fd);
    return st;
}

InitStatus init_setup(SfmPaths *paths) {
    const InitStatus st = init_prepare_config(paths);
    if (st != INIT_OK) return st;

    SfmConfig cfg;
    if (load_config(paths->config_file, &cfg) != CONFIG_OK) return INIT_ERR_CONFIG;
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
