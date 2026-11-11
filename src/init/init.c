#define _POSIX_C_SOURCE 200809L  // openat, mkdirat, fchmod, getpwuid_r, O_NOFOLLOW

#include "init.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../config/config.h"

// Unsigned octal constants (no signed int in bitwise operations).
#define DIR_MODE   ((mode_t)0700)  // drwx------  owner only
#define FILE_MODE  ((mode_t)0600)  // -rw-------  owner only
#define MODE_BITS  07777U          // permission bits + setuid/setgid/sticky

// Names of the files, and their locations relative to the home directory.
// (The folder chains below must describe the same places as these paths.)
#define CONFIG_NAME     "config.json"
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
static const DirStep STATE_CHAIN[]  = {{".local", false}, {"state", false}, {"sfm", true}};
static const DirStep DATA_CHAIN[]   = {{".local", false}, {"share", false}, {"sfm", true}, {"vault", true}};



/* ---------- helpers (private to this file) ---------- */



/**
 * @brief Finds the home directory of the current user.
 *
 * Uses $HOME when set; otherwise asks the password database. The result must
 * be an absolute path. Trailing slashes are removed.
 *
 * @param out  Receives the path.
 * @param size Size of @p out.
 * @return INIT_OK, INIT_ERR_NO_HOME, INIT_ERR_BAD_HOME or INIT_ERR_PATH_TOO_LONG.
 */
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
    if (len == 0) return INIT_ERR_BAD_HOME;  // "/" is not a home directory
    return INIT_OK;
}

/**
 * @brief Builds "<home>/<relative>" into @p out, refusing to truncate.
 * @return true if it fitted.
 */
static bool join_path(char *out, size_t size, const char *home, const char *relative) {
    const int n = snprintf(out, size, "%s/%s", home, relative);
    return n >= 0 && (size_t)n < size;
}

/**
 * @brief Closes a file descriptor if it is open.
 */
static void close_fd(int fd) {
    if (fd >= 0) (void)close(fd);
}

/**
 * @brief Creates one folder (if missing) and opens it.
 *
 * mkdirat/openat work relative to the already-open parent folder, so nothing
 * can swap a parent for a symlink between two steps. For sfm's own folders
 * (step->owned) the folder must not be a symlink, must belong to the current
 * user, and is forced to mode 0700 (fchmod also overrides the umask).
 *
 * @param parent_fd Open parent folder.
 * @param step      Folder to create/open.
 * @param out_fd    Receives the open folder (the caller closes it).
 * @return INIT_OK or the reason it failed.
 */
static InitStatus open_dir_step(int parent_fd, const DirStep *step, int *out_fd) {
    if (mkdirat(parent_fd, step->name, DIR_MODE) != 0 && errno != EEXIST) return INIT_ERR_MKDIR;

    // For sfm's own folders a symlink would be an attack, so O_NOFOLLOW.
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

/**
 * @brief Creates/opens every folder of a chain, starting below @p base_fd.
 *
 * @param base_fd Open starting folder (the home directory). Not closed here.
 * @param steps   The folders, outermost first.
 * @param count   Number of folders.
 * @param out_fd  Receives the innermost folder (the caller closes it).
 */
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

/**
 * @brief Checks an existing file and forces it to mode 0600.
 *
 * It must be a regular file (not a symlink, folder or pipe) owned by the
 * current user. O_NONBLOCK stops an attacker's named pipe from hanging us.
 *
 * @param dir_fd Open folder containing the file.
 * @param name   File name inside that folder.
 */
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

/**
 * @brief Creates an empty file (mode 0600) if it does not exist, then verifies it.
 *
 * O_EXCL makes creation atomic: it never opens a file someone else created
 * in the meantime, and O_NOFOLLOW never follows a planted symlink.
 */
static InitStatus ensure_empty_file(int dir_fd, const char *name) {
    const int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, FILE_MODE);
    if (fd >= 0) {
        close_fd(fd);
    } else if (errno != EEXIST) {
        return INIT_ERR_CREATE;
    }
    return verify_file(dir_fd, name);
}

/**
 * @brief Makes sure config.json exists (writing the default configuration if
 *        not) and has the right owner and permissions.
 *
 * An existing file is NOT rewritten or validated here: a corrupt config is
 * reported later by load_config() instead of being silently replaced.
 */
static InitStatus ensure_config_file(int dir_fd, const SfmPaths *paths) {
    const int fd = openat(dir_fd, CONFIG_NAME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
        close_fd(fd);  // it exists: verify_file() below checks it
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



/* ---------- public API (full contract documented in init.h) ---------- */



InitStatus init_setup(SfmPaths *paths) {
    if (paths == nullptr) return INIT_ERR_ARGS;

    // Files created by root would belong to root, not to the user.
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
    int state_fd = -1;
    int vault_fd = -1;

    st = ensure_chain(home_fd, CONFIG_CHAIN, sizeof CONFIG_CHAIN / sizeof CONFIG_CHAIN[0], &config_fd);
    if (st == INIT_OK) st = ensure_config_file(config_fd, &result);

    if (st == INIT_OK) {
        st = ensure_chain(home_fd, STATE_CHAIN, sizeof STATE_CHAIN / sizeof STATE_CHAIN[0], &state_fd);
    }
    if (st == INIT_OK) st = ensure_empty_file(state_fd, LOG_NAME);

    if (st == INIT_OK) {
        st = ensure_chain(home_fd, DATA_CHAIN, sizeof DATA_CHAIN / sizeof DATA_CHAIN[0], &vault_fd);
    }

    close_fd(vault_fd);
    close_fd(state_fd);
    close_fd(config_fd);
    close_fd(home_fd);

    if (st == INIT_OK) *paths = result;
    return st;
}

const char *init_strerror(InitStatus status) {
    switch (status) {
        case INIT_OK:                return "ok";
        case INIT_ERR_ARGS:          return "invalid arguments (internal error)";
        case INIT_ERR_ROOT:          return "sfm must not run as root (files created in a user's home would belong to root)";
        case INIT_ERR_NO_HOME:       return "cannot determine the home directory ($HOME is unset and the user has no entry)";
        case INIT_ERR_BAD_HOME:      return "the home directory is not an absolute path to an existing directory";
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