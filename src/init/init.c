#include "init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/*
#include "init.h"

// System and Standard Library Inclusions
#include <stdio.h>    // For snprintf() (safe path string formatting)
#include <stdlib.h>   // For free() and getenv() (environment variable lookup)
#include <string.h>   // For strdup() (string duplication)
#include <errno.h>    // For global 'errno' and constants like ENOENT, ENOTDIR, EEXIST
#include <unistd.h>   // For getuid() and close() (file descriptor cleanup)
#include <pwd.h>      // For getpwuid() and struct passwd (home dir lookup fallback)
#include <sys/stat.h> // For S_IRWXU mode flag constant and mkdirat()
#include <sys/types.h>// For type definitions like mode_t
#include <fcntl.h>    // For open() and flags O_RDONLY, O_DIRECTORY, O_CLOEXEC

// Safely resolves '~' to the user's home directory path
[[nodiscard]] static char* get_home_directory(void) {
    const char *home = getenv("HOME");
    if (home != nullptr && home[0] != '\0') {
        return strdup(home);
    }

    // Fallback to reading /etc/passwd if $HOME is unset
    struct passwd *pw = getpwuid(getuid());
    if (pw != nullptr && pw->pw_dir != nullptr) {
        return strdup(pw->pw_dir);
    }

    return nullptr;
}

[[nodiscard]] DirStatus setup_sfm_directory(void) {
    // 1. Locate the home directory
    char *home_dir = get_home_directory();
    if (home_dir == nullptr) {
        return DIR_ERR_HOME_NOT_FOUND;
    }

    // Build path to ~/.config safely
    char config_path[1024];
    int len = snprintf(config_path, sizeof(config_path), "%s/.config", home_dir);
    free(home_dir); // Free heap memory immediately after formatting

    if (len < 0 || (size_t)len >= sizeof(config_path)) {
        return DIR_ERR_PATH_TOO_LONG;
    }

    // 2. Open file descriptor for ~/.config atomically
    int config_fd = open(config_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (config_fd < 0) {
        if (errno == ENOENT) {
            return DIR_ERR_CONFIG_MISSING;
        } else if (errno == ENOTDIR) {
            return DIR_ERR_CONFIG_NOT_DIR;
        } else {
            return DIR_ERR_CONFIG_ACCESS;
        }
    }

    // 3. Atomically create 'sfm' relative to the directory descriptor
    constexpr mode_t dir_mode = S_IRWXU; // 0700 permissions (user-only)

    if (mkdirat(config_fd, "sfm", dir_mode) < 0) {
        close(config_fd);
        if (errno == EEXIST) {
            return DIR_ERR_SFM_EXISTS;
        }
        return DIR_ERR_CREATE_FAILED;
    }

    close(config_fd);
    return DIR_SUCCESS;
}
*/