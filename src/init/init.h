#ifndef INIT_H
#define INIT_H

#include <stddef.h>

// Return codes for directory creation operations
typedef enum: int {
    DIR_SUCCESS = 0,
    DIR_ERR_HOME_NOT_FOUND,
    DIR_ERR_PATH_TOO_LONG,
    DIR_ERR_CONFIG_MISSING,
    DIR_ERR_CONFIG_NOT_DIR,
    DIR_ERR_CONFIG_ACCESS,
    DIR_ERR_SFM_EXISTS,
    DIR_ERR_CREATE_FAILD
} DirStatus;

/**
* Ensures ~/.config exists and create 'sfm/' inside it.

* Mark function return as [[nodiscard]] so callers cannot ignore the status.
*
* @return DIR_SUCCESS on creation, or a specific DirStatus error code.
*/
[[nodiscard]] DirStatus setup_sfm_dir(void);

#endif