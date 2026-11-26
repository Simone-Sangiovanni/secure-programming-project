#ifndef SFM_INIT_H
#define SFM_INIT_H

#include "../config/config.h"

#define INIT_PATH_MAX 512

typedef struct {
    char config_file[INIT_PATH_MAX];
    char log_file[INIT_PATH_MAX];
    char vault_dir[INIT_PATH_MAX];
} SfmPaths;

typedef enum {
    INIT_OK = 0,
    INIT_ERR_ARGS,
    INIT_ERR_ROOT,
    INIT_ERR_NO_HOME,
    INIT_ERR_BAD_HOME,
    INIT_ERR_PATH_TOO_LONG,
    INIT_ERR_MKDIR,
    INIT_ERR_ACCESS,
    INIT_ERR_NOT_DIR,
    INIT_ERR_NOT_FILE,
    INIT_ERR_OWNER,
    INIT_ERR_PERMS,
    INIT_ERR_CREATE,
    INIT_ERR_CONFIG
} InitStatus;

[[nodiscard]] InitStatus init_prepare_config(SfmPaths *paths);
[[nodiscard]] InitStatus init_ensure_storage(const SfmConfig *cfg);
[[nodiscard]] InitStatus init_setup(SfmPaths *paths);
[[nodiscard]] const char *init_strerror(InitStatus status);

#endif