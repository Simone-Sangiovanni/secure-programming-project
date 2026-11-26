#ifndef SFM_CONFIG_H
#define SFM_CONFIG_H

typedef struct {
    char kdf[32];
    char salt[64];
    char verifier[128];
    char vault_path[512];
    char log_path[512];
    char config_path[512];
} SfmConfig;

typedef enum {
    CONFIG_OK = 0,
    CONFIG_ERR_ARGS,
    CONFIG_ERR_NOT_FOUND,
    CONFIG_ERR_IO,
    CONFIG_ERR_PARSE,
    CONFIG_ERR_INVALID
} ConfigStatus;

[[nodiscard]] ConfigStatus load_config(const char *file_path, SfmConfig *cfg);
[[nodiscard]] ConfigStatus save_config(const char *file_path, const SfmConfig *cfg);
[[nodiscard]] ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path,
                                               const char *vault_path, const char *log_path);
[[nodiscard]] bool config_is_first_run(const SfmConfig *cfg);

#endif