#ifndef SFM_VALIDATE_H
#define SFM_VALIDATE_H

#define VALIDATE_PATH_MAX 4096

typedef enum {
    VALIDATE_OK = 0,
    VALIDATE_ERR_EMPTY,
    VALIDATE_ERR_NOT_ABSOLUTE,
    VALIDATE_ERR_TOO_LONG,
    VALIDATE_ERR_NOT_A_FILE,
    VALIDATE_ERR_TRAVERSAL,
    VALIDATE_ERR_NOT_A_DIR,
    VALIDATE_ERR_PARENT
} ValidateStatus;

[[nodiscard]] bool validate_has_traversal(const char *path);
[[nodiscard]] ValidateStatus validate_absolute_path(const char *path);
[[nodiscard]] ValidateStatus validate_file_path(const char *path,
                                                char resolved_out[VALIDATE_PATH_MAX]);
[[nodiscard]] ValidateStatus validate_directory_path(const char *path,
                                                     char resolved_out[VALIDATE_PATH_MAX]);
[[nodiscard]] const char *validate_strerror(ValidateStatus status);

#endif