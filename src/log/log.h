#ifndef SFM_LOG_H
#define SFM_LOG_H

#include "../config/config.h"

/**
 * @file log.h
 * @brief Structured JSON Lines audit logging for security-relevant events.
 *
 * Appends records to the user's state log file (~/.local/state/sfm/sfm.log).
 * Every entry includes:
 *   - timestamp: UTC ISO-8601 timestamp (e.g. "2026-11-16T20:00:00Z")
 *   - event:     operation name ("login", "master_password_setup",
 *                "file_encrypt", "file_decrypt", "file_delete", "list_files")
 *   - user:      effective UID ("uid=1000")
 *   - source:    origin ("local" or "local:/dev/pts/0")
 *   - outcome:   "success" or "failure"
 *   - target:    optional sanitized filename (basename only, never full paths)
 *
 * Secrets, passwords, keys, and internal stack/errno details are never logged.
 */

typedef enum {
    LOG_EVENT_MASTER_SETUP = 0,
    LOG_EVENT_LOGIN,
    LOG_EVENT_LIST_FILES,
    LOG_EVENT_FILE_ENCRYPT,
    LOG_EVENT_FILE_DECRYPT,
    LOG_EVENT_FILE_DELETE
} LogEvent;

typedef enum {
    LOG_OUTCOME_SUCCESS = 0,
    LOG_OUTCOME_FAILURE
} LogOutcome;

/**
 * @brief Appends a single JSON Lines audit record to @p cfg->log_path.
 *
 * Verifies regular-file status and owner UID on the opened file descriptor
 * before writing. Logging failures are ignored so logging never crashes callers.
 *
 * @param cfg     Loaded configuration containing log_path.
 * @param event   Security-relevant action performed.
 * @param outcome Whether the action succeeded or failed.
 * @param target  Optional file path or name (may be nullptr); only the
 *                sanitized basename is recorded.
 */
void log_audit_event(const SfmConfig *cfg, LogEvent event, LogOutcome outcome, const char *target);

#endif
