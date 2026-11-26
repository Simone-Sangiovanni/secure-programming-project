#ifndef SFM_LOG_H
#define SFM_LOG_H

#include "../config/config.h"

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

void log_audit_event(const SfmConfig *cfg, LogEvent event, LogOutcome outcome, const char *target);

#endif