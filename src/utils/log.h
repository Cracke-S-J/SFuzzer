#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SF_TRACE,
    SF_INFO,
    SF_DEBUG,
    SF_WARN,
    SF_ERROR
} LOG_LEVEL;

void log_msg(LOG_LEVEL, const char*, const char*);

#ifdef __cplusplus
}
#endif