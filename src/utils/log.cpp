#include "log.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void log_msg(LOG_LEVEL lvl, const char* fname, const char* msg) {
    FILE* flog = fopen("/tmp/sfuzzer.log", "a+");
    switch (lvl) {
        case SF_TRACE:
            fprintf(flog, "[TRACE]%s: %s\n", fname, msg);
            break;
        case SF_DEBUG:
            fprintf(flog, "[DEBUG]%s: %s\n", fname, msg);
            break;
        case SF_INFO:
            fprintf(flog, "[INFO]%s: %s\n", fname, msg);
            break;
        case SF_WARN:
            fprintf(flog, "[WARN]%s: %s\n", fname, msg);
            break;
        case SF_ERROR:
            fprintf(flog, "[ERROR]%s: %s\n", fname, msg);
            break;
        default:
            break;
    }
    fclose(flog);
    return;
}

void dump_args(LOG_LEVEL lvl, const char* fname, char** args) {
    char** tmp = args;
    FILE* flog = fopen("/tmp/sfuzzer.log", "a+");
    switch (lvl) {
        case SF_TRACE:
            fprintf(flog, "[TRACE]%s: ", fname);
            break;
        case SF_DEBUG:
            fprintf(flog, "[DEBUG]%s: ", fname);
            break;
        case SF_INFO:
            fprintf(flog, "[INFO]%s: ", fname);
            break;
        case SF_WARN:
            fprintf(flog, "[WARN]%s: ", fname);
            break;
        case SF_ERROR:
            fprintf(flog, "[ERROR]%s: ", fname);
            break;
        default:
            break;
    }
    while(*tmp) {
        fprintf(flog, "%s ", *tmp++);
    }
    fprintf(flog, "\n");
    fclose(flog);
    return;
}

#ifdef __cplusplus
}
#endif