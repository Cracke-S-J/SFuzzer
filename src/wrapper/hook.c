#include "config.h"
#include "log.h"

#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#if defined HAVE_POSIX_SPAWN || defined HAVE_POSIX_SPAWNP
#include <spawn.h>
#endif

#if defined HAVE_NSGETENVIRON
# include <crt_externs.h>
static char **environ;
#else
extern char **environ;
#endif

#define ENV_PRELOAD "LD_PRELOAD"
#define ENV_SIZE 1

// #define TOSTRING(x) #x
// #define AT "libhook: (" __FILE__ ":" TOSTRING(__LINE__) ") "

// #define PERROR(msg) do { perror(AT msg); } while (0)

// #define ERROR_AND_EXIT(msg) do { PERROR(msg); exit(EXIT_FAILURE); } while (0)

const char* fname = "hook.c";
extern void log_msg(LOG_LEVEL, const char*, const char*);
#define DLSYM(TYPE_, VAR_, SYMBOL_)                                 \
    union {                                                         \
        void *from;                                                 \
        TYPE_ to;                                                   \
    } cast;                                                         \
    if (0 == (cast.from = dlsym(RTLD_NEXT, SYMBOL_))) {             \
        log_msg(SF_ERROR, fname, "dlsym failed");                   \
        exit(EXIT_FAILURE);                                         \
    }                                                               \
    TYPE_ const VAR_ = cast.to;


typedef char const * hook_env_t[ENV_SIZE];

static int capture_env_t(hook_env_t *);
static void release_env_t(hook_env_t *);
static char const **str_p_ud(char *const [], hook_env_t *);
static char const **str_s_ud(char const *[], char const *, char const *);
static char const **varlist2argv(char const * , va_list *);
static char const **str_arr_copy(char const **);
static size_t str_arr_len(char  const *const *const);
static void str_arr_free(char const**);


static hook_env_t env_names = { ENV_PRELOAD };

static hook_env_t initial_env = { 0 };

static int initialized = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void on_load(void) __attribute__((constructor));
static void on_unload(void) __attribute__((destructor));

static int mt_safe_on_load(void);
static void mt_safe_on_unload(void);


#ifdef HAVE_EXECVE
static int call_execve(const char *, char *const [], char *const []);
#endif
#ifdef HAVE_EXECVP
static int call_execvp(const char *, char *const []);
#endif
#ifdef HAVE_EXECVPE
static int call_execvpe(const char *, char *const [], char *const []);
#endif
#ifdef HAVE_EXECVP2
static int call_execvP(const char *, const char *, char *const []);
#endif
#ifdef HAVE_EXECT
static int call_exect(const char *, char *const [], char *const []);
#endif

// TODO, 先不考虑这个
// #ifdef HAVE_POSIX_SPAWN
// static int call_posix_spawn(pid_t *restrict pid, const char *restrict path,
//                             const posix_spawn_file_actions_t *file_actions,
//                             const posix_spawnattr_t *restrict attrp,
//                             char *const argv[restrict],
//                             char *const envp[restrict]);
// #endif
// #ifdef HAVE_POSIX_SPAWNP
// static int call_posix_spawnp(pid_t *restrict pid, const char *restrict file,
//                              const posix_spawn_file_actions_t *file_actions,
//                              const posix_spawnattr_t *restrict attrp,
//                              char *const argv[restrict],
//                              char *const envp[restrict]);
// #endif


static void on_load(void) {
    pthread_mutex_lock(&mutex);
    if (0 == initialized)
        initialized = mt_safe_on_load();
    pthread_mutex_unlock(&mutex);
}

static void on_unload(void) {
    pthread_mutex_lock(&mutex);
    if (0 != initialized)
        mt_safe_on_unload();
    initialized = 0;
    pthread_mutex_unlock(&mutex);
}

static int mt_safe_on_load(void) {
#ifdef HAVE_NSGETENVIRON
    environ = *_NSGetEnviron();
    if (0 == environ)
        return 0;
#endif
    // Capture current relevant environment variables
    return capture_env_t(&initial_env);
}

static void mt_safe_on_unload(void) {
    release_env_t(&initial_env);
}

void do_ins(const char* exec_name) {
    log_msg(SF_INFO, fname, "do ins");
    if (strcmp(exec_name, "as")) {
        fprintf(stderr, "insert asm\n");
    }
    return;
}

/* function to be hooked */

#ifdef HAVE_EXECVE
int execve(const char *path, char *const argv[], char *const envp[]) {
    do_ins(argv[1]);
    return call_execve(path, argv, envp);
}
#endif

#ifdef HAVE_EXECV
#ifndef HAVE_EXECVE
#error can not implement execv without execve
#endif
int execv(const char *path, char *const argv[]) {
    do_ins(argv[1]);
    return call_execve(path, argv, environ);
}
#endif

#ifdef HAVE_EXECVPE
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    do_ins(argv[1]);
    return call_execvpe(file, argv, envp);
}
#endif

#ifdef HAVE_EXECVP
int execvp(const char *file, char *const argv[]) {
    log_msg(SF_INFO, fname, "execvp");
    do_ins(argv[1]);
    return call_execvp(file, argv);
}
#endif

#ifdef HAVE_EXECVP2
int execvP(const char *file, const char *search_path, char *const argv[]) {
    do_ins(argv[1]);
    return call_execvP(file, search_path, argv);
}
#endif

#ifdef HAVE_EXECT
int exect(const char *path, char *const argv[], char *const envp[]) {
    do_ins(argv[1]);
    return call_exect(path, argv, envp);
}
#endif

#ifdef HAVE_EXECL
# ifndef HAVE_EXECVE
#  error can not implement execl without execve
# endif
int execl(const char *path, const char *arg, ...) {
    va_list args;
    va_start(args, arg);
    char const **argv = varlist2argv(arg, &args);
    va_end(args);

    do_ins(argv[1]);

    int const result = call_execve(path, (char *const *)argv, environ);
    str_arr_free(argv);
    return result;
}
#endif

#ifdef HAVE_EXECLP
# ifndef HAVE_EXECVP
#  error can not implement execlp without execvp
# endif
int execlp(const char *file, const char *arg, ...) {
    va_list args;
    va_start(args, arg);
    char const **argv = varlist2argv(arg, &args);
    va_end(args);

    do_ins(argv[1]);

    int const result = call_execvp(file, (char *const *)argv);
    str_arr_free(argv);
    return result;
}
#endif

#ifdef HAVE_EXECLE
# ifndef HAVE_EXECVE
#  error can not implement execle without execve
# endif
// int execle(const char *path, const char *arg, ..., char * const envp[]);
int execle(const char *path, const char *arg, ...) {
    va_list args;
    va_start(args, arg);
    char const **argv = varlist2argv(arg, &args);
    char const **envp = va_arg(args, char const **);
    va_end(args);

    do_ins(argv[1]);

    int const result = call_execve(path, (char *const *)argv, (char *const *)envp);
    str_arr_free(argv);
    return result;
}
#endif

// #ifdef HAVE_POSIX_SPAWN
// int posix_spawn(pid_t *restrict pid, const char *restrict path,
//                 const posix_spawn_file_actions_t *file_actions,
//                 const posix_spawnattr_t *restrict attrp,
//                 char *const argv[restrict], char *const envp[restrict]) {
//     report_call((char const *const *)argv);
//     return call_posix_spawn(pid, path, file_actions, attrp, argv, envp);
// }
// #endif

// #ifdef HAVE_POSIX_SPAWNP
// int posix_spawnp(pid_t *restrict pid, const char *restrict file,
//                  const posix_spawn_file_actions_t *file_actions,
//                  const posix_spawnattr_t *restrict attrp,
//                  char *const argv[restrict], char *const envp[restrict]) {
//     report_call((char const *const *)argv);
//     return call_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
// }
// #endif

/* These are the methods which forward the call to the standard implementation.
 */

#ifdef HAVE_EXECVE
static int call_execve(const char *path,
                       char *const argv[],
                       char *const envp[]) {
    typedef int (*func)(const char  *,
                        char *const *,
                        char *const *);

    DLSYM(func, fp, "execve");

    char const **const menvp = str_p_ud(envp, &initial_env);
    int const result = (*fp)(path, argv, (char *const *)menvp);
    str_arr_free(menvp);
    return result;
}
#endif

#ifdef HAVE_EXECVPE
static int call_execvpe(const char *file,
                        char *const argv[],
                        char *const envp[]) {
    typedef int (*func)(const char  *,
                        char *const *,
                        char *const *);

    DLSYM(func, fp, "execvpe");

    char const **const menvp = str_p_ud(envp, &initial_env);
    int const result = (*fp)(file, argv, (char *const *)menvp);
    str_arr_free(menvp);
    return result;
}
#endif

#ifdef HAVE_EXECVP
static int call_execvp(const char *file,
                       char *const argv[]) {
    typedef int (*func)(const char *,
                        char *const []);

    DLSYM(func, fp, "execvp");

    char **const original = environ;
    char const **const modified = str_p_ud(original, &initial_env);
    environ = (char **)modified;
    int const result = (*fp)(file, argv);
    environ = original;
    str_arr_free(modified);
    return result;
}
#endif

#ifdef HAVE_EXECVP2
static int call_execvP(const char *file,
                       const char *search_path,
                       char *const argv[]) {
    typedef int (*func)(const char *,
                        const char *,
                        char *const *);

    DLSYM(func, fp, "execvP");

    char **const original = environ;
    char const **const modified = str_p_ud(original, &initial_env);
    environ = (char **)modified;
    int const result = (*fp)(file, search_path, argv);
    environ = original;
    str_arr_free(modified);
    return result;
}
#endif

#ifdef HAVE_EXECT
static int call_exect(const char *path,
                      char *const argv[],
                      char *const envp[]) {
    typedef int (*func)(const char  *,
                        char *const *,
                        char *const *);

    DLSYM(func, fp, "exect");

    char const **const menvp = str_p_ud(envp, &initial_env);
    int const result = (*fp)(path, argv, (char *const *)menvp);
    str_arr_free(menvp);
    return result;
}
#endif

// #ifdef HAVE_POSIX_SPAWN
// static int call_posix_spawn(pid_t *restrict pid, const char *restrict path,
//                             const posix_spawn_file_actions_t *file_actions,
//                             const posix_spawnattr_t *restrict attrp,
//                             char *const argv[restrict],
//                             char *const envp[restrict]) {
//     typedef int (*func)(pid_t *restrict, const char *restrict,
//                         const posix_spawn_file_actions_t *,
//                         const posix_spawnattr_t *restrict,
//                         char *const *restrict, char *const *restrict);

//     DLSYM(func, fp, "posix_spawn");

//     char const **const menvp = str_p_ud(envp, &initial_env);
//     int const result =
//         (*fp)(pid, path, file_actions, attrp, argv, (char *const *restrict)menvp);
//     str_arr_free(menvp);
//     return result;
// }
// #endif
// 
// #ifdef HAVE_POSIX_SPAWNP
// static int call_posix_spawnp(pid_t *restrict pid, const char *restrict file,
//                              const posix_spawn_file_actions_t *file_actions,
//                              const posix_spawnattr_t *restrict attrp,
//                              char *const argv[restrict],
//                              char *const envp[restrict]) {
//     typedef int (*func)(pid_t *restrict, const char *restrict,
//                         const posix_spawn_file_actions_t *,
//                         const posix_spawnattr_t *restrict,
//                         char *const *restrict, char *const *restrict);

//     DLSYM(func, fp, "posix_spawnp");

//     char const **const menvp = str_p_ud(envp, &initial_env);
//     int const result =
//         (*fp)(pid, file, file_actions, attrp, argv, (char *const *restrict)menvp);
//     str_arr_free(menvp);
//     return result;
// }
// #endif


/* update environment */

static int capture_env_t(hook_env_t *env) {
    for (size_t it = 0; it < ENV_SIZE; ++it) {
        char const* const env_value = getenv(env_names[it]);
        assert(env_value != 0);
        char const* const env_copy = strdup(env_value);
        assert(env_copy != 0);
        (*env)[it] = env_copy;
    }
    return 1;
}

static void release_env_t(hook_env_t *env) {
    for (size_t it = 0; it < ENV_SIZE; ++it) {
        free((void *)(*env)[it]);
        (*env)[it] = 0;
    }
}

static char const **str_p_ud(char *const envp[],
                             hook_env_t *env) {
    char const **result = str_arr_copy((char const **)envp);
    for (size_t it = 0; it < ENV_SIZE && (*env)[it]; ++it)
        result = str_s_ud(result, env_names[it], (*env)[it]);
    return result;
}

static char const **str_s_ud(char const *envs[],
                             char const *key,
                             char const * const value) {
    // find the key if it's there
    size_t const key_length = strlen(key);
    char const **it = envs;
    for (; (it) && (*it); ++it) {
        if (0 == strncmp(*it, key, key_length) &&
            strlen(*it) > key_length && 
            '=' == (*it)[key_length]) {
            break;
        }
    }
    // allocate a environment entry
    size_t const value_length = strlen(value);
    size_t const env_length = key_length + value_length + 2;
    char *env = malloc(env_length);
    assert(env != 0);
    assert(-1 != snprintf(env, env_length, "%s=%s", key, value));
    // replace or append the environment entry
    if (it && *it) {
        free((void *)*it);
        *it = env;
	    return envs;
    }
    else {
        size_t const size = str_arr_len(envs);
        char const **result = realloc(envs, (size + 2) * sizeof(char const *));
        assert(result != 0);
        result[size] = env;
        result[size + 1] = 0;
        return result;
    }
}

static char const **varlist2argv(char const *const arg, va_list *args) {
    char const **result = 0;
    size_t size = 0;
    for (char const *it = arg; it; it = va_arg(*args, char const *)) {
        result = realloc(result, (size + 1) * sizeof(char *));
        char const *copy = (char const*)strdup(it);
        result[size++] = copy;
    }
    result = realloc(result, (size + 1) * sizeof(char const *));
    result[size++] = 0;

    return result;
}

static char const **str_arr_copy(char const **const in) {
    size_t const sz = str_arr_len(in);

    char const** result = malloc((sz + 1) * sizeof(char*));
    char const** out_it = result;
    for (char const *const *in_it = in; (in_it) && (*in_it);
         ++in_it, ++out_it) {
        // *out_it = strdup(*in_it);
        *out_it = *in_it;
    }
    *out_it = 0;
    return result;
}

static size_t str_arr_len(char const *const *const in) {
    size_t result = 0;
    for (char** it = (char**)in; (it) && (*it); ++it) {
        ++result;
    }
    return result;
}

static void str_arr_free(char const** in) {
    for (char const** it = in; (it) && (*it); ++it) {
        free((void *)*it);
    }
    free((void *)in);
}
