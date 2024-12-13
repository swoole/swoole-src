/*
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Wez Furlong <wez@thebrainroom.com>                           |
   +----------------------------------------------------------------------+
 */

#include "thirdparty/php/standard/proc_open.h"

using namespace std;
using swoole::Coroutine;
using swoole::PHPCoroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_PTY_H
#include <pty.h>
#elif defined(__FreeBSD__)
/* FreeBSD defines `openpty` in <libutil.h> */
#include <libutil.h>
#elif defined(__NetBSD__) || defined(__DragonFly__)
/* On recent NetBSD/DragonFlyBSD releases the emalloc, estrdup ... calls had been introduced in libutil */
#if defined(__NetBSD__)
#include <sys/termios.h>
#else
#include <termios.h>
#endif
extern int openpty(int *, int *, char *, struct termios *, struct winsize *);
#elif defined(__sun)
#include <termios.h>
#else
/* Mac OS X (and some BSDs) define `openpty` in <util.h> */
#include <util.h>
#endif

static int le_proc_open;
static const char *le_proc_name = "process/coroutine";

static pid_t _co_waitpid(pid_t __pid, int *__stat_loc, int __options) {
#ifdef SW_THREAD
    return System::waitpid_safe(__pid, __stat_loc, __options);
#else
    return System::waitpid(__pid, __stat_loc, __options);
#endif
}

/* {{{ _php_array_to_envp
 * Process the `environment` argument to `proc_open`
 * Convert into data structures which can be passed to underlying OS APIs like `exec` on POSIX or
 * `CreateProcessW` on Win32 */
static sw_php_process_env _php_array_to_envp(zval *environment) {
    zval *element;
    sw_php_process_env env;
#ifndef PHP_WIN32
    char **ep;
#endif
    char *p;
    size_t sizeenv = 0;
    HashTable *env_hash; /* temporary PHP array used as helper */

    memset(&env, 0, sizeof(env));

    if (!environment) {
        return env;
    }

    uint32_t cnt = zend_hash_num_elements(Z_ARRVAL_P(environment));

    if (cnt < 1) {
#ifndef PHP_WIN32
        env.envarray = (char **) ecalloc(1, sizeof(char *));
#endif
        env.envp = (char *) ecalloc(4, 1);
        return env;
    }

    ALLOC_HASHTABLE(env_hash);
    zend_hash_init(env_hash, cnt, NULL, NULL, 0);

    void *_key, *_str;
    zend_string *key, *str;
    /* first, we have to get the size of all the elements in the hash */
    ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(environment), _key, element) {
        key = (zend_string *) _key;
        str = zval_get_string(element);

        if (ZSTR_LEN(str) == 0) {
            zend_string_release_ex(str, 0);
            continue;
        }

        sizeenv += ZSTR_LEN(str) + 1;

        if (key && ZSTR_LEN(key)) {
            sizeenv += ZSTR_LEN(key) + 1;
            zend_hash_add_ptr(env_hash, key, str);
        } else {
            zend_hash_next_index_insert_ptr(env_hash, str);
        }
    }
    ZEND_HASH_FOREACH_END();

#ifndef PHP_WIN32
    ep = env.envarray = (char **) ecalloc(cnt + 1, sizeof(char *));
#endif
    p = env.envp = (char *) ecalloc(sizeenv + 4, 1);

    ZEND_HASH_FOREACH_STR_KEY_PTR(env_hash, _key, _str) {
        key = (zend_string *) _key;
        str = (zend_string *) _str;
#ifndef PHP_WIN32
        *ep = p;
        ++ep;
#endif

        if (key) {
            memcpy(p, ZSTR_VAL(key), ZSTR_LEN(key));
            p += ZSTR_LEN(key);
            *p++ = '=';
        }

        memcpy(p, ZSTR_VAL(str), ZSTR_LEN(str));
        p += ZSTR_LEN(str);
        *p++ = '\0';
        zend_string_release_ex(str, 0);
    }
    ZEND_HASH_FOREACH_END();

    assert((uint32_t) (p - env.envp) <= sizeenv);

    zend_hash_destroy(env_hash);
    FREE_HASHTABLE(env_hash);

    return env;
}
/* }}} */

/* {{{ _php_free_envp
 * Free the structures allocated by `_php_array_to_envp` */
static void _php_free_envp(sw_php_process_env env) {
    if (env.envarray) {
        efree(env.envarray);
    }
    if (env.envp) {
        efree(env.envp);
    }
}
/* }}} */

static void proc_co_rsrc_dtor(zend_resource *rsrc) {
    sw_php_process_handle *proc = (sw_php_process_handle *) rsrc->ptr;
    int wstatus = 0;

    /* Close all handles to avoid a deadlock */
    for (int i = 0; i < proc->npipes; i++) {
        if (proc->pipes[i] != NULL) {
            GC_DELREF(proc->pipes[i]);
            zend_list_close(proc->pipes[i]);
            proc->pipes[i] = NULL;
        }
    }

    if (proc->running) {
        _co_waitpid(proc->child, &wstatus, 0);
    }
    if (proc->wstatus) {
        *proc->wstatus = wstatus;
    }

    _php_free_envp(proc->env);
    efree(proc->pipes);
    zend_string_release_ex(proc->command, false);
    efree(proc);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION(proc_open) */
void swoole_proc_open_init(int module_number) {
    le_proc_open = zend_register_list_destructors_ex(proc_co_rsrc_dtor, NULL, le_proc_name, module_number);
}
/* }}} */

/* {{{ Kill a process opened by `proc_open` */
PHP_FUNCTION(swoole_proc_terminate) {
    zval *zproc;
    sw_php_process_handle *proc;
    zend_long sig_no = SIGTERM;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_RESOURCE(zproc)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(sig_no)
    ZEND_PARSE_PARAMETERS_END();

    proc = (sw_php_process_handle *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open);
    if (proc == NULL) {
        RETURN_THROWS();
    }

#ifdef PHP_WIN32
    RETURN_BOOL(TerminateProcess(proc->childHandle, 255));
#else
    RETURN_BOOL(kill(proc->child, sig_no) == 0);
#endif
}
/* }}} */

/* {{{ Close a process opened by `proc_open` */
PHP_FUNCTION(swoole_proc_close) {
    zval *zproc;
    int wstatus = 0;
    sw_php_process_handle *proc;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(zproc)
    ZEND_PARSE_PARAMETERS_END();

    if ((proc = (sw_php_process_handle *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open)) == NULL) {
        RETURN_THROWS();
    }
    proc->wstatus = &wstatus;
    zend_list_close(Z_RES_P(zproc));
    RETURN_LONG(wstatus);
}
/* }}} */

/* {{{ Get information about a process opened by `proc_open` */
PHP_FUNCTION(swoole_proc_get_status) {
    zval *zproc;
    sw_php_process_handle *proc;
    int wstatus;
    pid_t wait_pid;
    bool running = 1, signaled = 0, stopped = 0;
    int exitcode = -1, termsig = 0, stopsig = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(zproc)
    ZEND_PARSE_PARAMETERS_END();

    if ((proc = (sw_php_process_handle *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open)) == NULL) {
        RETURN_THROWS();
    }

    array_init(return_value);
    add_assoc_str(return_value, "command", zend_string_copy(proc->command));
    add_assoc_long(return_value, "pid", (zend_long) proc->child);

    errno = 0;
    wait_pid = _co_waitpid(proc->child, &wstatus, WNOHANG | WUNTRACED);

    if (wait_pid == proc->child) {
        if (WIFEXITED(wstatus)) {
            running = 0;
            exitcode = WEXITSTATUS(wstatus);
        }
        if (WIFSIGNALED(wstatus)) {
            running = 0;
            signaled = 1;
            termsig = WTERMSIG(wstatus);
        }
        if (WIFSTOPPED(wstatus)) {
            stopped = 1;
            stopsig = WSTOPSIG(wstatus);
        }
    } else if (wait_pid == -1) {
        /* The only error which could occur here is ECHILD, which means that the PID we were
         * looking for either does not exist or is not a child of this process */
        running = 0;
    }

    proc->running = running;

    add_assoc_bool(return_value, "running", running);
    add_assoc_bool(return_value, "signaled", signaled);
    add_assoc_bool(return_value, "stopped", stopped);
    add_assoc_long(return_value, "exitcode", exitcode);
    add_assoc_long(return_value, "termsig", termsig);
    add_assoc_long(return_value, "stopsig", stopsig);
}
/* }}} */

#ifdef PHP_WIN32

/* We use this to allow child processes to inherit handles
 * One static instance can be shared and used for all calls to `proc_open`, since the values are
 * never changed */
SECURITY_ATTRIBUTES php_proc_open_security = {
    .nLength = sizeof(SECURITY_ATTRIBUTES), .lpSecurityDescriptor = NULL, .bInheritHandle = TRUE};

#define pipe(pair) (CreatePipe(&pair[0], &pair[1], &php_proc_open_security, 0) ? 0 : -1)

#define COMSPEC_NT "cmd.exe"

static inline HANDLE dup_handle(HANDLE src, BOOL inherit, BOOL closeorig) {
    HANDLE copy, self = GetCurrentProcess();

    if (!DuplicateHandle(
            self, src, self, &copy, 0, inherit, DUPLICATE_SAME_ACCESS | (closeorig ? DUPLICATE_CLOSE_SOURCE : 0)))
        return NULL;
    return copy;
}

static inline HANDLE dup_fd_as_handle(int fd) {
    return dup_handle((HANDLE) _get_osfhandle(fd), TRUE, FALSE);
}

#define close_descriptor(fd) CloseHandle(fd)
#else /* !PHP_WIN32 */
#define close_descriptor(fd) close(fd)
#endif

/* Determines the type of a descriptor item. */
typedef enum _descriptor_type { DESCRIPTOR_TYPE_STD, DESCRIPTOR_TYPE_PIPE, DESCRIPTOR_TYPE_SOCKET } descriptor_type;

/* One instance of this struct is created for each item in `$descriptorspec` argument to `proc_open`
 * They are used within `proc_open` and freed before it returns */
typedef struct _descriptorspec_item {
    int index; /* desired FD # in child process */
    descriptor_type type;
    php_file_descriptor_t childend;  /* FD # opened for use in child
                                      * (will be copied to `index` in child) */
    php_file_descriptor_t parentend; /* FD # opened for use in parent
                                      * (for pipes only; will be 0 otherwise) */
    int mode_flags;                  /* mode for opening FDs: r/o, r/w, binary (on Win32), etc */
} descriptorspec_item;

static zend_string *get_valid_arg_string(zval *zv, int elem_num) {
    zend_string *str = zval_get_string(zv);
    if (!str) {
        return NULL;
    }

    if (elem_num == 1 && ZSTR_LEN(str) == 0) {
        zend_value_error("First element must contain a non-empty program name");
        zend_string_release(str);
        return NULL;
    }

    if (strlen(ZSTR_VAL(str)) != ZSTR_LEN(str)) {
        zend_value_error("Command array element %d contains a null byte", elem_num);
        zend_string_release(str);
        return NULL;
    }

    return str;
}

#ifdef PHP_WIN32
static void append_backslashes(smart_str *str, size_t num_bs) {
    for (size_t i = 0; i < num_bs; i++) {
        smart_str_appendc(str, '\\');
    }
}

/* See https://docs.microsoft.com/en-us/cpp/cpp/parsing-cpp-command-line-arguments */
static void append_win_escaped_arg(smart_str *str, zend_string *arg) {
    size_t num_bs = 0;

    smart_str_appendc(str, '"');
    for (size_t i = 0; i < ZSTR_LEN(arg); ++i) {
        char c = ZSTR_VAL(arg)[i];
        if (c == '\\') {
            num_bs++;
            continue;
        }

        if (c == '"') {
            /* Backslashes before " need to be doubled. */
            num_bs = num_bs * 2 + 1;
        }
        append_backslashes(str, num_bs);
        smart_str_appendc(str, c);
        num_bs = 0;
    }
    append_backslashes(str, num_bs * 2);
    smart_str_appendc(str, '"');
}

static zend_string *create_win_command_from_args(HashTable *args) {
    smart_str str = {0};
    zval *arg_zv;
    bool is_prog_name = 1;
    int elem_num = 0;

    ZEND_HASH_FOREACH_VAL(args, arg_zv) {
        zend_string *arg_str = get_valid_arg_string(arg_zv, ++elem_num);
        if (!arg_str) {
            smart_str_free(&str);
            return NULL;
        }

        if (!is_prog_name) {
            smart_str_appendc(&str, ' ');
        }

        append_win_escaped_arg(&str, arg_str);

        is_prog_name = 0;
        zend_string_release(arg_str);
    }
    ZEND_HASH_FOREACH_END();
    smart_str_0(&str);
    return str.s;
}

/* Get a boolean option from the `other_options` array which can be passed to `proc_open`.
 * (Currently, all options apply on Windows only.) */
static bool get_option(zval *other_options, char *opt_name, size_t opt_name_len) {
    HashTable *opt_ary = Z_ARRVAL_P(other_options);
    zval *item = zend_hash_str_find_deref(opt_ary, opt_name, opt_name_len);
    return item != NULL && (Z_TYPE_P(item) == IS_TRUE || ((Z_TYPE_P(item) == IS_LONG) && Z_LVAL_P(item)));
}

/* Initialize STARTUPINFOW struct, used on Windows when spawning a process.
 * Ref: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow */
static void init_startup_info(STARTUPINFOW *si, descriptorspec_item *descriptors, int ndesc) {
    memset(si, 0, sizeof(STARTUPINFOW));
    si->cb = sizeof(STARTUPINFOW);
    si->dwFlags = STARTF_USESTDHANDLES;

    si->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si->hStdError = GetStdHandle(STD_ERROR_HANDLE);

    /* redirect stdin/stdout/stderr if requested */
    for (int i = 0; i < ndesc; i++) {
        switch (descriptors[i].index) {
        case 0:
            si->hStdInput = descriptors[i].childend;
            break;
        case 1:
            si->hStdOutput = descriptors[i].childend;
            break;
        case 2:
            si->hStdError = descriptors[i].childend;
            break;
        }
    }
}

static void init_process_info(PROCESS_INFORMATION *pi) {
    memset(&pi, 0, sizeof(pi));
}

static zend_result convert_command_to_use_shell(wchar_t **cmdw, size_t cmdw_len) {
    size_t len = sizeof(COMSPEC_NT) + sizeof(" /s /c ") + cmdw_len + 3;
    wchar_t *cmdw_shell = (wchar_t *) malloc(len * sizeof(wchar_t));

    if (cmdw_shell == NULL) {
        php_error_docref(NULL, E_WARNING, "Command conversion failed");
        return FAILURE;
    }

    if (_snwprintf(cmdw_shell, len, L"%hs /s /c \"%s\"", COMSPEC_NT, *cmdw) == -1) {
        free(cmdw_shell);
        php_error_docref(NULL, E_WARNING, "Command conversion failed");
        return FAILURE;
    }

    free(*cmdw);
    *cmdw = cmdw_shell;

    return SUCCESS;
}
#endif

/* Convert command parameter array passed as first argument to `proc_open` into command string */
static zend_string *get_command_from_array(HashTable *array, char ***argv, int num_elems) {
    zval *arg_zv;
    zend_string *command = NULL;
    int i = 0;

    *argv = (char **) safe_emalloc(sizeof(char *), num_elems + 1, 0);

    ZEND_HASH_FOREACH_VAL(array, arg_zv) {
        zend_string *arg_str = get_valid_arg_string(arg_zv, i + 1);
        if (!arg_str) {
            /* Terminate with NULL so exit_fail code knows how many entries to free */
            (*argv)[i] = NULL;
            if (command != NULL) {
                zend_string_release_ex(command, false);
            }
            return NULL;
        }

        if (i == 0) {
            command = zend_string_copy(arg_str);
        }

        (*argv)[i++] = (char *) estrdup(ZSTR_VAL(arg_str));
        zend_string_release(arg_str);
    }
    ZEND_HASH_FOREACH_END();

    (*argv)[i] = NULL;
    return command;
}

static descriptorspec_item *alloc_descriptor_array(HashTable *descriptorspec) {
    uint32_t ndescriptors = zend_hash_num_elements(descriptorspec);
    return (descriptorspec_item *) ecalloc(sizeof(descriptorspec_item), ndescriptors);
}

static zend_string *get_string_parameter(zval *array, int index, const char *param_name) {
    zval *array_item;
    if ((array_item = zend_hash_index_find(Z_ARRVAL_P(array), index)) == NULL) {
        zend_value_error("Missing %s", param_name);
        return NULL;
    }
    return zval_try_get_string(array_item);
}

static zend_result set_proc_descriptor_to_blackhole(descriptorspec_item *desc) {
#ifdef PHP_WIN32
    desc->childend = CreateFileA(
        "nul", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (desc->childend == NULL) {
        php_error_docref(NULL, E_WARNING, "Failed to open nul");
        return FAILURE;
    }
#else
    desc->childend = open("/dev/null", O_RDWR);
    if (desc->childend < 0) {
        php_error_docref(NULL, E_WARNING, "Failed to open /dev/null: %s", strerror(errno));
        return FAILURE;
    }
#endif
    return SUCCESS;
}

static zend_result set_proc_descriptor_to_pty(descriptorspec_item *desc, int *master_fd, int *slave_fd) {
#ifdef HAVE_OPENPTY
    /* All FDs set to PTY in the child process will go to the slave end of the same PTY.
     * Likewise, all the corresponding entries in `$pipes` in the parent will all go to the master
     * end of the same PTY.
     * If this is the first descriptorspec set to 'pty', find an available PTY and get master and
     * slave FDs. */
    if (*master_fd == -1) {
        if (openpty(master_fd, slave_fd, NULL, NULL, NULL)) {
            php_error_docref(NULL, E_WARNING, "Could not open PTY (pseudoterminal): %s", strerror(errno));
            return FAILURE;
        }
    }

    desc->type = DESCRIPTOR_TYPE_PIPE;
    desc->childend = dup(*slave_fd);
    desc->parentend = dup(*master_fd);
    desc->mode_flags = O_RDWR;
    return SUCCESS;
#else
    php_error_docref(NULL, E_WARNING, "PTY (pseudoterminal) not supported on this system");
    return FAILURE;
#endif
}

/* Mark the descriptor close-on-exec, so it won't be inherited by children */
static php_file_descriptor_t make_descriptor_cloexec(php_file_descriptor_t fd) {
#ifdef PHP_WIN32
    return dup_handle(fd, FALSE, TRUE);
#else
#if defined(F_SETFD) && defined(FD_CLOEXEC)
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    return fd;
#endif
}

static zend_result set_proc_descriptor_to_pipe(descriptorspec_item *desc, zend_string *zmode) {
    php_file_descriptor_t newpipe[2];

    if (pipe(newpipe) != 0) {
        php_error_docref(NULL, E_WARNING, "Unable to create pipe %s", strerror(errno));
        return FAILURE;
    }

    desc->type = DESCRIPTOR_TYPE_PIPE;

    if (strncmp(ZSTR_VAL(zmode), "w", 1) != 0) {
        desc->parentend = newpipe[1];
        desc->childend = newpipe[0];
        desc->mode_flags = O_WRONLY;
    } else {
        desc->parentend = newpipe[0];
        desc->childend = newpipe[1];
        desc->mode_flags = O_RDONLY;
    }

    desc->parentend = make_descriptor_cloexec(desc->parentend);

#ifdef PHP_WIN32
    if (ZSTR_LEN(zmode) >= 2 && ZSTR_VAL(zmode)[1] == 'b') desc->mode_flags |= O_BINARY;
#endif

    return SUCCESS;
}

#ifdef PHP_WIN32
#define create_socketpair(socks) socketpair_win32(AF_INET, SOCK_STREAM, 0, (socks), 0)
#else
#define create_socketpair(socks) socketpair(AF_UNIX, SOCK_STREAM, 0, (socks))
#endif

static zend_result set_proc_descriptor_to_socket(descriptorspec_item *desc) {
    php_socket_t sock[2];

    if (create_socketpair(sock)) {
        zend_string *err = php_socket_error_str(php_socket_errno());
        php_error_docref(NULL, E_WARNING, "Unable to create socket pair: %s", ZSTR_VAL(err));
        zend_string_release(err);
        return FAILURE;
    }

    desc->type = DESCRIPTOR_TYPE_SOCKET;
    desc->parentend = make_descriptor_cloexec((php_file_descriptor_t) sock[0]);

    /* Pass sock[1] to child because it will never use overlapped IO on Windows. */
    desc->childend = (php_file_descriptor_t) sock[1];

    return SUCCESS;
}

static zend_result set_proc_descriptor_to_file(descriptorspec_item *desc,
                                               zend_string *file_path,
                                               zend_string *file_mode) {
    php_socket_t fd;

    /* try a wrapper */
    php_stream *stream =
        php_stream_open_wrapper(ZSTR_VAL(file_path), ZSTR_VAL(file_mode), REPORT_ERRORS | STREAM_WILL_CAST, NULL);
    if (stream == NULL) {
        return FAILURE;
    }

    /* force into an fd */
    if (php_stream_cast(stream, PHP_STREAM_CAST_RELEASE | PHP_STREAM_AS_FD, (void **) &fd, REPORT_ERRORS) == FAILURE) {
        return FAILURE;
    }

#ifdef PHP_WIN32
    desc->childend = dup_fd_as_handle((int) fd);
    _close((int) fd);

    /* Simulate the append mode by fseeking to the end of the file
     * This introduces a potential race condition, but it is the best we can do */
    if (strchr(ZSTR_VAL(file_mode), 'a')) {
        SetFilePointer(desc->childend, 0, NULL, FILE_END);
    }
#else
    desc->childend = fd;
#endif
    return SUCCESS;
}

static zend_result dup_proc_descriptor(php_file_descriptor_t from, php_file_descriptor_t *to, zend_ulong nindex) {
#ifdef PHP_WIN32
    *to = dup_handle(from, TRUE, FALSE);
    if (*to == NULL) {
        php_error_docref(NULL, E_WARNING, "Failed to dup() for descriptor " ZEND_LONG_FMT, nindex);
        return FAILURE;
    }
#else
    *to = dup(from);
    if (*to < 0) {
        php_error_docref(
            NULL, E_WARNING, "Failed to dup() for descriptor " ZEND_LONG_FMT ": %s", nindex, strerror(errno));
        return FAILURE;
    }
#endif
    return SUCCESS;
}

static zend_result redirect_proc_descriptor(
    descriptorspec_item *desc, int target, descriptorspec_item *descriptors, int ndesc, int nindex) {
    php_file_descriptor_t redirect_to = PHP_INVALID_FD;

    for (int i = 0; i < ndesc; i++) {
        if (descriptors[i].index == target) {
            redirect_to = descriptors[i].childend;
            break;
        }
    }

    if (redirect_to == PHP_INVALID_FD) { /* Didn't find the index we wanted */
        if (target < 0 || target > 2) {
            php_error_docref(NULL, E_WARNING, "Redirection target %d not found", target);
            return FAILURE;
        }

        /* Support referring to a stdin/stdout/stderr pipe adopted from the parent,
         * which happens whenever an explicit override is not provided. */
#ifndef PHP_WIN32
        redirect_to = target;
#else
        switch (target) {
        case 0:
            redirect_to = GetStdHandle(STD_INPUT_HANDLE);
            break;
        case 1:
            redirect_to = GetStdHandle(STD_OUTPUT_HANDLE);
            break;
        case 2:
            redirect_to = GetStdHandle(STD_ERROR_HANDLE);
            break;
            EMPTY_SWITCH_DEFAULT_CASE()
        }
#endif
    }

    return dup_proc_descriptor(redirect_to, &desc->childend, nindex);
}

/* Process one item from `$descriptorspec` argument to `proc_open` */
static zend_result set_proc_descriptor_from_array(
    zval *descitem, descriptorspec_item *descriptors, int ndesc, int nindex, int *pty_master_fd, int *pty_slave_fd) {
    zend_string *ztype = get_string_parameter(descitem, 0, "handle qualifier");
    if (!ztype) {
        return FAILURE;
    }

    zend_string *zmode = NULL, *zfile = NULL;
    zend_result retval = FAILURE;

#if 0
    if (zend_string_equals_literal(ztype, "pipe")) {
        /* Set descriptor to pipe */
        zmode = get_string_parameter(descitem, 1, "mode parameter for 'pipe'");
        if (zmode == NULL) {
            goto finish;
        }
        retval = set_proc_descriptor_to_pipe(&descriptors[ndesc], zmode);
    } else
#endif
    if (zend_string_equals_literal(ztype, "socket") || zend_string_equals_literal(ztype, "pipe")) {
        /* Set descriptor to socketpair */
        retval = set_proc_descriptor_to_socket(&descriptors[ndesc]);
    } else if (zend_string_equals(ztype, ZSTR_KNOWN(ZEND_STR_FILE))) {
        /* Set descriptor to file */
        if ((zfile = get_string_parameter(descitem, 1, "file name parameter for 'file'")) == NULL) {
            goto finish;
        }
        if ((zmode = get_string_parameter(descitem, 2, "mode parameter for 'file'")) == NULL) {
            goto finish;
        }
        retval = set_proc_descriptor_to_file(&descriptors[ndesc], zfile, zmode);
    } else if (zend_string_equals_literal(ztype, "redirect")) {
        /* Redirect descriptor to whatever another descriptor is set to */
        zval *ztarget = zend_hash_index_find_deref(Z_ARRVAL_P(descitem), 1);
        if (!ztarget) {
            zend_value_error("Missing redirection target");
            goto finish;
        }
        if (Z_TYPE_P(ztarget) != IS_LONG) {
            zend_value_error("Redirection target must be of type int, %s given", zend_zval_type_name(ztarget));
            goto finish;
        }

        retval = redirect_proc_descriptor(&descriptors[ndesc], (int) Z_LVAL_P(ztarget), descriptors, ndesc, nindex);
    } else if (zend_string_equals(ztype, ZSTR_KNOWN(ZEND_STR_NULL_LOWERCASE))) {
        /* Set descriptor to blackhole (discard all data written) */
        retval = set_proc_descriptor_to_blackhole(&descriptors[ndesc]);
    } else if (zend_string_equals_literal(ztype, "pty")) {
        /* Set descriptor to slave end of PTY */
        retval = set_proc_descriptor_to_pty(&descriptors[ndesc], pty_master_fd, pty_slave_fd);
    } else {
        php_error_docref(NULL, E_WARNING, "%s is not a valid descriptor spec/mode", ZSTR_VAL(ztype));
        goto finish;
    }

finish:
    if (zmode) zend_string_release(zmode);
    if (zfile) zend_string_release(zfile);
    zend_string_release(ztype);
    return retval;
}

static zend_result set_proc_descriptor_from_resource(zval *resource, descriptorspec_item *desc, int nindex) {
    /* Should be a stream - try and dup the descriptor */
    php_stream *stream = (php_stream *) zend_fetch_resource(Z_RES_P(resource), "stream", php_file_le_stream());
    if (stream == NULL) {
        return FAILURE;
    }

    php_socket_t fd;
    zend_result status = (zend_result) php_stream_cast(stream, PHP_STREAM_AS_FD, (void **) &fd, REPORT_ERRORS);
    if (status == FAILURE) {
        return FAILURE;
    }

#ifdef PHP_WIN32
    php_file_descriptor_t fd_t = (php_file_descriptor_t) _get_osfhandle(fd);
#else
    php_file_descriptor_t fd_t = fd;
#endif
    return dup_proc_descriptor(fd_t, &desc->childend, nindex);
}

#ifndef PHP_WIN32
#if defined(USE_POSIX_SPAWN)
static zend_result close_parentends_of_pipes(posix_spawn_file_actions_t *actions,
                                             descriptorspec_item *descriptors,
                                             int ndesc) {
    int r;
    for (int i = 0; i < ndesc; i++) {
        if (descriptors[i].type != DESCRIPTOR_TYPE_STD) {
            r = posix_spawn_file_actions_addclose(actions, descriptors[i].parentend);
            if (r != 0) {
                php_error_docref(
                    NULL, E_WARNING, "Cannot close file descriptor %d: %s", descriptors[i].parentend, strerror(r));
                return FAILURE;
            }
        }
        if (descriptors[i].childend != descriptors[i].index) {
            r = posix_spawn_file_actions_adddup2(actions, descriptors[i].childend, descriptors[i].index);
            if (r != 0) {
                php_error_docref(NULL,
                                 E_WARNING,
                                 "Unable to copy file descriptor %d (for pipe) into "
                                 "file descriptor %d: %s",
                                 descriptors[i].childend,
                                 descriptors[i].index,
                                 strerror(r));
                return FAILURE;
            }
            r = posix_spawn_file_actions_addclose(actions, descriptors[i].childend);
            if (r != 0) {
                php_error_docref(
                    NULL, E_WARNING, "Cannot close file descriptor %d: %s", descriptors[i].childend, strerror(r));
                return FAILURE;
            }
        }
    }

    return SUCCESS;
}
#else
static zend_result close_parentends_of_pipes(descriptorspec_item *descriptors, int ndesc) {
    /* We are running in child process
     * Close the 'parent end' of pipes which were opened before forking/spawning
     * Also, dup() the child end of all pipes as necessary so they will use the FD
     * number which the user requested */
    for (int i = 0; i < ndesc; i++) {
        if (descriptors[i].type != DESCRIPTOR_TYPE_STD) {
            close(descriptors[i].parentend);
        }
        if (descriptors[i].childend != descriptors[i].index) {
            if (dup2(descriptors[i].childend, descriptors[i].index) < 0) {
                php_error_docref(NULL,
                                 E_WARNING,
                                 "Unable to copy file descriptor %d (for pipe) into "
                                 "file descriptor %d: %s",
                                 descriptors[i].childend,
                                 descriptors[i].index,
                                 strerror(errno));
                return FAILURE;
            }
            close(descriptors[i].childend);
        }
    }

    return SUCCESS;
}
#endif
#endif

static void close_all_descriptors(descriptorspec_item *descriptors, int ndesc) {
    for (int i = 0; i < ndesc; i++) {
        close_descriptor(descriptors[i].childend);
        if (descriptors[i].parentend) close_descriptor(descriptors[i].parentend);
    }
}

static void efree_argv(char **argv) {
    if (argv) {
        char **arg = argv;
        while (*arg != NULL) {
            efree(*arg);
            arg++;
        }
        efree(argv);
    }
}

/* {{{ Execute a command, with specified files used for input/output */
PHP_FUNCTION(swoole_proc_open) {
    zend_string *command_str;
    HashTable *command_ht;
    HashTable *descriptorspec;                       /* Mandatory argument */
    zval *pipes;                                     /* Mandatory argument */
    char *cwd = NULL;                                /* Optional argument */
    size_t cwd_len = 0;                              /* Optional argument */
    zval *environment = NULL, *other_options = NULL; /* Optional arguments */

    sw_php_process_env env;
    int ndesc = 0;
    int i;
    zval *descitem = NULL;
    zend_string *str_index;
    zend_ulong nindex;
    descriptorspec_item *descriptors = NULL;
#ifdef PHP_WIN32
    PROCESS_INFORMATION pi;
    HANDLE childHandle;
    STARTUPINFOW si;
    BOOL newprocok;
    DWORD dwCreateFlags = 0;
    UINT old_error_mode;
    char cur_cwd[MAXPATHLEN];
    wchar_t *cmdw = NULL, *cwdw = NULL, *envpw = NULL;
    size_t cmdw_len;
    bool suppress_errors = 0;
    bool bypass_shell = 0;
    bool blocking_pipes = 0;
    bool create_process_group = 0;
    bool create_new_console = 0;
#else
    char **argv = NULL;
#endif
    int pty_master_fd = -1, pty_slave_fd = -1;
    php_process_id_t child;
    sw_php_process_handle *proc;

    ZEND_PARSE_PARAMETERS_START(3, 6)
    Z_PARAM_ARRAY_HT_OR_STR(command_ht, command_str)
    Z_PARAM_ARRAY_HT(descriptorspec)
    Z_PARAM_ZVAL(pipes)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING_OR_NULL(cwd, cwd_len)
    Z_PARAM_ARRAY_OR_NULL(environment)
    Z_PARAM_ARRAY_OR_NULL(other_options)
    ZEND_PARSE_PARAMETERS_END();

    memset(&env, 0, sizeof(env));

    if (command_ht) {
        uint32_t num_elems = zend_hash_num_elements(command_ht);
        if (num_elems == 0) {
            zend_argument_value_error(1, "must have at least one element");
            RETURN_THROWS();
        }

#ifdef PHP_WIN32
        /* Automatically bypass shell if command is given as an array */
        bypass_shell = 1;
        command_str = create_win_command_from_args(command_ht);
#else
        command_str = get_command_from_array(command_ht, &argv, num_elems);
#endif

        if (!command_str) {
#ifndef PHP_WIN32
            efree_argv(argv);
#endif
            RETURN_FALSE;
        }
    } else {
        zend_string_addref(command_str);
    }

#ifdef PHP_WIN32
    if (other_options) {
        suppress_errors = get_option(other_options, "suppress_errors", strlen("suppress_errors"));
        /* TODO: Deprecate in favor of array command? */
        bypass_shell = bypass_shell || get_option(other_options, "bypass_shell", strlen("bypass_shell"));
        blocking_pipes = get_option(other_options, "blocking_pipes", strlen("blocking_pipes"));
        create_process_group = get_option(other_options, "create_process_group", strlen("create_process_group"));
        create_new_console = get_option(other_options, "create_new_console", strlen("create_new_console"));
    }
#endif

    php_swoole_check_reactor();
    if (php_swoole_signal_isset_handler(SIGCHLD)) {
        php_swoole_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_proc_open");
        RETURN_FALSE;
    }

    swoole::Coroutine::get_current_safe();

    if (environment) {
        env = _php_array_to_envp(environment);
    }

    descriptors = alloc_descriptor_array(descriptorspec);

    /* Walk the descriptor spec and set up files/pipes */
    ZEND_HASH_FOREACH_KEY_VAL(descriptorspec, nindex, str_index, descitem) {
        if (str_index) {
            zend_argument_value_error(2, "must be an integer indexed array");
            goto exit_fail;
        }

        descriptors[ndesc].index = (int) nindex;

        ZVAL_DEREF(descitem);
        if (Z_TYPE_P(descitem) == IS_RESOURCE) {
            if (set_proc_descriptor_from_resource(descitem, &descriptors[ndesc], ndesc) == FAILURE) {
                goto exit_fail;
            }
        } else if (Z_TYPE_P(descitem) == IS_ARRAY) {
            if (set_proc_descriptor_from_array(
                    descitem, descriptors, ndesc, (int) nindex, &pty_master_fd, &pty_slave_fd) == FAILURE) {
                goto exit_fail;
            }
        } else {
            php_swoole_fatal_error(E_WARNING, "Descriptor item must be either an array or a File-Handle");
            goto exit_fail;
        }
        ndesc++;
    }
    ZEND_HASH_FOREACH_END();

#ifdef PHP_WIN32
    if (cwd == NULL) {
        char *getcwd_result = VCWD_GETCWD(cur_cwd, MAXPATHLEN);
        if (!getcwd_result) {
            php_error_docref(NULL, E_WARNING, "Cannot get current directory");
            goto exit_fail;
        }
        cwd = cur_cwd;
    }
    cwdw = php_win32_cp_any_to_w(cwd);
    if (!cwdw) {
        php_error_docref(NULL, E_WARNING, "CWD conversion failed");
        goto exit_fail;
    }

    init_startup_info(&si, descriptors, ndesc);
    init_process_info(&pi);

    if (suppress_errors) {
        old_error_mode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }

    dwCreateFlags = NORMAL_PRIORITY_CLASS;
    if (strcmp(sapi_module.name, "cli") != 0) {
        dwCreateFlags |= CREATE_NO_WINDOW;
    }
    if (create_process_group) {
        dwCreateFlags |= CREATE_NEW_PROCESS_GROUP;
    }
    if (create_new_console) {
        dwCreateFlags |= CREATE_NEW_CONSOLE;
    }
    envpw = php_win32_cp_env_any_to_w(env.envp);
    if (envpw) {
        dwCreateFlags |= CREATE_UNICODE_ENVIRONMENT;
    } else {
        if (env.envp) {
            php_error_docref(NULL, E_WARNING, "ENV conversion failed");
            goto exit_fail;
        }
    }

    cmdw = php_win32_cp_conv_any_to_w(ZSTR_VAL(command_str), ZSTR_LEN(command_str), &cmdw_len);
    if (!cmdw) {
        php_error_docref(NULL, E_WARNING, "Command conversion failed");
        goto exit_fail;
    }

    if (!bypass_shell) {
        if (convert_command_to_use_shell(&cmdw, cmdw_len) == FAILURE) {
            goto exit_fail;
        }
    }
    newprocok = CreateProcessW(
        NULL, cmdw, &php_proc_open_security, &php_proc_open_security, TRUE, dwCreateFlags, envpw, cwdw, &si, &pi);

    if (suppress_errors) {
        SetErrorMode(old_error_mode);
    }

    if (newprocok == FALSE) {
        DWORD dw = GetLastError();
        close_all_descriptors(descriptors, ndesc);
        php_error_docref(NULL, E_WARNING, "CreateProcess failed, error code: %u", dw);
        goto exit_fail;
    }

    childHandle = pi.hProcess;
    child = pi.dwProcessId;
    CloseHandle(pi.hThread);
#elif defined(USE_POSIX_SPAWN)
    posix_spawn_file_actions_t factions;
    int r;
    posix_spawn_file_actions_init(&factions);

    if (close_parentends_of_pipes(&factions, descriptors, ndesc) == FAILURE) {
        posix_spawn_file_actions_destroy(&factions);
        close_all_descriptors(descriptors, ndesc);
        goto exit_fail;
    }

    if (cwd) {
        r = posix_spawn_file_actions_addchdir_np(&factions, cwd);
        if (r != 0) {
            php_error_docref(NULL, E_WARNING, "posix_spawn_file_actions_addchdir_np() failed: %s", strerror(r));
        }
    }

    if (argv) {
        r = posix_spawnp(&child, ZSTR_VAL(command_str), &factions, NULL, argv, (env.envarray ? env.envarray : environ));
    } else {
        r = posix_spawn(&child,
                        "/bin/sh",
                        &factions,
                        NULL,
                        (char *const[]){"sh", "-c", ZSTR_VAL(command_str), NULL},
                        env.envarray ? env.envarray : environ);
    }
    posix_spawn_file_actions_destroy(&factions);
    if (r != 0) {
        close_all_descriptors(descriptors, ndesc);
        php_error_docref(NULL, E_WARNING, "posix_spawn() failed: %s", strerror(r));
        goto exit_fail;
    }
#elif HAVE_FORK
    /* the Unix way */
    child = swoole_fork(SW_FORK_EXEC);

    if (child == 0) {
        /* This is the child process */

        if (close_parentends_of_pipes(descriptors, ndesc) == FAILURE) {
            /* We are already in child process and can't do anything to make
             * `proc_open` return an error in the parent
             * All we can do is exit with a non-zero (error) exit code */
            _exit(127);
        }

        if (cwd) {
            php_ignore_value(chdir(cwd));
        }

        if (argv) {
            /* execvpe() is non-portable, use environ instead. */
            if (env.envarray) {
                environ = env.envarray;
            }
            execvp(ZSTR_VAL(command_str), argv);
        } else {
            if (env.envarray) {
                execle("/bin/sh", "sh", "-c", ZSTR_VAL(command_str), NULL, env.envarray);
            } else {
                execl("/bin/sh", "sh", "-c", ZSTR_VAL(command_str), NULL);
            }
        }

        /* If execvp/execle/execl are successful, we will never reach here
         * Display error and exit with non-zero (error) status code */
        php_error_docref(NULL, E_WARNING, "Exec failed: %s", strerror(errno));
        _exit(127);
    } else if (child < 0) {
        /* Failed to fork() */
        close_all_descriptors(descriptors, ndesc);
        php_error_docref(NULL, E_WARNING, "Fork failed: %s", strerror(errno));
        goto exit_fail;
    }
#else
#error You lose (configure should not have let you get here)
#endif

    /* We forked/spawned and this is the parent */

    pipes = zend_try_array_init(pipes);
    if (!pipes) {
        goto exit_fail;
    }

    proc = (sw_php_process_handle *) emalloc(sizeof(sw_php_process_handle));
    proc->command = zend_string_copy(command_str);
    proc->wstatus = nullptr;
    proc->running = true;
    proc->pipes = (zend_resource **) emalloc(sizeof(zend_resource *) * ndesc);
    proc->npipes = ndesc;
    proc->child = child;
    proc->env = env;

    /* Clean up all the child ends and then open streams on the parent
     *   ends, where appropriate */
    for (i = 0; i < ndesc; i++) {
        php_stream *stream = NULL;

        close_descriptor(descriptors[i].childend);

        if (descriptors[i].type == DESCRIPTOR_TYPE_PIPE) {
            const char *mode_string = NULL;

            switch (descriptors[i].mode_flags) {
#ifdef PHP_WIN32
            case O_WRONLY | O_BINARY:
                mode_string = "wb";
                break;
            case O_RDONLY | O_BINARY:
                mode_string = "rb";
                break;
#endif
            case O_WRONLY:
                mode_string = "w";
                break;
            case O_RDONLY:
                mode_string = "r";
                break;
            case O_RDWR:
                mode_string = "r+";
                break;
            }

#ifdef PHP_WIN32
            stream = php_stream_fopen_from_fd(
                _open_osfhandle((intptr_t) descriptors[i].parentend, descriptors[i].mode_flags), mode_string, NULL);
            php_stream_set_option(stream, PHP_STREAM_OPTION_PIPE_BLOCKING, blocking_pipes, NULL);
#else
            stream = php_swoole_create_stream_from_pipe(descriptors[i].parentend, mode_string, NULL STREAMS_CC);
#endif
        } else if (descriptors[i].type == DESCRIPTOR_TYPE_SOCKET) {
            stream = php_swoole_create_stream_from_socket(
                (php_socket_t) descriptors[i].parentend, AF_UNIX, SOCK_STREAM, 0 STREAMS_CC);
        } else {
            proc->pipes[i] = NULL;
        }

        if (stream) {
            zval retfp;

            /* nasty hack; don't copy it */
            stream->flags |= PHP_STREAM_FLAG_NO_SEEK;

            php_stream_to_zval(stream, &retfp);
            add_index_zval(pipes, descriptors[i].index, &retfp);

            proc->pipes[i] = Z_RES(retfp);
            Z_ADDREF(retfp);
        }
    }

    if (1) {
        RETVAL_RES(zend_register_resource(proc, le_proc_open));
    } else {
    exit_fail:
        _php_free_envp(env);
        RETVAL_FALSE;
    }

    zend_string_release_ex(command_str, false);
#ifdef PHP_WIN32
    free(cwdw);
    free(cmdw);
    free(envpw);
#else
    efree_argv(argv);
#endif
#ifdef HAVE_OPENPTY
    if (pty_master_fd != -1) {
        close(pty_master_fd);
    }
    if (pty_slave_fd != -1) {
        close(pty_slave_fd);
    }
#endif
    if (descriptors) {
        efree(descriptors);
    }
}
/* }}} */
