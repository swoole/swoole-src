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

#include "php_swoole_cxx.h"

SW_EXTERN_C_BEGIN
void swoole_proc_open_init(int module_number);
PHP_FUNCTION(swoole_proc_open);
PHP_FUNCTION(swoole_proc_close);
PHP_FUNCTION(swoole_proc_get_status);
PHP_FUNCTION(swoole_proc_terminate);
SW_EXTERN_C_END

#ifdef PHP_WIN32
typedef HANDLE php_file_descriptor_t;
typedef DWORD php_process_id_t;
#define PHP_INVALID_FD INVALID_HANDLE_VALUE
#else
typedef int php_file_descriptor_t;
typedef pid_t php_process_id_t;
#define PHP_INVALID_FD (-1)
#endif

/* Environment block under Win32 is a NUL terminated sequence of NUL terminated
 *   name=value strings.
 * Under Unix, it is an argv style array. */
typedef struct {
    char *envp;
#ifndef PHP_WIN32
    char **envarray;
#endif
} sw_php_process_env;

typedef struct {
    bool running;
    int *wstatus;
    php_process_id_t child;
#ifdef PHP_WIN32
    HANDLE childHandle;
#endif
    int npipes;
    zend_resource **pipes;
    zend_string *command;
    sw_php_process_env env;
#if HAVE_SYS_WAIT_H
    /* We can only request the status once before it becomes unavailable.
     * Cache the result so we can request it multiple times. */
    int cached_exit_wait_status_value;
    bool has_cached_exit_wait_status;
#endif
} sw_php_process_handle;
