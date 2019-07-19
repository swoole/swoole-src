/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2018 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Wez Furlong <wez@thebrainroom.com>                           |
   +----------------------------------------------------------------------+
 */

#include "thirdparty/php/standard/proc_open.h"
#include "coroutine_c_api.h"

using namespace std;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;

static int le_proc_open;
static const char *le_proc_name = "process/coroutine";

/* {{{ _php_array_to_envp */
static proc_co_env_t _php_array_to_envp(zval *environment)
{
    zval *element;
    proc_co_env_t env;
    zend_string *key, *str;
    char **ep;
    char *p;
    size_t cnt, l, sizeenv = 0;
    HashTable *env_hash;

    memset(&env, 0, sizeof(env));

    if (!environment)
    {
        return env;
    }

    cnt = zend_hash_num_elements(Z_ARRVAL_P(environment));

    if (cnt < 1)
    {
        env.envarray = (char **) ecalloc(1, sizeof(char *));
        env.envp = (char *) ecalloc(4, 1);
        return env;
    }

    ALLOC_HASHTABLE(env_hash);
    zend_hash_init(env_hash, cnt, NULL, NULL, 0);

    /* first, we have to get the size of all the elements in the hash */
    ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(environment), key, element)
    {
        str = zval_get_string(element);

        if (ZSTR_LEN(str) == 0)
        {
            zend_string_release(str);
            continue;
        }

        sizeenv += ZSTR_LEN(str) + 1;

        if (key && ZSTR_LEN(key))
        {
            sizeenv += ZSTR_LEN(key) + 1;
            zend_hash_add_ptr(env_hash, key, str);
        }
        else
        {
            zend_hash_next_index_insert_ptr(env_hash, str);
        }
    }
    ZEND_HASH_FOREACH_END();

    ep = env.envarray = (char **) ecalloc(cnt + 1, sizeof(char *));
    p = env.envp = (char *) ecalloc(sizeenv + 4, 1);

    void *_v1, *_v2;
    ZEND_HASH_FOREACH_STR_KEY_PTR(env_hash, _v1, _v2)
    {
        key = (zend_string*) _v1;
        str = (zend_string*) _v2;

        if (key)
        {
            l = ZSTR_LEN(key) + ZSTR_LEN(str) + 2;
            memcpy(p, ZSTR_VAL(key), ZSTR_LEN(key));
            strncat(p, "=", 1);
            strncat(p, ZSTR_VAL(str), ZSTR_LEN(str));

            *ep = p;
            ++ep;
            p += l;
        }
        else
        {
            memcpy(p, ZSTR_VAL(str), ZSTR_LEN(str));
            *ep = p;
            ++ep;
            p += ZSTR_LEN(str) + 1;
        }
        zend_string_release(str);
    }
    ZEND_HASH_FOREACH_END();

    assert((uint32_t )(p - env.envp) <= sizeenv);

    zend_hash_destroy(env_hash);
    FREE_HASHTABLE(env_hash);

    return env;
}
/* }}} */

/* {{{ _php_free_envp */
static void _php_free_envp(proc_co_env_t env)
{
    if (env.envarray)
    {
        efree(env.envarray);
    }
    if (env.envp)
    {
        efree(env.envp);
    }
}
/* }}} */

static void proc_co_rsrc_dtor(zend_resource *rsrc)
{
    proc_co_t *proc = (proc_co_t*) rsrc->ptr;
    int i;
    int wstatus = 0;

    /* Close all handles to avoid a deadlock */
    for (i = 0; i < proc->npipes; i++)
    {
        if (proc->pipes[i] != 0)
        {
            GC_DELREF(proc->pipes[i]);
            zend_list_close(proc->pipes[i]);
            proc->pipes[i] = 0;
        }
    }

    if (proc->running)
    {
        swoole_coroutine_waitpid(proc->child, &wstatus, 0);
    }
    if (proc->wstatus)
    {
        *proc->wstatus = wstatus;
    }

    _php_free_envp(proc->env);
    efree(proc->pipes);
    efree(proc->command);
    efree(proc);
}

void swoole_proc_open_init(int module_number)
{
	le_proc_open = zend_register_list_destructors_ex(proc_co_rsrc_dtor, NULL, le_proc_name, module_number);
}

/* {{{ proto bool proc_terminate(resource process [, int signal])
   kill a process opened by proc_open */
PHP_FUNCTION(swoole_proc_terminate)
{
	zval *zproc;
	proc_co_t *proc;
	zend_long sig_no = SIGTERM;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zproc)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(sig_no)
	ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((proc = (proc_co_t *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open)) == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(kill(proc->child, sig_no) == 0);
}
/* }}} */


PHP_FUNCTION(swoole_proc_close)
{
	zval *zproc;
	proc_co_t *proc;
	int wstatus;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_RESOURCE(zproc)
	ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((proc = (proc_co_t *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open)) == NULL)
    {
        RETURN_FALSE;
    }

    proc->wstatus = &wstatus;
    zend_list_close(Z_RES_P(zproc));
	RETURN_LONG(wstatus);
}

PHP_FUNCTION(swoole_proc_get_status)
{
	zval *zproc;
	proc_co_t *proc;
	int wstatus;
	pid_t wait_pid;
	int running = 1, signaled = 0, stopped = 0;
	int exitcode = -1, termsig = 0, stopsig = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_RESOURCE(zproc)
	ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((proc = (proc_co_t *) zend_fetch_resource(Z_RES_P(zproc), le_proc_name, le_proc_open)) == NULL)
    {
        RETURN_FALSE;
    }

	array_init(return_value);

	add_assoc_string(return_value, "command", proc->command);
	add_assoc_long(return_value, "pid", (zend_long) proc->child);

	errno = 0;
    wait_pid = swoole_coroutine_waitpid(proc->child, &wstatus, WNOHANG | WUNTRACED);

    if (wait_pid == proc->child)
    {
        if (WIFEXITED(wstatus))
        {
            running = 0;
            exitcode = WEXITSTATUS(wstatus);
        }
        if (WIFSIGNALED(wstatus))
        {
            running = 0;
            signaled = 1;

            termsig = WTERMSIG(wstatus);
        }
        if (WIFSTOPPED(wstatus))
        {
            stopped = 1;
            stopsig = WSTOPSIG(wstatus);
        }
    }
    else if (wait_pid == -1)
    {
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

#define DESC_PIPE		1
#define DESC_FILE		2
#define DESC_PARENT_MODE_WRITE	8

struct php_proc_open_descriptor_item {
	int index; 							/* desired fd number in child process */
	int parentend, childend;	        /* fds for pipes in parent/child */
	int mode;							/* mode for proc_open code */
	int mode_flags;						/* mode flags for opening fds */
};
/* }}} */

/* {{{ proto resource proc_open(string command, array descriptorspec, array &pipes [, string cwd [, array env [, array other_options]]])
   Run a process with more control over it's file descriptors */
PHP_FUNCTION(swoole_proc_open)
{
	char *command, *cwd=NULL;
	size_t command_len, cwd_len = 0;
	zval *descriptorspec;
	zval *pipes;
	zval *environment = NULL;
	zval *other_options = NULL;
	proc_co_env_t env;
	int ndesc = 0;
	int i;
	zval *descitem = NULL;
	zend_string *str_index;
	zend_ulong nindex;
	struct php_proc_open_descriptor_item *descriptors = NULL;
	int ndescriptors_array;

	pid_t child;
	proc_co_t *proc;

	ZEND_PARSE_PARAMETERS_START(3, 6)
		Z_PARAM_STRING(command, command_len)
		Z_PARAM_ARRAY(descriptorspec)
#if PHP_VERSION_ID >= 70400
		Z_PARAM_ZVAL(pipes)
#else
		Z_PARAM_ZVAL_DEREF(pipes)
#endif
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING_EX(cwd, cwd_len, 1, 0)
		Z_PARAM_ARRAY_EX(environment, 1, 0)
		Z_PARAM_ARRAY_EX(other_options, 1, 0)
	ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

	php_swoole_check_reactor();
    if (php_swoole_signal_isset_handler(SIGCHLD))
    {
        php_swoole_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_proc_open");
        RETURN_FALSE;
    }

    Coroutine::get_current_safe();
    swoole_coroutine_signal_init();

	command = estrdup(command);

	command_len = strlen(command);

    if (environment)
    {
        env = _php_array_to_envp(environment);
    }
    else
    {
        memset(&env, 0, sizeof(env));
    }

    ndescriptors_array = zend_hash_num_elements(Z_ARRVAL_P(descriptorspec));

    descriptors = (struct php_proc_open_descriptor_item *) safe_emalloc(sizeof(struct php_proc_open_descriptor_item),
            ndescriptors_array, 0);

    memset(descriptors, 0, sizeof(struct php_proc_open_descriptor_item) * ndescriptors_array);

    /* walk the descriptor spec and set up files/pipes */
    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(descriptorspec), nindex, str_index, descitem)
    {
        zval *ztype;

        if (str_index)
        {
            php_swoole_fatal_error(E_WARNING, "descriptor spec must be an integer indexed array");
            goto exit_fail;
        }

        descriptors[ndesc].index = (int) nindex;

        if (Z_TYPE_P(descitem) == IS_RESOURCE)
        {
            /* should be a stream - try and dup the descriptor */
            php_stream *stream;
            php_socket_t fd;

            php_stream_from_zval(stream, descitem);

            if (FAILURE == php_stream_cast(stream, PHP_STREAM_AS_FD, (void ** )&fd, REPORT_ERRORS))
            {
                goto exit_fail;
            }

            descriptors[ndesc].childend = dup(fd);
            if (descriptors[ndesc].childend < 0)
            {
                php_swoole_fatal_error(E_WARNING,
                        "unable to dup File-Handle for descriptor " ZEND_ULONG_FMT " - %s", nindex,
                        strerror(errno));
                goto exit_fail;
            }

            descriptors[ndesc].mode = DESC_FILE;

        }
        else if (Z_TYPE_P(descitem) != IS_ARRAY)
        {
            php_swoole_fatal_error(E_WARNING, "Descriptor item must be either an array or a File-Handle");
            goto exit_fail;
        }
        else
        {

            if ((ztype = zend_hash_index_find(Z_ARRVAL_P(descitem), 0)) != NULL)
            {
                convert_to_string_ex(ztype);
            }
            else
            {
                php_swoole_fatal_error(E_WARNING, "Missing handle qualifier in array");
                goto exit_fail;
            }

            if (strcmp(Z_STRVAL_P(ztype), "pipe") == 0)
            {
                int newpipe[2];
                zval *zmode;

                if ((zmode = zend_hash_index_find(Z_ARRVAL_P(descitem), 1)) != NULL)
                {
                    convert_to_string_ex(zmode);
                }
                else
                {
                    php_swoole_fatal_error(E_WARNING, "Missing mode parameter for 'pipe'");
                    goto exit_fail;
                }

                descriptors[ndesc].mode = DESC_PIPE;

                if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, newpipe))
                {
                    php_swoole_fatal_error(E_WARNING, "unable to create pipe %s", strerror(errno));
                    goto exit_fail;
                }

                if (strncmp(Z_STRVAL_P(zmode), "w", 1) != 0)
                {
                    descriptors[ndesc].parentend = newpipe[1];
                    descriptors[ndesc].childend = newpipe[0];
                    descriptors[ndesc].mode |= DESC_PARENT_MODE_WRITE;
                }
                else
                {
                    descriptors[ndesc].parentend = newpipe[0];
                    descriptors[ndesc].childend = newpipe[1];
                }
                descriptors[ndesc].mode_flags =
                        descriptors[ndesc].mode & DESC_PARENT_MODE_WRITE ? O_WRONLY : O_RDONLY;

            }
            else if (strcmp(Z_STRVAL_P(ztype), "file") == 0)
            {
                zval *zfile, *zmode;
                php_socket_t fd;
                php_stream *stream;

                descriptors[ndesc].mode = DESC_FILE;

                if ((zfile = zend_hash_index_find(Z_ARRVAL_P(descitem), 1)) != NULL)
                {
                    convert_to_string_ex(zfile);
                }
                else
                {
                    php_swoole_fatal_error(E_WARNING, "Missing file name parameter for 'file'");
                    goto exit_fail;
                }

                if ((zmode = zend_hash_index_find(Z_ARRVAL_P(descitem), 2)) != NULL)
                {
                    convert_to_string_ex(zmode);
                }
                else
                {
                    php_swoole_fatal_error(E_WARNING, "Missing mode parameter for 'file'");
                    goto exit_fail;
                }

                /* try a wrapper */
                stream = php_stream_open_wrapper(Z_STRVAL_P(zfile), Z_STRVAL_P(zmode), REPORT_ERRORS|STREAM_WILL_CAST, NULL);

                /* force into an fd */
                if (stream == NULL || FAILURE == php_stream_cast(stream, PHP_STREAM_CAST_RELEASE|PHP_STREAM_AS_FD, (void ** )&fd, REPORT_ERRORS))
                {
                    goto exit_fail;
                }

                descriptors[ndesc].childend = fd;
            }
            else if (strcmp(Z_STRVAL_P(ztype), "pty") == 0)
            {

                php_swoole_fatal_error(E_WARNING, "pty pseudo terminal not supported on this system");
                goto exit_fail;
            }
            else
            {
                php_swoole_fatal_error(E_WARNING, "%s is not a valid descriptor spec/mode", Z_STRVAL_P(ztype));
                goto exit_fail;
            }
        }
        ndesc++;
    }
    ZEND_HASH_FOREACH_END();

    /* the unix way */
    child = swoole_fork(SW_FORK_EXEC);

    if (child == 0)
    {
        /* this is the child process */

        /* close those descriptors that we just opened for the parent stuff,
         * dup new descriptors into required descriptors and close the original
         * cruft */
        for (i = 0; i < ndesc; i++)
        {
            switch (descriptors[i].mode & ~DESC_PARENT_MODE_WRITE)
            {
            case DESC_PIPE:
                close(descriptors[i].parentend);
                break;
            }
            if (dup2(descriptors[i].childend, descriptors[i].index) < 0)
            {
                perror("dup2");
            }
            if (descriptors[i].childend != descriptors[i].index)
            {
                close(descriptors[i].childend);
            }
        }

        if (cwd)
        {
            php_ignore_value(chdir(cwd));
        }

        if (env.envarray)
        {
            execle("/bin/sh", "sh", "-c", command, NULL, env.envarray);
        }
        else
        {
            execl("/bin/sh", "sh", "-c", command, NULL);
        }
        _exit(127);

    }
    else if (child < 0)
    {
        /* failed to fork() */

        /* clean up all the descriptors */
        for (i = 0; i < ndesc; i++)
        {
            close(descriptors[i].childend);
            if (descriptors[i].parentend)
            {
                close(descriptors[i].parentend);
            }
        }

        php_swoole_fatal_error(E_WARNING, "fork failed - %s", strerror(errno));

        goto exit_fail;

    }

    /* we forked/spawned and this is the parent */

    proc = (proc_co_t*) emalloc(sizeof(proc_co_t));
    proc->wstatus = nullptr;
    proc->command = command;
    proc->pipes = (zend_resource **) emalloc(sizeof(zend_resource *) * ndesc);
    proc->npipes = ndesc;
    proc->child = child;
    proc->env = env;
    proc->running = true;

	zval_ptr_dtor(pipes);
	array_init(pipes);


	/* clean up all the child ends and then open streams on the parent
	 * ends, where appropriate */
    for (i = 0; i < ndesc; i++)
    {
        php_stream *stream = NULL;

        close(descriptors[i].childend);

        switch (descriptors[i].mode & ~DESC_PARENT_MODE_WRITE)
        {
        case DESC_PIPE:
            stream = php_swoole_create_stream_from_socket(descriptors[i].parentend, AF_UNIX, SOCK_STREAM, 0 STREAMS_CC);
            /* mark the descriptor close-on-exec, so that it won't be inherited by potential other children */
            fcntl(descriptors[i].parentend, F_SETFD, FD_CLOEXEC);
            if (stream)
            {
                zval retfp;

                /* nasty hack; don't copy it */
                stream->flags |= PHP_STREAM_FLAG_NO_SEEK;

                php_stream_to_zval(stream, &retfp);
                (void) add_index_zval(pipes, descriptors[i].index, &retfp);

                proc->pipes[i] = Z_RES(retfp);
                Z_ADDREF(retfp);
            }
            break;
        default:
            proc->pipes[i] = NULL;
        }
    }

	efree(descriptors);
	ZVAL_RES(return_value, zend_register_resource(proc, le_proc_open));
	return;

    exit_fail:
    efree(descriptors);
    _php_free_envp(env);
    efree(command);

	RETURN_FALSE;

}
/* }}} */
