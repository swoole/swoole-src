/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"

#define SWOOLE_GET_WORKER(zobject, process) zval **zprocess;\
	if (zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_process"), (void **) &zprocess) == FAILURE){ \
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have process");\
	RETURN_FALSE;}\
	ZEND_FETCH_RESOURCE(process, swWorker *, zprocess, -1, SW_RES_PROCESS_NAME, le_swoole_process);

void swoole_destory_process(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	swWorker *process = (swWorker *) rsrc->ptr;
	swPipe *_pipe = process->ptr;
	if (_pipe)
	{
		_pipe->close(_pipe);
		efree(_pipe);
	}
	efree(process);
}

PHP_METHOD(swoole_process, __construct)
{

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	zend_bool redirect_stdin_and_stdout = 0;
	zend_bool create_pipe = 1;
	zval *callback;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|bb", &callback, &redirect_stdin_and_stdout, &create_pipe) == FAILURE)
	{
		RETURN_FALSE;
	}

	char *func_name = NULL;
	if (!zend_is_callable(callback, 0, &func_name TSRMLS_CC))
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "function '%s' is not callable", func_name);
		efree(func_name);
		RETURN_FALSE;
	}
	efree(func_name);

	swWorker *process = emalloc(sizeof(swWorker));
	bzero(process, sizeof(swWorker));

	if (redirect_stdin_and_stdout)
	{
		process->redirect_stdin = 1;
		process->redirect_stdout = 1;
		create_pipe = 1;
	}

	if (create_pipe)
	{
		swPipe *_pipe = emalloc(sizeof(swWorker));
		if (swPipeUnsock_create(_pipe, 1, SOCK_STREAM) < 0)
		{
			RETURN_FALSE;
		}
		process->ptr = _pipe;
		process->pipe_master = _pipe->getFd(_pipe, 1);
		process->pipe_worker = _pipe->getFd(_pipe, 0);
	}

	zval *zres;
	MAKE_STD_ZVAL(zres);
	ZEND_REGISTER_RESOURCE(zres, process, le_swoole_process);

	zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("callback"), callback TSRMLS_CC);
	zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("_process"), zres TSRMLS_CC);
	zval_ptr_dtor(&zres);
}

PHP_METHOD(swoole_process, wait)
{
	int status;
	pid_t pid = wait(&status);
	if (pid > 0)
	{
		array_init(return_value);
		add_assoc_long(return_value, "code", WEXITSTATUS(status));
		add_assoc_long(return_value, "pid", pid);
	}
	else
	{
		RETURN_FALSE;
	}
}

PHP_METHOD(swoole_process, kill)
{
	long pid;
	long sig = SIGTERM;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &pid, &sig) == FAILURE)
	{
		RETURN_FALSE;
	}

	int ret = kill((int) pid, (int) sig);
	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "kill(%d, %d) failed. Error: %s[%d]", (int) pid, (int) sig, strerror(errno), errno);
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

PHP_METHOD(swoole_process, start)
{
	swWorker *process;
	SWOOLE_GET_WORKER(getThis(), process);
	zval *zpipe;

	pid_t pid = fork();

	if (pid < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "fork() failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	else if(pid > 0)
	{
		process->pid = pid;
		process->pipe = process->pipe_master;

		close(process->pipe_worker);

		MAKE_STD_ZVAL(zpipe);
		ZVAL_LONG(zpipe, process->pipe);

		zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("pipe"), zpipe TSRMLS_CC);
		zval_ptr_dtor(&zpipe);

		RETURN_LONG(pid);
	}
	else
	{
		process->pipe = process->pipe_worker;
		process->pid = getpid();

		close(process->pipe_master);

		if (process->redirect_stdin)
		{
			if (dup2(process->pipe, STDIN_FILENO) < 0)
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "dup2() failed. Error: %s[%d]", strerror(errno), errno);
			}
		}

		if (process->redirect_stdout)
		{
			if (dup2(process->pipe, STDOUT_FILENO) < 0)
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "dup2() failed. Error: %s[%d]", strerror(errno), errno);
			}
		}

		zval *zpid;
		MAKE_STD_ZVAL(zpid);
		ZVAL_LONG(zpid, process->pid);

		zend_update_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("pid"), zpid TSRMLS_CC);
		zval_ptr_dtor(&zpid);

		MAKE_STD_ZVAL(zpipe);
		ZVAL_LONG(zpipe, process->pipe);

		zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("pipe"), zpipe TSRMLS_CC);
		zval_ptr_dtor(&zpipe);

		zval *zcallback = zend_read_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("callback"), 0 TSRMLS_CC);
		zval **args[1];

		if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "no callback.");
			RETURN_FALSE;
		}

		zval *retval;
		args[0] = &getThis();

		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "callback function error");
			RETURN_FALSE;
		}

		if (retval)
		{
			zval_ptr_dtor(&retval);
		}

		zend_bailout();
	}
	RETURN_TRUE;
}

PHP_METHOD(swoole_process, read)
{
	long buf_size = 8192;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &buf_size) == FAILURE)
	{
		RETURN_FALSE;
	}

	if (buf_size > 65536)
	{
		buf_size = 65536;
	}

	swWorker *process;
	SWOOLE_GET_WORKER(getThis(), process);

	if (process->pipe == 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not pipe, can not use write()");
		RETURN_FALSE;
	}

	char *buf = emalloc(buf_size);
	int ret;

	do
	{
		ret = read(process->pipe, buf, buf_size - 1);
	}
	while(errno < 0 && errno == EINTR);

	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	buf[ret] = 0;
	ZVAL_STRINGL(return_value, buf, ret, 0);
}

PHP_METHOD(swoole_process, write)
{
	char *data = NULL;
	int data_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
	{
		RETURN_FALSE;
	}

	if (data_len < 1)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "send data empty.");
		RETURN_FALSE;
	}

	swWorker *process;
	SWOOLE_GET_WORKER(getThis(), process);

	if (process->pipe == 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not pipe, can not use read()");
		RETURN_FALSE;
	}

	int ret;
	do
	{
		ret = write(process->pipe, data, (size_t) data_len);
	}
	while(errno < 0 && errno == EINTR);

	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	ZVAL_LONG(return_value, ret);
}

PHP_METHOD(swoole_process, exec)
{
	char *execfile = NULL;
	int execfile_len = 0;
	zval *args;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &execfile, &execfile_len, &args) == FAILURE)
	{
		RETURN_FALSE;
	}

	if (execfile_len < 1)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "execfile name empty.");
		RETURN_FALSE;
	}

	swWorker *process;
	SWOOLE_GET_WORKER(getThis(), process);

	if (process->pipe == 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not pipe, can not use exec()");
		RETURN_FALSE;
	}

	swBreakPoint();

	int exec_argc = php_swoole_array_length(args);
	char **exec_args = emalloc(sizeof(char*) * exec_argc + 1);

	zval **value;
	Bucket *_p;
	_p = Z_ARRVAL_P(args)->pListHead;
	exec_args[0] = strdup(execfile);

	int i = 1;
	while(_p != NULL)
	{
		value = (zval **) _p->pData;
		convert_to_string(*value);

		zval_add_ref(value);
		exec_args[i] = Z_STRVAL_PP(value);

		_p = _p->pListNext;
		i++;
	}
	exec_args[i] = NULL;

	if (execv(execfile, exec_args) < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "execv() failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	else
	{
		RETURN_TRUE;
	}
}

PHP_METHOD(swoole_process, exit)
{
	long ret_code = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &ret_code) == FAILURE)
	{
		RETURN_FALSE;
	}

	swWorker *process;
	SWOOLE_GET_WORKER(getThis(), process);

	if (getpid() != process->pid)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "not current process.");
		RETURN_FALSE;
	}

	if (ret_code < 0 || ret_code > 255)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "exit ret_code range is [>0 and <255] ");
		ret_code = 1;
	}

	close(process->pipe);

	if (SwooleG.main_reactor != NULL)
	{
		SwooleG.running = 0;
	}

	if (ret_code == 0)
	{
		zend_bailout();
	}
	else
	{
		exit(ret_code);
	}
}
