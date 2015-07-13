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
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"

static PHP_METHOD(swoole_process, __construct);
static PHP_METHOD(swoole_process, __destruct);
static PHP_METHOD(swoole_process, useQueue);
static PHP_METHOD(swoole_process, pop);
static PHP_METHOD(swoole_process, push);
static PHP_METHOD(swoole_process, kill);
static PHP_METHOD(swoole_process, signal);
static PHP_METHOD(swoole_process, wait);
static PHP_METHOD(swoole_process, daemon);
#ifdef HAVE_CPU_AFFINITY
static PHP_METHOD(swoole_process, setaffinity);
#endif
static PHP_METHOD(swoole_process, start);
static PHP_METHOD(swoole_process, write);
static PHP_METHOD(swoole_process, read);
static PHP_METHOD(swoole_process, close);
static PHP_METHOD(swoole_process, exit);
static PHP_METHOD(swoole_process, exec);

static void php_swoole_onSignal(int signo);

static uint32_t php_swoole_worker_round_id = 1;
static zval *signal_callback[SW_SIGNO_MAX];
static zend_class_entry swoole_process_ce;
zend_class_entry *swoole_process_class_entry_ptr;

static const zend_function_entry swoole_process_methods[] =
{
    PHP_ME(swoole_process, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_process, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_process, wait, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, signal, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, kill, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, daemon, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#ifdef HAVE_CPU_AFFINITY
    PHP_ME(swoole_process, setaffinity, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#endif
    PHP_ME(swoole_process, useQueue, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, start, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, write, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, read, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, push, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, pop, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exit, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exec, NULL, ZEND_ACC_PUBLIC)
    PHP_FALIAS(name, swoole_set_process_name, NULL)
    PHP_FE_END
};

void swoole_process_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_process_ce, "swoole_process", swoole_process_methods);
    swoole_process_class_entry_ptr = zend_register_internal_class(&swoole_process_ce TSRMLS_CC);

    /**
     * 31 signal constants
     */
   zval *zpcntl;
   if (sw_zend_hash_find(&module_registry, ZEND_STRS("pcntl"), (void **) &zpcntl) == FAILURE)
   {
       REGISTER_LONG_CONSTANT("SIGHUP", (long) SIGHUP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGINT", (long) SIGINT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGQUIT", (long) SIGQUIT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGILL", (long) SIGILL, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTRAP", (long) SIGTRAP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGABRT", (long) SIGABRT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGBUS", (long) SIGBUS, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGFPE", (long) SIGFPE, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGKILL", (long) SIGKILL, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGUSR1", (long) SIGUSR1, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGSEGV", (long) SIGSEGV, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGUSR2", (long) SIGUSR2, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGPIPE", (long) SIGPIPE, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGALRM", (long) SIGALRM, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTERM", (long) SIGTERM, CONST_CS | CONST_PERSISTENT);
#ifdef SIGSTKFLT
       REGISTER_LONG_CONSTANT("SIGSTKFLT", (long) SIGSTKFLT, CONST_CS | CONST_PERSISTENT);
#endif
       REGISTER_LONG_CONSTANT("SIGCHLD", (long) SIGCHLD, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGCONT", (long) SIGCONT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGSTOP", (long) SIGSTOP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTSTP", (long) SIGTSTP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTTIN", (long) SIGTTIN, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTTOU", (long) SIGTTOU, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGURG", (long) SIGURG, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGXCPU", (long) SIGXCPU, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGXFSZ", (long) SIGXFSZ, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGVTALRM", (long) SIGVTALRM, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGPROF", (long) SIGPROF, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGWINCH", (long) SIGWINCH, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGIO", (long) SIGIO, CONST_CS | CONST_PERSISTENT);
#ifdef SIGPWR
       REGISTER_LONG_CONSTANT("SIGPWR", (long) SIGPWR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef SIGSYS
       REGISTER_LONG_CONSTANT("SIGSYS", (long) SIGSYS, CONST_CS | CONST_PERSISTENT);
#endif
   }
}

static PHP_METHOD(swoole_process, __construct)
{
    zend_bool redirect_stdin_and_stdout = 0;
    zend_bool create_pipe = 1;
    zval *callback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|bb", &callback, &redirect_stdin_and_stdout, &create_pipe) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    swWorker *process = emalloc(sizeof(swWorker));
    bzero(process, sizeof(swWorker));

    process->id = php_swoole_worker_round_id++;

    if (php_swoole_worker_round_id == 0)
    {
        php_swoole_worker_round_id = 1;
    }

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
        process->pipe_object = _pipe;
        process->pipe_master = _pipe->getFd(_pipe, SW_PIPE_MASTER);
        process->pipe_worker = _pipe->getFd(_pipe, SW_PIPE_WORKER);
        process->pipe = process->pipe_master;

        zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("pipe"), process->pipe_master TSRMLS_CC);
    }

    swoole_set_object(getThis(), process);
    zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("callback"), callback TSRMLS_CC);
}

static PHP_METHOD(swoole_process, __destruct)
{
    swWorker *process = swoole_get_object(getThis());
    swPipe *_pipe = process->pipe_object;
    if (_pipe)
    {
        _pipe->close(_pipe);
        efree(_pipe);
    }
    if (process->queue)
    {
        process->queue->free(process->queue);
        efree(process->queue);
    }
    efree(process);
}

static PHP_METHOD(swoole_process, wait)
{
    int status;
    zend_bool blocking = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &blocking) == FAILURE)
    {
        RETURN_FALSE;
    }

    int options = 0;
    if (!blocking)
    {
        options |= WNOHANG;
    }

    pid_t pid = swWaitpid(-1, &status, options);
    if (pid > 0)
    {
        array_init(return_value);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "pid", pid);
        add_assoc_long(return_value, "signal", WTERMSIG(status));
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, useQueue)
{
    long msgkey = -1;
    long mode = 2;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &msgkey, &mode) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());

    if (msgkey < 0)
    {
#if PHP_MAJOR_VERSION == 7
         msgkey = ftok(execute_data->func->op_array.filename->val, 0);
#else
       msgkey = ftok(EG(active_op_array)->filename, 0);
#endif
    }

    swQueue *queue = emalloc(sizeof(swQueue));
    if (swQueueMsg_create(queue, 1, msgkey, 0) < 0)
    {
        RETURN_FALSE;
    }
    process->queue = queue;
    process->ipc_mode = mode;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, kill)
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

static PHP_METHOD(swoole_process, signal)
{
    zval *callback = NULL;
    long signo = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &signo, &callback) == FAILURE)
    {
        return;
    }

    if (!SWOOLE_G(cli))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "cannot use swoole_process::signal here.");
        RETURN_FALSE;
    }

    if (SwooleGS->start)
    {
        if (signo == SIGTERM || signo == SIGALRM)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot use swoole_process::signal in swoole_server.");
            RETURN_FALSE;
        }
    }

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no callback.");
        RETURN_FALSE;
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    sw_zval_add_ref(&callback);
    signal_callback[signo] = callback;

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4
    SwooleG.use_signalfd = 1;
#else
    SwooleG.use_signalfd = 0;
#endif

    php_swoole_check_reactor();

    /**
     * for swSignalfd_setup
     */
    SwooleG.main_reactor->check_signalfd = 1;
    swSignal_add(signo, php_swoole_onSignal);

    RETURN_TRUE;
}

/**
 * safe signal
 */
static void php_swoole_onSignal(int signo)
{
    zval *retval;
    zval **args[1];
    zval *callback = signal_callback[signo];

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zsigno;
    SW_MAKE_STD_ZVAL(zsigno);
    ZVAL_LONG(zsigno, signo);

    args[0] = &zsigno;

    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "user_signal handler error");
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zsigno);
}

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC)
{
    process->pipe = process->pipe_worker;
    process->pid = getpid();

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

    /**
     * Close EventLoop
     */
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->free(SwooleG.main_reactor);
        SwooleG.main_reactor = NULL;
        bzero(&SwooleWG, sizeof(SwooleWG));
        SwooleG.pid = process->pid;
    }

    if (SwooleG.timer.fd)
    {
        SwooleG.timer.free(&SwooleG.timer);
        bzero(&SwooleG.timer, sizeof(SwooleG.timer));
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_clear();
    }
#endif

    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pid"), process->pid TSRMLS_CC);
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pipe"), process->pipe_worker TSRMLS_CC);

    zval *zcallback = sw_zend_read_property(swoole_process_class_entry_ptr, object, ZEND_STRL("callback"), 0 TSRMLS_CC);
    zval **args[1];

    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "no callback.");
        return SW_ERR;
    }

    zval *retval = NULL;
    args[0] = &object;
    sw_zval_add_ref(&object);

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "callback function error");
        return SW_ERR;
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (SwooleG.main_reactor)
    {
        php_swoole_event_wait();
    }

    zend_bailout();
    return SW_OK;
}

static PHP_METHOD(swoole_process, start)
{
    swWorker *process = swoole_get_object(getThis());

    if (process->pid > 0 && kill(process->pid, 0) == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "process is already started.");
        RETURN_FALSE;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "fork() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    else if (pid > 0)
    {
        process->pid = pid;
        process->child_process = 0;
        zend_update_property_long(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("pid"), process->pid TSRMLS_CC);
        RETURN_LONG(pid);
    }
    else
    {
        process->child_process = 1;
        SW_CHECK_RETURN(php_swoole_process_start(process, getThis() TSRMLS_CC));
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, read)
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

    swWorker *process = swoole_get_object(getThis());

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
    SW_ZVAL_STRINGL(return_value, buf, ret, 0);
}

static PHP_METHOD(swoole_process, write)
{
    char *data = NULL;
    zend_size_t data_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (data_len < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "send data empty.");
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not pipe, can not use read()");
        RETURN_FALSE;
    }

    int ret;

    //async write
    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, process->pipe, data, (size_t) data_len);
    }
    else
    {
        ret = swSocket_write_blocking(process->pipe, data, data_len);
    }

    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "write() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    ZVAL_LONG(return_value, ret);
}

static PHP_METHOD(swoole_process, push)
{
    char *data;
    zend_size_t length;

    struct
    {
        long type;
        char data[65536];
    } message;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (length <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data empty.");
        RETURN_FALSE;
    }
    else if (length >= sizeof(message.data))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data too big.");
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());

    if (!process->queue)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not msgqueue, can not use push()");
        RETURN_FALSE;
    }

    message.type = process->id;
    memcpy(message.data, data, length);

    if (process->queue->in(process->queue, (swQueue_data *)&message, length) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "msgsnd() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, pop)
{
    long maxsize = SW_MSGMAX;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &maxsize) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (maxsize <= 0 || maxsize > SW_MSGMAX)
    {
        maxsize = SW_MSGMAX;
    }
    swWorker *process = swoole_get_object(getThis());
    if (!process->queue)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not msgqueue, can not use push()");
        RETURN_FALSE;
    }

    struct
    {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (process->ipc_mode == 2)
    {
        message.type = 0;
    }
    else
    {
        message.type = process->id;
    }

    int n = process->queue->out(process->queue, (swQueue_data *) &message, maxsize);
    if (n < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "msgrcv() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(message.data, n, 1);
}

static PHP_METHOD(swoole_process, exec)
{
    char *execfile = NULL;
    zend_size_t execfile_len = 0;
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

    int exec_argc = php_swoole_array_length(args);
    char **exec_args = emalloc(sizeof(char*) * exec_argc + 1);

    zval *value = NULL;
    exec_args[0] = strdup(execfile);
    int i = 1;
//    Bucket *_p;
//    _p = SW_Z_ARRVAL_P(args)->pListHead;
//    while(_p != NULL)
//    {
//        value = (zval **) _p->pData;
//        convert_to_string(*value);
//
//        sw_zval_add_ref(value);
//        exec_args[i] = Z_STRVAL_PP(value);
//
//        _p = _p->pListNext;
//        i++;
//    }
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(args), value)
        convert_to_string(value);

        sw_zval_add_ref(&value);
        exec_args[i] = Z_STRVAL_P(value);
        i++;
    SW_HASHTABLE_FOREACH_END();
    exec_args[i] = NULL;

    if (execv(execfile, exec_args) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "execv(%s) failed. Error: %s[%d]", execfile, strerror(errno), errno);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_process, daemon)
{
    zend_bool nochdir = 0;
    zend_bool noclose = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|bb", &nochdir, &noclose) == FAILURE)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(daemon(nochdir, noclose) == 0);
}

#ifdef HAVE_CPU_AFFINITY
static PHP_METHOD(swoole_process, setaffinity)
{
    zval *array;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &array) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (Z_ARRVAL_P(array)->nNumOfElements == 0)
    {
        RETURN_FALSE;
    }
    if (Z_ARRVAL_P(array)->nNumOfElements > SW_CPU_NUM)
    {
        swoole_php_fatal_error(E_WARNING, "More than the number of CPU");
        RETURN_FALSE;
    }

    zval *value = NULL;
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(array), value)
        convert_to_long(value);
        if (Z_LVAL_P(value) >= SW_CPU_NUM)
        {
            swoole_php_fatal_error(E_WARNING, "invalid cpu id [%d]", (int) Z_LVAL_P(value));
            RETURN_FALSE;
        }
        CPU_SET(Z_LVAL_P(value), &cpu_set);
    SW_HASHTABLE_FOREACH_END();

    if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
    {
        swoole_php_sys_error(E_WARNING, "sched_setaffinity() failed.");
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
#endif

static PHP_METHOD(swoole_process, exit)
{
    long ret_code = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &ret_code) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());

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

static PHP_METHOD(swoole_process, close)
{
    swWorker *process = swoole_get_object(getThis());

    if (process->pipe == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "have not pipe, can not use close()");
        RETURN_FALSE;
    }

    int ret = process->pipe_object->close(process->pipe_object);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "close() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    else
    {
        process->pipe = 0;
        efree(process->pipe_object);
        process->pipe_object = NULL;
    }
    ZVAL_LONG(return_value, ret);
}
