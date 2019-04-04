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

#include "php_swoole_cxx.h"
#include "php_streams.h"
#include "php_network.h"

#include "swoole_coroutine.h"

using namespace swoole;

namespace php
{
struct process
{
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
    zend_object *zsocket;
    int pipe_type;
};

enum process_pipe_type
{
    PIPE_TYPE_STREAM = 1,
    PIPE_TYPE_DGRAM = 2,
};
}

static PHP_METHOD(swoole_process, __construct);
static PHP_METHOD(swoole_process, __destruct);
static PHP_METHOD(swoole_process, useQueue);
static PHP_METHOD(swoole_process, statQueue);
static PHP_METHOD(swoole_process, freeQueue);
static PHP_METHOD(swoole_process, pop);
static PHP_METHOD(swoole_process, push);
static PHP_METHOD(swoole_process, kill);
static PHP_METHOD(swoole_process, signal);
static PHP_METHOD(swoole_process, alarm);
static PHP_METHOD(swoole_process, wait);
static PHP_METHOD(swoole_process, daemon);
#ifdef HAVE_CPU_AFFINITY
static PHP_METHOD(swoole_process, setaffinity);
#endif
static PHP_METHOD(swoole_process, setTimeout);
static PHP_METHOD(swoole_process, setBlocking);
static PHP_METHOD(swoole_process, start);
static PHP_METHOD(swoole_process, write);
static PHP_METHOD(swoole_process, read);
static PHP_METHOD(swoole_process, close);
static PHP_METHOD(swoole_process, exit);
static PHP_METHOD(swoole_process, exec);
static PHP_METHOD(swoole_process, exportSocket);

static void php_swoole_onSignal(int signo);
static void free_signal_callback(void* data);

static uint32_t php_swoole_worker_round_id = 0;
static zval *signal_callback[SW_SIGNO_MAX];
zend_class_entry *swoole_process_ce;
static zend_object_handlers swoole_process_handlers;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_construct, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
    ZEND_ARG_INFO(0, redirect_stdin_and_stdout)
    ZEND_ARG_INFO(0, pipe_type)
    ZEND_ARG_INFO(0, enable_coroutine)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, blocking)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_signal, 0, 0, 2)
    ZEND_ARG_INFO(0, signal_no)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_alarm, 0, 0, 1)
    ZEND_ARG_INFO(0, usec)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_kill, 0, 0, 1)
    ZEND_ARG_INFO(0, pid)
    ZEND_ARG_INFO(0, signal_no)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_daemon, 0, 0, 0)
    ZEND_ARG_INFO(0, nochdir)
    ZEND_ARG_INFO(0, noclose)
ZEND_END_ARG_INFO()

#ifdef HAVE_CPU_AFFINITY
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setaffinity, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cpu_settings, 0)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setTimeout, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setBlocking, 0, 0, 1)
    ZEND_ARG_INFO(0, blocking)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_useQueue, 0, 0, 0)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, capacity)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_read, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exit, 0, 0, 0)
    ZEND_ARG_INFO(0, exit_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exec, 0, 0, 2)
    ZEND_ARG_INFO(0, exec_file)
    ZEND_ARG_INFO(0, args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_name, 0, 0, 1)
    ZEND_ARG_INFO(0, process_name)
ZEND_END_ARG_INFO()

#define MSGQUEUE_NOWAIT    (1 << 8)

static const zend_function_entry swoole_process_methods[] =
{
    PHP_ME(swoole_process, __construct, arginfo_swoole_process_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, __destruct, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, wait, arginfo_swoole_process_wait, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, signal, arginfo_swoole_process_signal, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, alarm, arginfo_swoole_process_alarm, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, kill, arginfo_swoole_process_kill, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, daemon, arginfo_swoole_process_daemon, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#ifdef HAVE_CPU_AFFINITY
    PHP_ME(swoole_process, setaffinity, arginfo_swoole_process_setaffinity, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#endif
    PHP_ME(swoole_process, setTimeout, arginfo_swoole_process_setTimeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, setBlocking, arginfo_swoole_process_setBlocking, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, useQueue, arginfo_swoole_process_useQueue, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, statQueue, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, freeQueue, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, start, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, write, arginfo_swoole_process_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, close, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, read, arginfo_swoole_process_read, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, push, arginfo_swoole_process_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, pop, arginfo_swoole_process_pop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exit, arginfo_swoole_process_exit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exec, arginfo_swoole_process_exec, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exportSocket, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_FALIAS(name, swoole_set_process_name, arginfo_swoole_process_name)
    PHP_FE_END
};

void swoole_process_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_process, "Swoole\\Process", "swoole_process", NULL, swoole_process_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_process, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_process, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process, zend_class_unset_property_deny);

    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("IPC_NOWAIT"), MSGQUEUE_NOWAIT);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_MASTER"), SW_PIPE_CLOSE_MASTER);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_WORKER"), SW_PIPE_CLOSE_WORKER);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_READ"), SW_PIPE_CLOSE_READ);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_WRITE"), SW_PIPE_CLOSE_WRITE);
    bzero(signal_callback, sizeof(signal_callback));

    zend_declare_property_null(swoole_process_ce, ZEND_STRL("pipe"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("callback"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("msgQueueId"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("msgQueueKey"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("pid"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("id"), ZEND_ACC_PUBLIC);

    /**
     * 31 signal constants
     */
    if (!zend_hash_str_find(&module_registry, ZEND_STRL("pcntl")))
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
        REGISTER_LONG_CONSTANT("SIG_IGN", (long) SIG_IGN, CONST_CS | CONST_PERSISTENT);
    }
}

static PHP_METHOD(swoole_process, __construct)
{
    zend_bool redirect_stdin_and_stdout = 0;
    zend_long pipe_type = 2;
    zend_bool enable_coroutine = SW_FALSE;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process only can be used in PHP CLI mode");
        RETURN_FALSE;
    }

    if (SwooleG.serv && SwooleG.serv->gs->start == 1 && swIsMaster())
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process can't be used in master process");
        RETURN_FALSE;
    }

    if (SwooleAIO.init)
    {
        swoole_php_fatal_error(E_ERROR, "unable to create process with async-io threads");
        RETURN_FALSE;
    }

    php::process *proc = (php::process *) emalloc(sizeof(php::process));
    bzero(proc, sizeof(php::process));

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 4)
        Z_PARAM_FUNC(proc->fci, proc->fci_cache);
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(redirect_stdin_and_stdout)
        Z_PARAM_LONG(pipe_type)
        Z_PARAM_BOOL(enable_coroutine)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swWorker *process = (swWorker *) emalloc(sizeof(swWorker));
    bzero(process, sizeof(swWorker));

    int base = 1;
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        base = SwooleG.serv->worker_num + SwooleG.serv->task_worker_num + SwooleG.serv->user_worker_num;
    }
    if (php_swoole_worker_round_id == 0)
    {
        php_swoole_worker_round_id = base;
    }
    process->id = php_swoole_worker_round_id++;

    if (redirect_stdin_and_stdout)
    {
        process->redirect_stdin = 1;
        process->redirect_stdout = 1;
        process->redirect_stderr = 1;
        /**
         * Forced to use stream pipe
         */
        pipe_type = 1;
    }

    if (pipe_type > 0)
    {
        swPipe *_pipe = (swPipe *) emalloc(sizeof(swPipe));
        int socket_type = pipe_type == php::PIPE_TYPE_STREAM ? SOCK_STREAM : SOCK_DGRAM;
        if (swPipeUnsock_create(_pipe, 1, socket_type) < 0)
        {
            RETURN_FALSE;
        }

        process->pipe_object = _pipe;
        process->pipe_master = _pipe->getFd(_pipe, SW_PIPE_MASTER);
        process->pipe_worker = _pipe->getFd(_pipe, SW_PIPE_WORKER);
        process->pipe = process->pipe_master;

        zend_update_property_long(swoole_process_ce, getThis(), ZEND_STRL("pipe"), process->pipe_master);
    }

    proc->pipe_type = pipe_type;

    process->enable_coroutine = enable_coroutine ? 1 : 0;
    process->ptr2 = proc;

    sw_fci_cache_persist(&proc->fci_cache);
    swoole_set_object(getThis(), process);
}

static PHP_METHOD(swoole_process, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    swoole_set_object(getThis(), NULL);
    swPipe *_pipe = process->pipe_object;
    if (_pipe)
    {
        _pipe->close(_pipe);
        efree(_pipe);
    }
    if (process->queue)
    {
        efree(process->queue);
    }
    php::process *proc = (php::process *) process->ptr2;
    if (proc)
    {
        sw_fci_cache_discard(&proc->fci_cache);
        if (proc->zsocket)
        {
            OBJ_RELEASE(proc->zsocket);
        }
        efree(proc);
        efree(process);
    }
}

static PHP_METHOD(swoole_process, wait)
{
    int status;
    zend_bool blocking = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &blocking) == FAILURE)
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
        add_assoc_long(return_value, "pid", pid);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, useQueue)
{
    long msgkey = 0;
    long mode = 2;
    long capacity = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lll", &msgkey, &mode, &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());

    if (msgkey <= 0)
    {
        msgkey = ftok(zend_get_executed_filename(), 1);
    }

    swMsgQueue *queue = (swMsgQueue *) emalloc(sizeof(swMsgQueue));
    if (swMsgQueue_create(queue, 1, msgkey, 0) < 0)
    {
        RETURN_FALSE;
    }
    if (mode & MSGQUEUE_NOWAIT)
    {
        swMsgQueue_set_blocking(queue, 0);
        mode = mode & (~MSGQUEUE_NOWAIT);
    }
    if (capacity > 0)
    {
        swMsgQueue_set_capacity(queue, capacity);
    }
    process->queue = queue;
    process->ipc_mode = mode;
    zend_update_property_long(swoole_process_ce, getThis(), ZEND_STRL("msgQueueId"), queue->msg_id);
    zend_update_property_long(swoole_process_ce, getThis(), ZEND_STRL("msgQueueKey"), msgkey);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, statQueue)
{
    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (!process->queue)
    {
        swoole_php_fatal_error(E_WARNING, "no queue, can't get stats of the queue");
        RETURN_FALSE;
    }

    int queue_num = -1;
    int queue_bytes = -1;
    if (swMsgQueue_stat(process->queue, &queue_num, &queue_bytes) == 0)
    {
        array_init(return_value);
        add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), queue_num);
        add_assoc_long_ex(return_value, ZEND_STRL("queue_bytes"), queue_bytes);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, freeQueue)
{
    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->queue && swMsgQueue_free(process->queue) == SW_OK)
    {
        efree(process->queue);
        process->queue = NULL;
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, kill)
{
    zend_long pid;
    zend_long sig = SIGTERM;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|l", &pid, &sig) == FAILURE)
    {
        RETURN_FALSE;
    }

    int ret = swKill((int) pid, (int) sig);
    if (ret < 0)
    {
        if (!(sig == 0 && errno == ESRCH))
        {
            swoole_php_sys_error(E_WARNING, "swKill(%d, %d) failed", (int) pid, (int) sig);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, signal)
{
    zval *callback = NULL;
    long signo = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz", &signo, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "cannot use swoole_process::signal here");
        RETURN_FALSE;
    }

    if (signo < 0 || signo >= SW_SIGNO_MAX)
    {
        swoole_php_fatal_error(E_WARNING, "invalid signal number [%ld]", signo);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    swSignalHandler handler = swSignal_get_handler(signo);

    if (handler && handler != php_swoole_onSignal)
    {
        swoole_php_fatal_error(E_WARNING, "This signal [%ld] processor has been registered by the system", signo);
        RETURN_FALSE
    }

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        callback = signal_callback[signo];
        if (callback)
        {
            swSignal_add(signo, NULL);
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_signal_callback, callback);
            signal_callback[signo] = NULL;
            SwooleG.main_reactor->signal_listener_num--;
            RETURN_TRUE;
        }
        else
        {
            swoole_php_error(E_WARNING, "no callback");
            RETURN_FALSE;
        }
    }
    else if (Z_TYPE_P(callback) == IS_LONG && Z_LVAL_P(callback) == (long) SIG_IGN)
    {
        handler = NULL;
    }
    else
    {
        char *func_name;
        if (!sw_zend_is_callable(callback, 0, &func_name))
        {
            swoole_php_error(E_WARNING, "function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);

        callback = sw_zval_dup(callback);
        Z_TRY_ADDREF_P(callback);

        handler = php_swoole_onSignal;
    }

    /**
     * for swSignalfd_setup
     */
    SwooleG.main_reactor->check_signalfd = 1;

    //free the old callback
    if (signal_callback[signo])
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, free_signal_callback, signal_callback[signo]);
    }
    else
    {
        SwooleG.main_reactor->signal_listener_num++;
    }
    signal_callback[signo] = callback;

    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(signo, handler);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, alarm)
{
    zend_long usec;
    zend_long type = ITIMER_REAL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|l", &usec, &type) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "cannot use swoole_process::alarm here");
        RETURN_FALSE;
    }

    if (SwooleG.timer.initialized != 0)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use both 'timer' and 'alarm' at the same time");
        RETURN_FALSE;
    }

    struct itimerval timer_set;
    bzero(&timer_set, sizeof(timer_set));

    if (usec > 0)
    {
        long _sec = usec / 1000000;
        long _usec = usec - (_sec * 1000000);

        timer_set.it_interval.tv_sec = _sec;
        timer_set.it_interval.tv_usec = _usec;

        timer_set.it_value.tv_sec = _sec;
        timer_set.it_value.tv_usec = _usec;

        if (timer_set.it_value.tv_usec > 1e6)
        {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(type, &timer_set, NULL) < 0)
    {
        swoole_php_sys_error(E_WARNING, "setitimer() failed");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static void free_signal_callback(void* data)
{
    zval *callback = (zval*) data;
    sw_zval_free(callback);
}

/**
 * safe signal
 */
static void php_swoole_onSignal(int signo)
{
    zval *retval = NULL;
    zval args[1];
    zval *callback = signal_callback[signo];

    ZVAL_LONG(& args[0], signo);

    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "user_signal handler error");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

zend_bool php_swoole_signal_isset_handler(int signo)
{
    if (signo < 0 || signo >= SW_SIGNO_MAX)
    {
        swoole_php_fatal_error(E_WARNING, "invalid signal number [%d]", signo);
        return SW_FALSE;
    }
    return signal_callback[signo] != NULL;
}

void php_swoole_process_clean()
{
    int i;
    for (i = 0; i < SW_SIGNO_MAX; i++)
    {
        if (signal_callback[i])
        {
            sw_zval_free(signal_callback[i]);
            signal_callback[i] = NULL;
        }
    }

    if (SwooleG.process_type != SW_PROCESS_USERWORKER)
    {
        SwooleG.process_type = 0;
    }
}

int php_swoole_process_start(swWorker *process, zval *zobject)
{
    process->pipe = process->pipe_worker;
    process->pid = getpid();

    if (process->redirect_stdin)
    {
        if (dup2(process->pipe, STDIN_FILENO) < 0)
        {
            swoole_php_sys_error(E_WARNING, "dup2() failed");
        }
    }

    if (process->redirect_stdout)
    {
        if (dup2(process->pipe, STDOUT_FILENO) < 0)
        {
            swoole_php_sys_error(E_WARNING, "dup2() failed");
        }
    }

    if (process->redirect_stderr)
    {
        if (dup2(process->pipe, STDERR_FILENO) < 0)
        {
            swoole_php_sys_error(E_WARNING, "dup2() failed");
        }
    }

    php_swoole_process_clean();
    SwooleWG.id = process->id;
    SwooleWG.worker = process;

    zend_update_property_long(swoole_process_ce, zobject, ZEND_STRL("pid"), process->pid);
    zend_update_property_long(swoole_process_ce, zobject, ZEND_STRL("pipe"), process->pipe_worker);

    zval args[1];
    zval *retval = NULL;
    args[0] = *zobject;
    Z_TRY_ADDREF_P(zobject);

    php::process *proc = (php::process *) process->ptr2;

    if (process->enable_coroutine)
    {
        if (PHPCoroutine::create(&proc->fci_cache, 1, args) < 0)
        {
            swoole_php_error(E_WARNING, "create process coroutine error");
            return SW_ERR;
        }
    }
    else
    {
        zval _retval, *retval = &_retval;
        if (sw_call_user_function_fast_ex(NULL, &proc->fci_cache, retval, 1, args) == FAILURE)
        {
            swoole_php_error(E_WARNING, "callback function error");
        }
        zval_ptr_dtor(retval);
    }

    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }

    if (SwooleG.main_reactor)
    {
        php_swoole_event_wait();
    }
    SwooleG.running = 0;

    sw_zend_bailout();
    return SW_OK;
}

static PHP_METHOD(swoole_process, start)
{
    swWorker *process = (swWorker *) swoole_get_object(getThis());

    if (swKill(process->pid, 0) == 0)
    {
        swoole_php_fatal_error(E_WARNING, "process has already been started");
        RETURN_FALSE;
    }

    pid_t pid = swoole_fork();
    if (pid < 0)
    {
        swoole_php_sys_error(E_WARNING, "fork() failed");
        RETURN_FALSE;
    }
    else if (pid > 0)
    {
        process->pid = pid;
        process->child_process = 0;
        zend_update_property_long(swoole_server_ce, getThis(), ZEND_STRL("pid"), process->pid);
        RETURN_LONG(pid);
    }
    else
    {
        process->child_process = 1;
        SW_CHECK_RETURN(php_swoole_process_start(process, getThis()));
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, read)
{
    long buf_size = 8192;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &buf_size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (buf_size > 65536)
    {
        buf_size = 65536;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());

    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot read from pipe");
        RETURN_FALSE;
    }

    zend_string *buf = zend_string_alloc(buf_size, 0);
    ssize_t ret = read(process->pipe, buf->val, buf_size);;
    if (ret < 0)
    {
        efree(buf);
        if (errno != EINTR)
        {
            swoole_php_sys_error(E_WARNING, "read() failed");
        }
        RETURN_FALSE;
    }
    buf->val[ret] = 0;
    buf->len = ret;
    ZVAL_STR(return_value, buf);
}

static PHP_METHOD(swoole_process, write)
{
    char *data = NULL;
    size_t data_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &data_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (data_len < 1)
    {
        swoole_php_fatal_error(E_WARNING, "the data to send is empty");
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot write into pipe");
        RETURN_FALSE;
    }

    int ret;

    //async write
    if (SwooleG.main_reactor)
    {
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, process->pipe);
        if (_socket && _socket->nonblock)
        {
            ret = SwooleG.main_reactor->write(SwooleG.main_reactor, process->pipe, data, (size_t) data_len);
        }
        else
        {
            goto _blocking_read;
        }
    }
    else
    {
        _blocking_read: ret = swSocket_write_blocking(process->pipe, data, data_len);
    }

    if (ret < 0)
    {
        swoole_php_sys_error(E_WARNING, "write() failed");
        RETURN_FALSE;
    }
    ZVAL_LONG(return_value, ret);
}

/**
 * export Swoole\Coroutine\Socket object
 */
static PHP_METHOD(swoole_process, exportSocket)
{
    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot export stream");
        RETURN_FALSE;
    }
    php::process *proc = (php::process *) process->ptr2;
    if (!proc->zsocket)
    {
        proc->zsocket = php_swoole_export_socket_ex(process->pipe, proc->pipe_type == php::PIPE_TYPE_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM);
        if (!proc->zsocket)
        {
            RETURN_FALSE;
        }
    }
    GC_ADDREF(proc->zsocket);
    RETURN_OBJ(proc->zsocket);
}

static PHP_METHOD(swoole_process, push)
{
    char *data;
    size_t length;

    struct
    {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "the data to push is empty");
        RETURN_FALSE;
    }
    else if (length >= sizeof(message.data))
    {
        swoole_php_fatal_error(E_WARNING, "the data to push is too big");
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());

    if (!process->queue)
    {
        swoole_php_fatal_error(E_WARNING, "no msgqueue, cannot use push()");
        RETURN_FALSE;
    }

    message.type = process->id;
    memcpy(message.data, data, length);

    if (swMsgQueue_push(process->queue, (swQueue_data *)&message, length) < 0)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, pop)
{
    long maxsize = SW_MSGMAX;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &maxsize) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (maxsize > SW_MSGMAX || maxsize <= 0)
    {
        maxsize = SW_MSGMAX;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (!process->queue)
    {
        swoole_php_fatal_error(E_WARNING, "no msgqueue, cannot use pop()");
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

    int n = swMsgQueue_pop(process->queue, (swQueue_data *) &message, maxsize);
    if (n < 0)
    {
        RETURN_FALSE;
    }
    RETURN_STRINGL(message.data, n);
}

static PHP_METHOD(swoole_process, exec)
{
    char *execfile = NULL;
    size_t execfile_len = 0;
    zval *args;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &execfile, &execfile_len, &args) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (execfile_len < 1)
    {
        swoole_php_fatal_error(E_WARNING, "exec file name is empty");
        RETURN_FALSE;
    }

    int exec_argc = php_swoole_array_length(args);
    char **exec_args = (char **) emalloc(sizeof(char*) * (exec_argc + 2));

    zval *value = NULL;
    exec_args[0] = sw_strdup(execfile);
    int i = 1;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(args), value)
        convert_to_string(value);
        Z_TRY_ADDREF_P(value);
        exec_args[i] = Z_STRVAL_P(value);
        i++;
    SW_HASHTABLE_FOREACH_END();
    exec_args[i] = NULL;

    if (execv(execfile, exec_args) < 0)
    {
        swoole_php_sys_error(E_WARNING, "execv(%s) failed", execfile);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_process, daemon)
{
    zend_bool nochdir = 1;
    zend_bool noclose = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|bb", &nochdir, &noclose) == FAILURE)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(daemon(nochdir, noclose) == 0);
}

#ifdef HAVE_CPU_AFFINITY
static PHP_METHOD(swoole_process, setaffinity)
{
    zval *array;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &array) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (php_swoole_array_length(array) == 0)
    {
        RETURN_FALSE;
    }
    if (php_swoole_array_length(array) > SW_CPU_NUM)
    {
        swoole_php_fatal_error(E_WARNING, "More than the number of CPU");
        RETURN_FALSE;
    }

    zval *value = NULL;
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(array), value)
        if (zval_get_long(value) >= SW_CPU_NUM)
        {
            swoole_php_fatal_error(E_WARNING, "invalid cpu id [%d]", (int) Z_LVAL_P(value));
            RETURN_FALSE;
        }
        CPU_SET(Z_LVAL_P(value), &cpu_set);
    SW_HASHTABLE_FOREACH_END();

#ifdef __FreeBSD__
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpu_set), &cpu_set) < 0)
#else
    if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
#endif
    {
        swoole_php_sys_error(E_WARNING, "sched_setaffinity() failed");
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
#endif

static PHP_METHOD(swoole_process, exit)
{
    long ret_code = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &ret_code) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());

    if (getpid() != process->pid)
    {
        swoole_php_fatal_error(E_WARNING, "not current process");
        RETURN_FALSE;
    }

    if (ret_code < 0 || ret_code > 255)
    {
        swoole_php_fatal_error(E_WARNING, "exit ret_code range is [>0 and <255] ");
        ret_code = 1;
    }

    close(process->pipe);

    SwooleG.running = 0;

    if (ret_code == 0)
    {
        sw_zend_bailout();
    }
    else
    {
        exit(ret_code);
    }
}

static PHP_METHOD(swoole_process, close)
{
    long which = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &which) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot close the pipe");
        RETURN_FALSE;
    }

    int ret;
    if (which == SW_PIPE_CLOSE_READ)
    {
        ret = shutdown(process->pipe, SHUT_RD);
    }
    else if (which == SW_PIPE_CLOSE_WRITE)
    {
        ret = shutdown(process->pipe, SHUT_WR);
    }
    else
    {
        ret = swPipeUnsock_close_ext(process->pipe_object, which);
    }
    if (ret < 0)
    {
        swoole_php_sys_error(E_WARNING, "close() failed");
        RETURN_FALSE;
    }
    if (which == 0)
    {
        process->pipe = 0;
        efree(process->pipe_object);
        process->pipe_object = NULL;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, setTimeout)
{
    double seconds;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &seconds) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot setTimeout the pipe");
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swSocket_set_timeout(process->pipe, seconds));
}

static PHP_METHOD(swoole_process, setBlocking)
{
    zend_bool blocking;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "b", &blocking) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = (swWorker *) swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, cannot setBlocking the pipe");
        RETURN_FALSE;
    }
    if (blocking)
    {
        swSetBlock(process->pipe);
    }
    else
    {
        swSetNonBlock(process->pipe);
    }
    if (SwooleG.main_reactor)
    {
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, process->pipe);
        if (_socket)
        {
            _socket->nonblock = blocking ? 0 : 1;
        }
    }
}
