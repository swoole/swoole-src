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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"
#include "php_swoole_process.h"

#include "swoole_server.h"
#include "swoole_msg_queue.h"
#include "swoole_signal.h"

#include <sys/ipc.h>
#include <sys/resource.h>

using namespace swoole;

zend_class_entry *swoole_process_ce;
static zend_object_handlers swoole_process_handlers;

static uint32_t php_swoole_worker_round_id = 0;
static zend_fcall_info_cache *signal_fci_caches[SW_SIGNO_MAX] = {};

struct ProcessObject {
    Worker *worker;
    zend_object std;
};

static sw_inline ProcessObject *php_swoole_process_fetch_object(zend_object *obj) {
    return (ProcessObject *) ((char *) obj - swoole_process_handlers.offset);
}

Worker *php_swoole_process_get_worker(zval *zobject) {
    return php_swoole_process_fetch_object(Z_OBJ_P(zobject))->worker;
}

Worker *php_swoole_process_get_and_check_worker(zval *zobject) {
    Worker *worker = php_swoole_process_get_worker(zobject);
    if (!worker) {
        php_swoole_fatal_error(E_ERROR, "you must call Process constructor first");
    }
    return worker;
}

void php_swoole_process_set_worker(zval *zobject, Worker *worker) {
    php_swoole_process_fetch_object(Z_OBJ_P(zobject))->worker = worker;
}

static void php_swoole_process_free_object(zend_object *object) {
    ProcessObject *process = php_swoole_process_fetch_object(object);
    Worker *worker = process->worker;

    if (worker) {
        UnixSocket *_pipe = worker->pipe_object;
        if (_pipe) {
            delete _pipe;
        }

        if (worker->queue) {
            delete worker->queue;
        }

        zend::Process *proc = (zend::Process *) worker->ptr2;
        if (proc) {
            delete proc;
        }
        efree(worker);
    }

    zend_object_std_dtor(object);
}

static zend_object *php_swoole_process_create_object(zend_class_entry *ce) {
    ProcessObject *process = (ProcessObject *) zend_object_alloc(sizeof(ProcessObject), ce);
    zend_object_std_init(&process->std, ce);
    object_properties_init(&process->std, ce);
    process->std.handlers = &swoole_process_handlers;
    return &process->std;
}

SW_EXTERN_C_BEGIN
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
static PHP_METHOD(swoole_process, setAffinity);
#endif
static PHP_METHOD(swoole_process, set);
static PHP_METHOD(swoole_process, setTimeout);
static PHP_METHOD(swoole_process, setBlocking);
static PHP_METHOD(swoole_process, setPriority);
static PHP_METHOD(swoole_process, getPriority);
static PHP_METHOD(swoole_process, start);
static PHP_METHOD(swoole_process, write);
static PHP_METHOD(swoole_process, read);
static PHP_METHOD(swoole_process, close);
static PHP_METHOD(swoole_process, exit);
static PHP_METHOD(swoole_process, exec);
static PHP_METHOD(swoole_process, exportSocket);
SW_EXTERN_C_END

static void php_swoole_onSignal(int signo);

// clang-format off

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
    ZEND_ARG_INFO(0, pipes)
ZEND_END_ARG_INFO()

#ifdef HAVE_CPU_AFFINITY
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setAffinity, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cpu_settings, 0)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setPriority, 0, 0, 2)
    ZEND_ARG_INFO(0, which)
    ZEND_ARG_INFO(0, priority)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_getPriority, 0, 0, 1)
    ZEND_ARG_INFO(0, which)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

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

#define MSGQUEUE_NOWAIT (1 << 8)

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
    PHP_ME(swoole_process, setAffinity, arginfo_swoole_process_setAffinity, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#endif
    PHP_ME(swoole_process, setPriority, arginfo_swoole_process_setPriority, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, getPriority, arginfo_swoole_process_getPriority, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, set, arginfo_swoole_process_set, ZEND_ACC_PUBLIC)
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
// clang-format on

void php_swoole_process_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_process, "Swoole\\Process", "swoole_process", nullptr, swoole_process_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_process);
    SW_SET_CLASS_CLONEABLE(swoole_process, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_process, php_swoole_process_create_object, php_swoole_process_free_object, ProcessObject, std);

    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("IPC_NOWAIT"), MSGQUEUE_NOWAIT);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_MASTER"), SW_PIPE_CLOSE_MASTER);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_WORKER"), SW_PIPE_CLOSE_WORKER);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_READ"), SW_PIPE_CLOSE_READ);
    zend_declare_class_constant_long(swoole_process_ce, ZEND_STRL("PIPE_WRITE"), SW_PIPE_CLOSE_WRITE);

    zend_declare_property_null(swoole_process_ce, ZEND_STRL("pipe"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("msgQueueId"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("msgQueueKey"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("pid"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_ce, ZEND_STRL("id"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_process_ce, ZEND_STRL("callback"), ZEND_ACC_PRIVATE);

    /**
     * 31 signal constants
     */
    if (!zend_hash_str_find(&module_registry, ZEND_STRL("pcntl"))) {
        REGISTER_LONG_CONSTANT("SIGHUP", (zend_long) SIGHUP, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGINT", (zend_long) SIGINT, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGQUIT", (zend_long) SIGQUIT, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGILL", (zend_long) SIGILL, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGTRAP", (zend_long) SIGTRAP, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGABRT", (zend_long) SIGABRT, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGBUS", (zend_long) SIGBUS, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGFPE", (zend_long) SIGFPE, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGKILL", (zend_long) SIGKILL, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGUSR1", (zend_long) SIGUSR1, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGSEGV", (zend_long) SIGSEGV, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGUSR2", (zend_long) SIGUSR2, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGPIPE", (zend_long) SIGPIPE, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGALRM", (zend_long) SIGALRM, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGTERM", (zend_long) SIGTERM, CONST_CS | CONST_PERSISTENT);
#ifdef SIGSTKFLT
        REGISTER_LONG_CONSTANT("SIGSTKFLT", (zend_long) SIGSTKFLT, CONST_CS | CONST_PERSISTENT);
#endif
        REGISTER_LONG_CONSTANT("SIGCHLD", (zend_long) SIGCHLD, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGCONT", (zend_long) SIGCONT, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGSTOP", (zend_long) SIGSTOP, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGTSTP", (zend_long) SIGTSTP, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGTTIN", (zend_long) SIGTTIN, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGTTOU", (zend_long) SIGTTOU, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGURG", (zend_long) SIGURG, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGXCPU", (zend_long) SIGXCPU, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGXFSZ", (zend_long) SIGXFSZ, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGVTALRM", (zend_long) SIGVTALRM, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGPROF", (zend_long) SIGPROF, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGWINCH", (zend_long) SIGWINCH, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("SIGIO", (zend_long) SIGIO, CONST_CS | CONST_PERSISTENT);
#ifdef SIGPWR
        REGISTER_LONG_CONSTANT("SIGPWR", (zend_long) SIGPWR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef SIGSYS
        REGISTER_LONG_CONSTANT("SIGSYS", (zend_long) SIGSYS, CONST_CS | CONST_PERSISTENT);
#endif
        REGISTER_LONG_CONSTANT("SIG_IGN", (zend_long) SIG_IGN, CONST_CS | CONST_PERSISTENT);

        REGISTER_LONG_CONSTANT("PRIO_PROCESS", (zend_long) PRIO_PROCESS, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("PRIO_PGRP", (zend_long) PRIO_PGRP, CONST_CS | CONST_PERSISTENT);
        REGISTER_LONG_CONSTANT("PRIO_USER", (zend_long) PRIO_USER, CONST_CS | CONST_PERSISTENT);
    }
}

static PHP_METHOD(swoole_process, __construct) {
    Worker *process = php_swoole_process_get_worker(ZEND_THIS);

    if (process) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    // only cli env
    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "%s can only be used in PHP CLI mode", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    if (sw_server() && sw_server()->is_started() && sw_server()->is_master()) {
        php_swoole_fatal_error(E_ERROR, "%s can't be used in master process", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    if (SwooleTG.async_threads) {
        php_swoole_fatal_error(E_ERROR, "unable to create %s with async-io threads", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend::Function func;
    zend_bool redirect_stdin_and_stdout = 0;
    zend_long pipe_type = zend::PIPE_TYPE_DGRAM;
    zend_bool enable_coroutine = false;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 4)
    Z_PARAM_FUNC(func.fci, func.fci_cache);
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(redirect_stdin_and_stdout)
    Z_PARAM_LONG(pipe_type)
    Z_PARAM_BOOL(enable_coroutine)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    process = (Worker *) ecalloc(1, sizeof(Worker));

    uint32_t base = 1;
    if (sw_server() && sw_server()->is_started()) {
        base = sw_server()->worker_num + sw_server()->task_worker_num + sw_server()->get_user_worker_num();
    }
    if (php_swoole_worker_round_id == 0) {
        php_swoole_worker_round_id = base;
    }
    process->id = php_swoole_worker_round_id++;

    if (redirect_stdin_and_stdout) {
        process->redirect_stdin = true;
        process->redirect_stdout = true;
        process->redirect_stderr = true;
        /**
         * Forced to use stream pipe
         */
        pipe_type = zend::PIPE_TYPE_STREAM;
    }

    if (pipe_type > 0) {
        int socket_type = pipe_type == zend::PIPE_TYPE_STREAM ? SOCK_STREAM : SOCK_DGRAM;
        UnixSocket *_pipe = new UnixSocket(true, socket_type);
        if (!_pipe->ready()) {
            zend_throw_exception(swoole_exception_ce, "failed to create unix soccket", errno);
            delete _pipe;
            efree(process);
            RETURN_FALSE;
        }

        process->pipe_master = _pipe->get_socket(true);
        process->pipe_worker = _pipe->get_socket(false);

        process->pipe_object = _pipe;
        process->pipe_current = process->pipe_master;

        zend_update_property_long(
            swoole_process_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("pipe"), process->pipe_master->fd);
    }

    zend::Process *proc = new zend::Process((enum zend::PipeType) pipe_type, enable_coroutine);
    process->ptr2 = proc;

    zend_update_property(
        swoole_process_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("callback"), ZEND_CALL_ARG(execute_data, 1));
    php_swoole_process_set_worker(ZEND_THIS, process);
}

static PHP_METHOD(swoole_process, __destruct) {}

static PHP_METHOD(swoole_process, wait) {
    zend_bool blocking = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &blocking) == FAILURE) {
        RETURN_FALSE;
    }

    auto exit_status = swoole::wait_process(-1, blocking ? 0 : WNOHANG);
    if (exit_status.get_pid() > 0) {
        array_init(return_value);
        add_assoc_long(return_value, "pid", exit_status.get_pid());
        add_assoc_long(return_value, "code", exit_status.get_code());
        add_assoc_long(return_value, "signal", exit_status.get_signal());
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, useQueue) {
    long msgkey = 0;
    long mode = 2;
    long capacity = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lll", &msgkey, &mode, &capacity) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);

    if (msgkey <= 0) {
        msgkey = ftok(zend_get_executed_filename(), 1);
    }

    MsgQueue *queue = new MsgQueue(msgkey);
    if (!queue->ready()) {
        delete queue;
        RETURN_FALSE;
    }
    if (mode & MSGQUEUE_NOWAIT) {
        queue->set_blocking(false);
        mode = mode & (~MSGQUEUE_NOWAIT);
    }
    if (capacity > 0) {
        queue->set_capacity(capacity);
    }
    process->queue = queue;
    process->ipc_mode = mode;
    zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("msgQueueId"), queue->get_id());
    zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("msgQueueKey"), msgkey);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, statQueue) {
    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (!process->queue) {
        php_swoole_fatal_error(E_WARNING, "no queue, can't get stats of the queue");
        RETURN_FALSE;
    }

    size_t queue_num = -1;
    size_t queue_bytes = -1;
    if (process->queue->stat(&queue_num, &queue_bytes)) {
        array_init(return_value);
        add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), queue_num);
        add_assoc_long_ex(return_value, ZEND_STRL("queue_bytes"), queue_bytes);
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, freeQueue) {
    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->queue && process->queue->destroy()) {
        delete process->queue;
        process->queue = nullptr;
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, kill) {
    zend_long pid;
    zend_long sig = SIGTERM;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|l", &pid, &sig) == FAILURE) {
        RETURN_FALSE;
    }

    int ret = swoole_kill((int) pid, (int) sig);
    if (ret < 0) {
        if (!(sig == 0 && errno == ESRCH)) {
            php_swoole_sys_error(E_WARNING, "kill(%d, %d) failed", (int) pid, (int) sig);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, signal) {
    zend_long signo = 0;
    zval *zcallback = nullptr;
    zend_fcall_info_cache *fci_cache = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(signo)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL_EX(zcallback, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "%s::signal can only be used in CLI mode", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    if (signo < 0 || signo >= SW_SIGNO_MAX) {
        php_swoole_fatal_error(E_WARNING, "invalid signal number [" ZEND_LONG_FMT "]", signo);
        RETURN_FALSE;
    }

    swSignalHandler handler = swoole_signal_get_handler(signo);
    if (handler && handler != php_swoole_onSignal) {
        php_swoole_fatal_error(
            E_WARNING, "signal [" ZEND_LONG_FMT "] processor has been registered by the system", signo);
        RETURN_FALSE;
    }

    if (zcallback == nullptr) {
        fci_cache = signal_fci_caches[signo];
        if (fci_cache) {
            swoole_signal_set(signo, nullptr);
            signal_fci_caches[signo] = nullptr;
            swoole_event_defer(sw_zend_fci_cache_free, fci_cache);
            SwooleTG.signal_listener_num--;
            RETURN_TRUE;
        } else {
            php_swoole_error(E_WARNING, "unable to find the callback of signal [" ZEND_LONG_FMT "]", signo);
            RETURN_FALSE;
        }
    } else if (Z_TYPE_P(zcallback) == IS_LONG && Z_LVAL_P(zcallback) == (zend_long) SIG_IGN) {
        handler = nullptr;
    } else {
        char *func_name;
        fci_cache = (zend_fcall_info_cache *) ecalloc(1, sizeof(zend_fcall_info_cache));
        if (!sw_zend_is_callable_ex(zcallback, nullptr, 0, &func_name, 0, fci_cache, nullptr)) {
            php_swoole_error(E_WARNING, "function '%s' is not callable", func_name);
            efree(func_name);
            efree(fci_cache);
            RETURN_FALSE;
        }
        efree(func_name);
        sw_zend_fci_cache_persist(fci_cache);
        handler = php_swoole_onSignal;
    }

    if (sw_server() && sw_server()->is_sync_process()) {
        if (signal_fci_caches[signo]) {
            sw_zend_fci_cache_free(signal_fci_caches[signo]);
        } else {
            SwooleTG.signal_listener_num++;
        }
        signal_fci_caches[signo] = fci_cache;
        swoole_signal_set(signo, handler);
        RETURN_TRUE;
    }

    php_swoole_check_reactor();
    // for swSignalfd_setup
    SwooleTG.reactor->check_signalfd = true;
    if (!SwooleTG.reactor->isset_exit_condition(Reactor::EXIT_CONDITION_SIGNAL_LISTENER)) {
        SwooleTG.reactor->set_exit_condition(Reactor::EXIT_CONDITION_SIGNAL_LISTENER,
                                             [](Reactor *reactor, size_t &event_num) -> bool {
                                                 return SwooleTG.signal_listener_num == 0 or !SwooleG.wait_signal;
                                             });
    }

    if (signal_fci_caches[signo]) {
        // free the old fci_cache
        swoole_event_defer(sw_zend_fci_cache_free, signal_fci_caches[signo]);
    } else {
        SwooleTG.signal_listener_num++;
    }
    signal_fci_caches[signo] = fci_cache;

    // use user settings
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swoole_signal_set(signo, handler);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, alarm) {
    zend_long usec;
    zend_long type = ITIMER_REAL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|l", &usec, &type) == FAILURE) {
        RETURN_FALSE;
    }

    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "cannot use %s::alarm here", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    if (SwooleTG.timer) {
        php_swoole_fatal_error(E_WARNING, "cannot use both 'timer' and 'alarm' at the same time");
        RETURN_FALSE;
    }

    struct itimerval timer_set = {};

    if (usec > 0) {
        long _sec = usec / 1000000;
        long _usec = usec - (_sec * 1000000);

        timer_set.it_interval.tv_sec = _sec;
        timer_set.it_interval.tv_usec = _usec;

        timer_set.it_value.tv_sec = _sec;
        timer_set.it_value.tv_usec = _usec;

        if (timer_set.it_value.tv_usec > 1e6) {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(type, &timer_set, nullptr) < 0) {
        php_swoole_sys_error(E_WARNING, "setitimer() failed");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

/**
 * safe signal
 */
static void php_swoole_onSignal(int signo) {
    zend_fcall_info_cache *fci_cache = signal_fci_caches[signo];

    if (fci_cache) {
        zval argv[1];
        ZVAL_LONG(&argv[0], signo);

        if (UNEXPECTED(!zend::function::call(fci_cache, 1, argv, nullptr, php_swoole_is_enable_coroutine()))) {
            php_swoole_fatal_error(
                E_WARNING, "%s: signal [%d] handler error", ZSTR_VAL(swoole_process_ce->name), signo);
        }
    }
}

zend_bool php_swoole_signal_isset_handler(int signo) {
    if (signo < 0 || signo >= SW_SIGNO_MAX) {
        php_swoole_fatal_error(E_WARNING, "invalid signal number [%d]", signo);
        return 0;
    }
    return signal_fci_caches[signo] != nullptr;
}

void php_swoole_process_clean() {
    for (int i = 0; i < SW_SIGNO_MAX; i++) {
        zend_fcall_info_cache *fci_cache = signal_fci_caches[i];
        if (fci_cache) {
            sw_zend_fci_cache_discard(fci_cache);
            efree(fci_cache);
            signal_fci_caches[i] = nullptr;
        }
    }

    if (SwooleG.process_type != SW_PROCESS_USERWORKER) {
        SwooleG.process_type = 0;
    }
}

int php_swoole_process_start(Worker *process, zval *zobject) {
    zval *zcallback = sw_zend_read_property_ex(swoole_process_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_CALLBACK), 0);
    zend_fcall_info_cache fci_cache;

    if (!sw_zend_is_callable_ex(zcallback, nullptr, 0, nullptr, 0, &fci_cache, nullptr)) {
        php_swoole_fatal_error(E_ERROR, "Illegal callback function of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
        return SW_ERR;
    }

    zend::Process *proc = (zend::Process *) process->ptr2;

    process->pipe_current = process->pipe_worker;
    process->pid = getpid();

    if (process->redirect_stdin) {
        if (dup2(process->pipe_current->fd, STDIN_FILENO) < 0) {
            php_swoole_sys_error(E_WARNING, "dup2() failed");
        }
    }

    if (process->redirect_stdout) {
        if (dup2(process->pipe_current->fd, STDOUT_FILENO) < 0) {
            php_swoole_sys_error(E_WARNING, "dup2() failed");
        }
    }

    if (process->redirect_stderr) {
        if (dup2(process->pipe_current->fd, STDERR_FILENO) < 0) {
            php_swoole_sys_error(E_WARNING, "dup2() failed");
        }
    }

    php_swoole_process_clean();
    SwooleG.process_id = process->id;
    SwooleWG.worker = process;

    zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("pid"), process->pid);
    if (process->pipe_current) {
        zend_update_property_long(
            swoole_process_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("pipe"), process->pipe_current->fd);
    }
    // eventloop create
    if (proc->enable_coroutine && php_swoole_reactor_init() < 0) {
        return SW_ERR;
    }
    // main function
    if (UNEXPECTED(!zend::function::call(&fci_cache, 1, zobject, nullptr, proc->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    // eventloop start
    if (proc->enable_coroutine) {
        php_swoole_event_wait();
    }
    // equivalent to exit
    zend_bailout();

    return SW_OK;
}

static PHP_METHOD(swoole_process, start) {
    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);

    if (process->pid && swoole_kill(process->pid, 0) == 0) {
        php_swoole_fatal_error(E_WARNING, "process has already been started");
        RETURN_FALSE;
    }

    pid_t pid = swoole_fork(0);
    if (pid < 0) {
        php_swoole_sys_error(E_WARNING, "fork() failed");
        RETURN_FALSE;
    } else if (pid > 0) {
        process->pid = pid;
        process->child_process = 0;
        zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("pid"), process->pid);
        RETURN_LONG(pid);
    } else {
        process->child_process = 1;
        SW_CHECK_RETURN(php_swoole_process_start(process, ZEND_THIS));
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, read) {
    long buf_size = 8192;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &buf_size) == FAILURE) {
        RETURN_FALSE;
    }

    if (buf_size > 65536) {
        buf_size = 65536;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);

    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot read from pipe");
        RETURN_FALSE;
    }

    zend_string *buf = zend_string_alloc(buf_size, 0);
    ssize_t ret = process->pipe_current->read(buf->val, buf_size);

    if (ret < 0) {
        efree(buf);
        if (errno != EINTR) {
            php_swoole_sys_error(E_WARNING, "read() failed");
        }
        RETURN_FALSE;
    }
    buf->val[ret] = 0;
    buf->len = ret;
    RETURN_STR(buf);
}

static PHP_METHOD(swoole_process, write) {
    char *data = nullptr;
    size_t data_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &data_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (data_len < 1) {
        php_swoole_fatal_error(E_WARNING, "the data to send is empty");
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot write into pipe");
        RETURN_FALSE;
    }

    ssize_t ret;

    // async write
    if (SwooleTG.reactor) {
        if (process->pipe_current->nonblock) {
            ret = swoole_event_write(process->pipe_current, data, (size_t) data_len);
        } else {
            goto _blocking_read;
        }
    } else {
    _blocking_read:
        ret = process->pipe_current->send_blocking(data, data_len);
    }

    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "write() failed");
        RETURN_FALSE;
    }
    ZVAL_LONG(return_value, ret);
}

/**
 * export Swoole\Coroutine\Socket object
 */
static PHP_METHOD(swoole_process, exportSocket) {
    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot export stream");
        RETURN_FALSE;
    }
    zend::Process *proc = (zend::Process *) process->ptr2;
    if (!proc->zsocket) {
        proc->zsocket =
            php_swoole_dup_socket(process->pipe_current->fd,
                                  proc->pipe_type == zend::PIPE_TYPE_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM);
        if (!proc->zsocket) {
            RETURN_FALSE;
        }
    }
    GC_ADDREF(proc->zsocket);
    RETURN_OBJ(proc->zsocket);
}

static PHP_METHOD(swoole_process, push) {
    char *data;
    size_t length;

    struct {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &length) == FAILURE) {
        RETURN_FALSE;
    }

    if (length <= 0) {
        php_swoole_fatal_error(E_WARNING, "the data to push is empty");
        RETURN_FALSE;
    } else if (length >= sizeof(message.data)) {
        php_swoole_fatal_error(E_WARNING, "the data to push is too big");
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);

    if (!process->queue) {
        php_swoole_fatal_error(E_WARNING, "no msgqueue, cannot use push()");
        RETURN_FALSE;
    }

    message.type = process->id + 1;
    memcpy(message.data, data, length);

    if (!process->queue->push((QueueNode *) &message, length)) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, pop) {
    long maxsize = SW_MSGMAX;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &maxsize) == FAILURE) {
        RETURN_FALSE;
    }

    if (maxsize > SW_MSGMAX || maxsize <= 0) {
        maxsize = SW_MSGMAX;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (!process->queue) {
        php_swoole_fatal_error(E_WARNING, "no msgqueue, cannot use pop()");
        RETURN_FALSE;
    }

    struct {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (process->ipc_mode == 2) {
        message.type = 0;
    } else {
        message.type = process->id + 1;
    }

    ssize_t n = process->queue->pop((QueueNode *) &message, maxsize);
    if (n < 0) {
        RETURN_FALSE;
    }
    RETURN_STRINGL(message.data, n);
}

static PHP_METHOD(swoole_process, exec) {
    char *execfile = nullptr;
    size_t execfile_len = 0;
    zval *args;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &execfile, &execfile_len, &args) == FAILURE) {
        RETURN_FALSE;
    }

    if (execfile_len < 1) {
        php_swoole_fatal_error(E_WARNING, "exec file name is empty");
        RETURN_FALSE;
    }

    int exec_argc = php_swoole_array_length(args);
    char **exec_args = (char **) emalloc(sizeof(char *) * (exec_argc + 2));

    zval *value = nullptr;
    exec_args[0] = sw_strdup(execfile);
    int i = 1;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(args), value)
    convert_to_string(value);
    Z_TRY_ADDREF_P(value);
    exec_args[i] = Z_STRVAL_P(value);
    i++;
    SW_HASHTABLE_FOREACH_END();
    exec_args[i] = nullptr;

    if (execv(execfile, exec_args) < 0) {
        php_swoole_sys_error(E_WARNING, "execv(%s) failed", execfile);
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_process, daemon) {
    zend_bool nochdir = 1;
    zend_bool noclose = 1;
    zval *zpipes = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 3)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(nochdir)
    Z_PARAM_BOOL(noclose)
    Z_PARAM_ARRAY(zpipes)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval *elem;
    int fd = 0;

    if (zpipes) {
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(zpipes), elem) {
            if (!ZVAL_IS_NULL(elem)) {
                int new_fd = php_swoole_convert_to_fd(elem);
                if (new_fd >= 0) {
                    if (dup2(new_fd, fd) < 0) {
                        swoole_sys_warning("dup2(%d, %d) failed", new_fd, fd);
                    }
                }
            }
            if (fd++ == 2) {
                break;
            }
        }
        ZEND_HASH_FOREACH_END();
    }

    RETURN_BOOL(swoole_daemon(nochdir, noclose) == 0);
}

#ifdef HAVE_CPU_AFFINITY
static PHP_METHOD(swoole_process, setAffinity) {
    zval *array;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &array) == FAILURE) {
        RETURN_FALSE;
    }
    if (php_swoole_array_length(array) == 0) {
        RETURN_FALSE;
    }
    if (php_swoole_array_length(array) > SW_CPU_NUM) {
        php_swoole_fatal_error(E_WARNING, "More than the number of CPU");
        RETURN_FALSE;
    }

    zval *value = nullptr;
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(array), value)
    if (zval_get_long(value) >= SW_CPU_NUM) {
        php_swoole_fatal_error(E_WARNING, "invalid cpu id [%d]", (int) Z_LVAL_P(value));
        RETURN_FALSE;
    }
    CPU_SET(Z_LVAL_P(value), &cpu_set);
    SW_HASHTABLE_FOREACH_END();

    if (swoole_set_cpu_affinity(&cpu_set) < 0) {
        php_swoole_sys_error(E_WARNING, "sched_setaffinity() failed");
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
#endif

static PHP_METHOD(swoole_process, exit) {
    long ret_code = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &ret_code) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);

    if (getpid() != process->pid) {
        php_swoole_fatal_error(E_WARNING, "not current process");
        RETURN_FALSE;
    }

    if (ret_code < 0 || ret_code > 255) {
        php_swoole_fatal_error(E_WARNING, "exit ret_code range is [>0 and <255] ");
        ret_code = 1;
    }

    exit(ret_code);
}

static PHP_METHOD(swoole_process, close) {
    long which = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &which) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot close the pipe");
        RETURN_FALSE;
    }

    if (process->pipe_object == nullptr) {
        php_swoole_fatal_error(E_WARNING, "cannot close the pipe");
        RETURN_FALSE;
    }

    int ret;
    if (which == SW_PIPE_CLOSE_READ) {
        ret = process->pipe_current->shutdown(SHUT_RD);
    } else if (which == SW_PIPE_CLOSE_WRITE) {
        ret = process->pipe_current->shutdown(SHUT_WR);
    } else {
        ret = process->pipe_object->close(which);
    }
    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "close() failed");
        RETURN_FALSE;
    }
    if (which == 0) {
        delete process->pipe_object;
        process->pipe_object = nullptr;
        process->pipe_current = nullptr;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, set) {
    zval *zset = nullptr;
    HashTable *vht = nullptr;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    zend::Process *proc = (zend::Process *) process->ptr2;

    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        proc->enable_coroutine = zval_is_true(ztmp);
    }
}

static PHP_METHOD(swoole_process, setTimeout) {
    double seconds;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &seconds) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot setTimeout the pipe");
        RETURN_FALSE;
    }
    RETURN_BOOL(process->pipe_current->set_timeout(seconds));
}

static PHP_METHOD(swoole_process, setBlocking) {
    zend_bool blocking;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "b", &blocking) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    if (process->pipe_current == nullptr) {
        php_swoole_fatal_error(E_WARNING, "no pipe, cannot setBlocking the pipe");
        RETURN_FALSE;
    }
    if (blocking) {
        process->pipe_current->set_block();
    } else {
        process->pipe_current->set_nonblock();
    }
}

static PHP_METHOD(swoole_process, setPriority) {
    zend_long which, priority;
    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(which)
    Z_PARAM_LONG(priority)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    RETURN_BOOL(setpriority(which, process->pid, priority) == 0);
}

static PHP_METHOD(swoole_process, getPriority) {
    zend_long which;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(which)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Worker *process = php_swoole_process_get_and_check_worker(ZEND_THIS);
    RETURN_LONG(getpriority(which, process->pid));
}
