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
#include "connection.h"
#include "websocket.h"
#include "ext/standard/php_var.h"
#include "zend_smart_str.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#include <unordered_map>
#include <list>

using namespace std;
using namespace swoole;

typedef struct
{
    int current_fd;
    uint32_t session_id;
    swServer *serv;
    swListenPort *port;
    int index;
} swConnectionIterator;

static int php_swoole_task_id = 0;
static int dgram_server_socket;

struct
{
    zval *zobjects[SW_MAX_LISTEN_PORT];
    zval *zports;
    uint8_t num;
    swoole_server_port_property *primary_port;
} server_port_list;

typedef struct
{
    php_coro_context context;
    int *list;
    uint32_t count;
    zval *result;
    swTimer_node *timer;
} swTaskCo;

static zend_fcall_info_cache *server_callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];

static unordered_map<int, zend_fcall_info_cache> task_callbacks;
static unordered_map<int, swTaskCo*> task_coroutine_map;
static unordered_map<int, list<php_coro_context *> *> send_coroutine_map;

struct server_event {
    enum php_swoole_server_callback_type type;
    std::string name;
    server_event(enum php_swoole_server_callback_type type, std::string &&name) : type(type) , name(name) { }
};

static unordered_map<string, server_event> server_event_map({
    { "start",        server_event(SW_SERVER_CB_onStart,        "Start") },
    { "shutdown",     server_event(SW_SERVER_CB_onShutdown,     "Shutdown") },
    { "workerstart",  server_event(SW_SERVER_CB_onWorkerStart,  "WorkerStart") },
    { "workerstop",   server_event(SW_SERVER_CB_onWorkerStop,   "WorkerStop") },
    { "task",         server_event(SW_SERVER_CB_onTask,         "Task") },
    { "finish",       server_event(SW_SERVER_CB_onFinish,       "Finish") },
    { "workerexit",   server_event(SW_SERVER_CB_onWorkerExit,   "WorkerExit") },
    { "workererror",  server_event(SW_SERVER_CB_onWorkerError,  "WorkerError") },
    { "managerstart", server_event(SW_SERVER_CB_onManagerStart, "ManagerStart") },
    { "managerstop",  server_event(SW_SERVER_CB_onManagerStop,  "ManagerStop") },
    { "pipemessage",  server_event(SW_SERVER_CB_onPipeMessage,  "PipeMessage") },
});

// arginfo server
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server__construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, server_socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendwait, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_protect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, is_protected)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, server_socket)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_pause, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_confirm, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

#ifdef SWOOLE_SOCKETS_SUPPORT
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getSocket, 0, 0, 0)
    ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getCallback, 0, 0, 1)
    ZEND_ARG_INFO(0, event_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_listen, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, worker_id)
    ZEND_ARG_CALLABLE_INFO(0, finish_callback, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskCo, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, tasks, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskWaitMulti, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, tasks, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat, 0, 0, 1)
    ZEND_ARG_INFO(0, reactor_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_stop, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_bind, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendMessage, 0, 0, 2)
    ZEND_ARG_INFO(0, message)
    ZEND_ARG_INFO(0, dst_worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addProcess, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, process, swoole_process, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_getClientInfo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reactor_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_getClientList, 0, 0, 1)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

//arginfo connection_iterator
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_iterator_offsetExists, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_iterator_offsetGet, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_iterator_offsetUnset, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_iterator_offsetSet, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()
//arginfo end

static PHP_METHOD(swoole_server, __construct);
static PHP_METHOD(swoole_server, __destruct);
static PHP_METHOD(swoole_server, set);
static PHP_METHOD(swoole_server, on);
static PHP_METHOD(swoole_server, getCallback);
static PHP_METHOD(swoole_server, listen);
static PHP_METHOD(swoole_server, sendMessage);
static PHP_METHOD(swoole_server, addProcess);
static PHP_METHOD(swoole_server, start);
static PHP_METHOD(swoole_server, stop);
static PHP_METHOD(swoole_server, send);
static PHP_METHOD(swoole_server, sendfile);
static PHP_METHOD(swoole_server, stats);
static PHP_METHOD(swoole_server, bind);
static PHP_METHOD(swoole_server, sendto);
static PHP_METHOD(swoole_server, sendwait);
static PHP_METHOD(swoole_server, exists);
static PHP_METHOD(swoole_server, protect);
static PHP_METHOD(swoole_server, close);
static PHP_METHOD(swoole_server, confirm);
static PHP_METHOD(swoole_server, pause);
static PHP_METHOD(swoole_server, resume);
static PHP_METHOD(swoole_server, task);
static PHP_METHOD(swoole_server, taskwait);
static PHP_METHOD(swoole_server, taskWaitMulti);
static PHP_METHOD(swoole_server, taskCo);
static PHP_METHOD(swoole_server, finish);
static PHP_METHOD(swoole_server, reload);
static PHP_METHOD(swoole_server, shutdown);
static PHP_METHOD(swoole_server, heartbeat);
static PHP_METHOD(swoole_server, getClientList);
static PHP_METHOD(swoole_server, getClientInfo);
#ifdef SW_BUFFER_RECV_TIME
static PHP_METHOD(swoole_server, getReceivedTime);
#endif
#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server, getSocket);
#endif

/**
 * Server\Connection
 */
static PHP_METHOD(swoole_connection_iterator, count);
static PHP_METHOD(swoole_connection_iterator, rewind);
static PHP_METHOD(swoole_connection_iterator, next);
static PHP_METHOD(swoole_connection_iterator, current);
static PHP_METHOD(swoole_connection_iterator, key);
static PHP_METHOD(swoole_connection_iterator, valid);
static PHP_METHOD(swoole_connection_iterator, offsetExists);
static PHP_METHOD(swoole_connection_iterator, offsetGet);
static PHP_METHOD(swoole_connection_iterator, offsetSet);
static PHP_METHOD(swoole_connection_iterator, offsetUnset);
static PHP_METHOD(swoole_connection_iterator, __construct);
static PHP_METHOD(swoole_connection_iterator, __destruct);

/**
 * Server\Task
 */
static PHP_METHOD(swoole_server_task, finish);

static zend_function_entry swoole_server_methods[] = {
    PHP_ME(swoole_server, __construct, arginfo_swoole_server__construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, listen, arginfo_swoole_server_listen, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_server, addlistener, listen, arginfo_swoole_server_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, on, arginfo_swoole_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getCallback, arginfo_swoole_server_getCallback, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, set, arginfo_swoole_server_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, send, arginfo_swoole_server_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendto, arginfo_swoole_server_sendto, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendwait, arginfo_swoole_server_sendwait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, exists, arginfo_swoole_server_exists, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_server, exist, exists, arginfo_swoole_server_exists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, protect, arginfo_swoole_server_protect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendfile, arginfo_swoole_server_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, close, arginfo_swoole_server_close, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, confirm, arginfo_swoole_server_confirm, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, pause, arginfo_swoole_server_pause, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, resume, arginfo_swoole_server_resume, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, task, arginfo_swoole_server_task, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, taskwait, arginfo_swoole_server_taskwait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, taskWaitMulti, arginfo_swoole_server_taskWaitMulti, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, taskCo, arginfo_swoole_server_taskCo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, finish, arginfo_swoole_server_finish, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, reload, arginfo_swoole_server_reload, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, shutdown, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stop, arginfo_swoole_server_stop, ZEND_ACC_PUBLIC)
    PHP_FALIAS(getLastError, swoole_last_error, arginfo_swoole_void)
    PHP_ME(swoole_server, heartbeat, arginfo_swoole_server_heartbeat, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getClientInfo, arginfo_swoole_getClientInfo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getClientList, arginfo_swoole_getClientList, ZEND_ACC_PUBLIC)
    //psr-0 style
    PHP_MALIAS(swoole_server, connection_info, getClientInfo, arginfo_swoole_getClientInfo, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_server, connection_list, getClientList, arginfo_swoole_getClientList, ZEND_ACC_PUBLIC)
    //process
    PHP_ME(swoole_server, sendMessage, arginfo_swoole_server_sendMessage, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, addProcess, arginfo_swoole_server_addProcess, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_server, getSocket, arginfo_swoole_server_getSocket, ZEND_ACC_PUBLIC)
#endif
#ifdef SW_BUFFER_RECV_TIME
    PHP_ME(swoole_server, getReceivedTime, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_server, bind, arginfo_swoole_server_bind, ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};

static const zend_function_entry swoole_connection_iterator_methods[] =
{
    PHP_ME(swoole_connection_iterator, __construct,  arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, __destruct,  arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, rewind,      arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, next,        arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, current,     arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, key,         arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, valid,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, count,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetExists,    arginfo_swoole_connection_iterator_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetGet,       arginfo_swoole_connection_iterator_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetSet,       arginfo_swoole_connection_iterator_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetUnset,     arginfo_swoole_connection_iterator_offsetUnset, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_server_task_methods[] =
{
    PHP_ME(swoole_server_task, finish, arginfo_swoole_server_finish, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

zend_class_entry *swoole_server_ce;
zend_object_handlers swoole_server_handlers;

zend_class_entry *swoole_connection_iterator_ce;
static zend_object_handlers swoole_connection_iterator_handlers;

static zend_class_entry *swoole_server_task_ce;
static zend_object_handlers swoole_server_task_handlers;

static int php_swoole_task_finish(swServer *serv, zval *data, swEventData *current_task);
static void php_swoole_onPipeMessage(swServer *serv, swEventData *req);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onWorkerStart(swServer *, int worker_id);
static void php_swoole_onWorkerStop(swServer *, int worker_id);
static void php_swoole_onWorkerExit(swServer *serv, int worker_id);
static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker);
static int php_swoole_onTask(swServer *, swEventData *task);
static int php_swoole_onTaskCo(swServer *, swEventData *task);
static int php_swoole_onFinish(swServer *, swEventData *task);
static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo);
static void php_swoole_onManagerStart(swServer *serv);
static void php_swoole_onManagerStop(swServer *serv);

static void php_swoole_onSendTimeout(swTimer *timer, swTimer_node *tnode);
static int php_swoole_server_send_resume(swServer *serv, php_coro_context *context, int fd);
static void php_swoole_task_onTimeout(swTimer *timer, swTimer_node *tnode);
static int php_swoole_server_dispatch_func(swServer *serv, swConnection *conn, swSendData *data);
static zval* php_swoole_server_add_port(swServer *serv, swListenPort *port);

static inline zend_bool php_swoole_server_isset_callback(swListenPort *port, int event_type)
{
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (property->callbacks[event_type] || server_port_list.primary_port->callbacks[event_type])
    {
        return SW_TRUE;
    }
    else
    {
        return SW_FALSE;
    }
}

static void swoole_server_task_free_object(zend_object *object)
{
    uint32_t handle = object->handle;
    zval _zobject, *zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    swDataHead *info = (swDataHead *) swoole_get_property_by_handle(handle, 0);
    efree(info);
    swoole_set_property_by_handle(handle, 0, NULL);
    swoole_set_object_by_handle(handle, NULL);
    zend_object_std_dtor(object);
}

static zend_object *swoole_server_task_create_object(zend_class_entry *ce)
{
    zend_object *object;
    object = zend_objects_new(ce);
    object->handlers = &swoole_server_task_handlers;
    object_properties_init(object, ce);

    swDataHead *info = (swDataHead *) emalloc(sizeof(swDataHead));
    swoole_set_property_by_handle(object->handle, 0, info);

    return object;
}

static sw_inline zend_bool is_enable_coroutine(swServer *serv)
{
    if (swIsTaskWorker())
    {
        return serv->task_enable_coroutine;
    }
    else
    {
        return serv->enable_coroutine;
    }
}

void swoole_server_rshutdown()
{
    if (!SwooleG.serv)
    {
        return;
    }

    swServer *serv = SwooleG.serv;

    swWorker_clean_pipe_buffer(serv);

    if (serv->gs->start > 0)
    {
        if (PG(last_error_message))
        {
            switch (PG(last_error_type))
            {
            case E_ERROR:
            case E_CORE_ERROR:
            case E_USER_ERROR:
            case E_COMPILE_ERROR:
                swoole_error_log(SW_LOG_ERROR, SW_ERROR_PHP_FATAL_ERROR, "Fatal error: %s in %s on line %d", PG(last_error_message),
                        PG(last_error_file)?PG(last_error_file):"-", PG(last_error_lineno));
                break;
            default:
                break;
            }
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SERVER_WORKER_TERMINATED, "worker process is terminated by exit()/die()");
        }
    }
}

void swoole_server_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_server, "Swoole\\Server", "swoole_server", NULL, swoole_server_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_server, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_server);

    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "after", &swoole_server_ce->function_table, "after");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "tick", &swoole_server_ce->function_table, "tick");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "clear", &swoole_server_ce->function_table, "clearTimer");

    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "defer", &swoole_server_ce->function_table, "defer");

    SW_INIT_CLASS_ENTRY(swoole_server_task, "Swoole\\Server\\Task", "swoole_server_task", NULL, swoole_server_task_methods);
    swoole_server_task_ce->ce_flags |= ZEND_ACC_FINAL;
    SW_SET_CLASS_SERIALIZABLE(swoole_server_task, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_server_task, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server_task, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_AND_FREE(swoole_server_task, swoole_server_task_create_object, swoole_server_task_free_object);

    SW_INIT_CLASS_ENTRY(swoole_connection_iterator, "Swoole\\Connection\\Iterator", "swoole_connection_iterator", NULL, swoole_connection_iterator_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_connection_iterator, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_connection_iterator, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_connection_iterator, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_connection_iterator);
    zend_class_implements(swoole_connection_iterator_ce, 2, zend_ce_iterator, zend_ce_arrayaccess);
#ifdef SW_HAVE_COUNTABLE
    zend_class_implements(swoole_connection_iterator_ce, 1, zend_ce_countable);
#endif

    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onStart"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onShutdown"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerStart"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerStop"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerExit"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerError"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onTask"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onFinish"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onManagerStart"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onManagerStop"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onPipeMessage"), ZEND_ACC_PRIVATE);

    zend_declare_property_null(swoole_server_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("connections"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_server_ce, ZEND_STRL("host"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("mode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("ports"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("master_pid"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("manager_pid"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("worker_id"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_server_ce, ZEND_STRL("taskworker"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_ce, ZEND_STRL("worker_pid"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_server_task_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("id"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("worker_id"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_DISCARD_PACKET", SW_DISPATCH_RESULT_DISCARD_PACKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_CLOSE_CONNECTION", SW_DISPATCH_RESULT_CLOSE_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_USERFUNC_FALLBACK", SW_DISPATCH_RESULT_USERFUNC_FALLBACK);
}

zend_fcall_info_cache* php_swoole_server_get_fci_cache(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    swoole_server_port_property *property;
    zend_fcall_info_cache* fci_cache;

    if (unlikely(!port))
    {
        swWarn("invalid server_fd[%d]", server_fd);
        return NULL;
    }
    if ((property = (swoole_server_port_property *) port->ptr) && (fci_cache = property->caches[event_type]))
    {
        return fci_cache;
    }
    else
    {
        return server_port_list.primary_port->caches[event_type];
    }
}

static int php_swoole_create_dir(const char* path, size_t length)
{
    if (access(path, F_OK) == 0)
    {
        return 0;
    }
#if 1
    return php_stream_mkdir(path, 0777, PHP_STREAM_MKDIR_RECURSIVE | REPORT_ERRORS, NULL) ? 0 : -1;
#else
    int     startpath;
    int     endpath;
    int     i            = 0;
    int     pathlen      = length;
    char    curpath[128] = {0};
    if ('/' != path[0])
    {
        if (getcwd(curpath, sizeof(curpath)) == NULL)
        {
            php_swoole_sys_error(E_WARNING, "getcwd() failed");
            return -1;
        }
        strcat(curpath, "/");
        startpath   = strlen(curpath);
        strcat(curpath, path);
        if (path[pathlen] != '/')
        {
            strcat(curpath, "/");
        }
        endpath = strlen(curpath);
    }
    else
    {
        strcpy(curpath, path);
        if (path[pathlen] != '/')
        {
            strcat(curpath, "/");
        }
        startpath    = 1;
        endpath      = strlen(curpath);
    }
    for (i = startpath; i < endpath ; i++ )
    {
        if ('/' == curpath[i])
        {
            curpath[i] = '\0';
            if (access(curpath, F_OK) != 0)
            {
                if (mkdir(curpath, 0755) == -1)
                {
                    php_swoole_sys_error(E_WARNING, "mkdir(%s, 0755)", path);
                    return -1;
                }
            }
            curpath[i] = '/';
        }
    }
    return 0;
#endif
}

int php_swoole_task_pack(swEventData *task, zval *data)
{
    smart_str serialized_data = { 0 };
    php_serialize_data_t var_hash;

    task->info.type = SW_EVENT_TASK;
    //field fd save task_id
    task->info.fd = php_swoole_task_id++;
    if (unlikely(php_swoole_task_id >= INT_MAX))
    {
        php_swoole_task_id = 0;
    }
    //field reactor_id save the worker_id
    task->info.reactor_id = SwooleWG.id;
    swTask_type(task) = 0;

    char *task_data_str;
    int task_data_len = 0;
    //need serialize
    if (Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(task) |= SW_TASK_SERIALIZE;

        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, data, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

        if (!serialized_data.s)
        {
            return -1;
        }
        task_data_str = ZSTR_VAL(serialized_data.s);
        task_data_len = ZSTR_LEN(serialized_data.s);
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    if (task_data_len >= (int)(SW_IPC_MAX_SIZE - sizeof(task->info)))
    {
        if (swTaskWorker_large_pack(task, task_data_str, task_data_len) < 0)
        {
            php_swoole_fatal_error(E_WARNING, "large task pack failed");
            task->info.fd = SW_ERR;
            task->info.len = 0;
        }
    }
    else
    {
        memcpy(task->data, task_data_str, task_data_len);
        task->info.len = task_data_len;
    }
    smart_str_free(&serialized_data);
    return task->info.fd;
}

void php_swoole_get_recv_data(swServer *serv, zval *zdata, swEventData *req, char *header, uint32_t header_length)
{
    char *data = NULL;

    size_t length = swWorker_get_data(serv, req, &data);
    if (header_length >= length)
    {
        ZVAL_EMPTY_STRING(zdata);
    }
    else
    {
        ZVAL_STRINGL(zdata, data + header_length, length - header_length);
    }
    if (header_length > 0)
    {
        memcpy(header, data, header_length);
    }
}

size_t php_swoole_get_send_data(zval *zdata, char **str)
{
    size_t length;

    if (Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_buffer_ce))
    {
        swString *str_buffer = (swString *) swoole_get_object(zdata);
        length = str_buffer->length - str_buffer->offset;
        *str = str_buffer->str + str_buffer->offset;
    }
    else
    {
        convert_to_string(zdata);
        length = Z_STRLEN_P(zdata);
        *str = Z_STRVAL_P(zdata);
    }

    return length;
}

static sw_inline int php_swoole_check_task_param(swServer *serv, zend_long dst_worker_id)
{
    if (UNEXPECTED(serv->task_worker_num == 0))
    {
        php_swoole_fatal_error(E_WARNING, "task method can't be executed without task worker");
        return SW_ERR;
    }
    if (UNEXPECTED(dst_worker_id >= serv->task_worker_num))
    {
        php_swoole_fatal_error(E_WARNING, "worker_id must be less than task_worker_num[%u]", serv->task_worker_num);
        return SW_ERR;
    }
    if (UNEXPECTED(swIsTaskWorker()))
    {
        php_swoole_fatal_error(E_WARNING, "Server->task() cannot use in the task-worker");
        return SW_ERR;
    }
    return SW_OK;
}

zval* php_swoole_task_unpack(swEventData *task_result)
{
    zval *result_data, *result_unserialized_data;
    char *result_data_str;
    int result_data_len = 0;
    php_unserialize_data_t var_hash;
    swString *large_packet;

    /**
     * Large result package
     */
    if (swTask_type(task_result) & SW_TASK_TMPFILE)
    {
        large_packet = swTaskWorker_large_unpack(task_result);
        /**
         * unpack failed
         */
        if (large_packet == NULL)
        {
            return NULL;
        }
        result_data_str = large_packet->str;
        result_data_len = large_packet->length;
    }
    else
    {
        result_data_str = task_result->data;
        result_data_len = task_result->info.len;
    }

    if (swTask_type(task_result) & SW_TASK_SERIALIZE)
    {
        result_unserialized_data = sw_malloc_zval();

        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        //unserialize success
        if (php_var_unserialize(*&result_unserialized_data, (const unsigned char **) &result_data_str,
                (const unsigned char *) (result_data_str + result_data_len), &var_hash))
        {
            result_data = result_unserialized_data;
        }
        //failed
        else
        {
            result_data = sw_malloc_zval();
            ZVAL_STRINGL(result_data, result_data_str, result_data_len);
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    }
    else
    {
        result_data = sw_malloc_zval();
        ZVAL_STRINGL(result_data, result_data_str, result_data_len);
    }
    return result_data;
}

static void php_swoole_task_wait_co(swServer *serv, swEventData *req, double timeout, int dst_worker_id, INTERNAL_FUNCTION_PARAMETERS)
{
    swTask_type(req) |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);

    swTaskCo *task_co = (swTaskCo *) emalloc(sizeof(swTaskCo));
    bzero(task_co, sizeof(swTaskCo));
    task_co->count = 1;
    task_co->context.state = SW_CORO_CONTEXT_RUNNING;
    Z_LVAL(task_co->context.coro_params) = req->info.fd;

    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
    if (swProcessPool_dispatch(&serv->gs->task_workers, req, &dst_worker_id) < 0)
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        RETURN_FALSE;
    }
    else
    {
        task_coroutine_map[req->info.fd] = task_co;
    }

    long ms = (long) (timeout * 1000);
    swTimer_node *timer = swTimer_add(&SwooleG.timer, ms, 0, task_co, php_swoole_task_onTimeout);
    if (timer)
    {
        task_co->timer = timer;
    }
    PHPCoroutine::yield_m(return_value, &task_co->context);
}

static void php_swoole_task_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swTaskCo *task_co = (swTaskCo *) tnode->data;
    php_coro_context *context = &task_co->context;
    zval *retval = NULL;

    //Server->taskwait, single task
    if (task_co->list == NULL)
    {
        zval result;
        ZVAL_FALSE(&result);
        int ret = PHPCoroutine::resume_m(context, &result, retval);
        if (ret == SW_CORO_ERR_END && retval)
        {
            zval_ptr_dtor(retval);
        }
        task_coroutine_map.erase(Z_LVAL(context->coro_params));
        efree(task_co);
        return;
    }

    uint32_t i;
    zval *result = task_co->result;

    for (i = 0; i < task_co->count; i++)
    {
        if (!zend_hash_index_exists(Z_ARRVAL_P(result), i))
        {
            add_index_bool(result, i, 0);
            task_coroutine_map.erase(task_co->list[i]);
        }
    }

    int ret = PHPCoroutine::resume_m(context, result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    sw_zval_free(result);
    efree(task_co);
}

static zval* php_swoole_server_add_port(swServer *serv, swListenPort *port)
{
    zval *port_object;

    port_object = sw_malloc_zval();
    object_init_ex(port_object, swoole_server_port_ce);
    server_port_list.zobjects[server_port_list.num++] = port_object;

    swoole_server_port_property *property = (swoole_server_port_property *) ecalloc(1, sizeof(swoole_server_port_property));
    property->serv = serv;
    property->port = port;
    swoole_set_property(port_object, 0, property);
    swoole_set_object(port_object, port);

    port->ptr = property;

    zend_update_property_string(swoole_server_port_ce, port_object, ZEND_STRL("host"), port->host);
    zend_update_property_long(swoole_server_port_ce, port_object, ZEND_STRL("port"), port->port);
    zend_update_property_long(swoole_server_port_ce, port_object, ZEND_STRL("type"), port->type);
    zend_update_property_long(swoole_server_port_ce, port_object, ZEND_STRL("sock"), port->sock);

    zval connection_iterator;
    object_init_ex(&connection_iterator, swoole_connection_iterator_ce);
    zend_update_property(swoole_server_port_ce, port_object, ZEND_STRL("connections"), &connection_iterator);

    swConnectionIterator *i = (swConnectionIterator *) ecalloc(1, sizeof(swConnectionIterator));
    i->serv = serv;
    i->port = port;
    swoole_set_object(&connection_iterator, i);
    zval_ptr_dtor(&connection_iterator);

    (void) add_next_index_zval(server_port_list.zports, port_object);
    Z_TRY_ADDREF_P(port_object);

    return port_object;
}

void php_swoole_server_before_start(swServer *serv, zval *zobject)
{
    /**
     * create swoole server
     */
    if (swServer_create(serv) < 0)
    {
        php_swoole_fatal_error(E_ERROR, "failed to create the server. Error: %s", sw_error);
        return;
    }

    swTraceLog(SW_TRACE_SERVER, "Create Swoole\\Server: host=%s, port=%d, mode=%d, type=%d", serv->listen_list->host, (int) serv->listen_list->port, serv->factory_mode, (int) serv->listen_list->type);

    serv->ptr2 = sw_zval_dup(zobject);

    if (serv->enable_coroutine)
    {
        serv->reload_async = 1;
    }

    if (serv->send_yield)
    {
        if (serv->onClose == NULL)
        {
            serv->onClose = php_swoole_onClose;
        }
    }

    /**
     * Master Process ID
     */
    zend_update_property_long(swoole_server_ce, zobject, ZEND_STRL("master_pid"), getpid());

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_ce, zobject, ZEND_STRL("setting"), 0);
#ifdef HT_ALLOW_COW_VIOLATION
    HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(zsetting));
#endif

    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("worker_num")))
    {
        add_assoc_long(zsetting, "worker_num", serv->worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("task_worker_num")))
    {
        add_assoc_long(zsetting, "task_worker_num", serv->task_worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("buffer_output_size")))
    {
        add_assoc_long(zsetting, "buffer_output_size", serv->buffer_output_size);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("max_connection")))
    {
        add_assoc_long(zsetting, "max_connection", serv->max_connection);
    }
#ifdef HAVE_PTRACE
    //trace request
    if (serv->request_slowlog_file && (serv->trace_event_worker || serv->task_worker_num > 0))
    {
        serv->manager_alarm = serv->request_slowlog_timeout;
        if (swServer_add_hook(serv, SW_SERVER_HOOK_MANAGER_TIMER, php_swoole_trace_check, 1) < 0)
        {
            php_swoole_fatal_error(E_ERROR, "Unable to add server hook");
            return;
        }
    }
#endif

    int i;
    zval *zport_object;
    zval *zport_setting;
    swListenPort *port;
    bool find_http_port = false;

    for (i = 1; i < server_port_list.num; i++)
    {
        zport_object = server_port_list.zobjects[i];
        zport_setting = sw_zend_read_property(swoole_server_port_ce, zport_object, ZEND_STRL("setting"), 0);
        //use swoole_server->setting
        if (zport_setting == NULL || ZVAL_IS_NULL(zport_setting))
        {
            Z_TRY_ADDREF_P(zport_object);
            sw_zend_call_method_with_1_params(zport_object, swoole_server_port_ce, NULL, "set", NULL, zsetting);
        }
    }

    for (i = 0; i < server_port_list.num; i++)
    {
        zport_object = server_port_list.zobjects[i];
        port = (swListenPort *) swoole_get_object(zport_object);

        if (swSocket_is_dgram(port->type) && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onPacket))
        {
            php_swoole_fatal_error(E_ERROR, "require onPacket callback");
            return;
        }

#ifdef SW_USE_OPENSSL
        if (port->ssl_option.verify_peer && !port->ssl_option.client_cert_file)
        {
            php_swoole_fatal_error(E_ERROR, "server open verify peer require client_cert_file config");
            return;
        }
#endif

        if (!port->open_http_protocol)
        {
            port->open_http_protocol = port->open_websocket_protocol || port->open_http2_protocol;
        }
        if (port->open_http_protocol)
        {
            find_http_port = true;
            if (port->open_websocket_protocol)
            {
                if (!php_swoole_server_isset_callback(port, SW_SERVER_CB_onMessage))
                {
                    php_swoole_fatal_error(E_ERROR, "require onMessage callback");
                    return;
                }
            }
            else if (port->open_http_protocol && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onRequest))
            {
                php_swoole_fatal_error(E_ERROR, "require onRequest callback");
                return;
            }
        }
        else if (!port->open_redis_protocol)
        {
            if (swSocket_is_stream(port->type) && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onReceive))
            {
                php_swoole_fatal_error(E_ERROR, "require onReceive callback");
                return;
            }
        }
    }

    if (find_http_port)
    {
        serv->onReceive = php_swoole_http_onReceive;
        serv->onClose = php_swoole_http_onClose;
        if (!instanceof_function(Z_OBJCE_P(zobject), swoole_http_server_ce))
        {
            php_swoole_error(E_WARNING, "use %s class and open http related protocols may lead to some errors (inconsistent class type)", SW_Z_OBJCE_NAME_VAL_P(zobject));
        }
        php_swoole_http_server_init_global_variant();
    }
}

void php_swoole_server_register_callbacks(swServer *serv)
{
    /*
     * optional callback
     */
    if (server_callbacks[SW_SERVER_CB_onStart] != NULL)
    {
        serv->onStart = php_swoole_onStart;
    }
    serv->onShutdown = php_swoole_onShutdown;
    /**
     * require callback, set the master/manager/worker PID
     */
    serv->onWorkerStart = php_swoole_onWorkerStart;

    if (server_callbacks[SW_SERVER_CB_onWorkerStop] != NULL)
    {
        serv->onWorkerStop = php_swoole_onWorkerStop;
    }
    if (server_callbacks[SW_SERVER_CB_onWorkerExit] != NULL)
    {
        serv->onWorkerExit = php_swoole_onWorkerExit;
    }
    /**
     * Task Worker
     */
    if (server_callbacks[SW_SERVER_CB_onTask] != NULL)
    {
        if (serv->task_enable_coroutine)
        {
            serv->onTask = php_swoole_onTaskCo;
        }
        else
        {
            serv->onTask = php_swoole_onTask;
        }
        serv->onFinish = php_swoole_onFinish;
    }
    if (server_callbacks[SW_SERVER_CB_onWorkerError] != NULL)
    {
        serv->onWorkerError = php_swoole_onWorkerError;
    }
    if (server_callbacks[SW_SERVER_CB_onManagerStart] != NULL)
    {
        serv->onManagerStart = php_swoole_onManagerStart;
    }
    if (server_callbacks[SW_SERVER_CB_onManagerStop] != NULL)
    {
        serv->onManagerStop = php_swoole_onManagerStop;
    }
    if (server_callbacks[SW_SERVER_CB_onPipeMessage] != NULL)
    {
        serv->onPipeMessage = php_swoole_onPipeMessage;
    }
    if (serv->send_yield)
    {
        serv->onBufferEmpty = php_swoole_onBufferEmpty;
    }
}

static int php_swoole_task_finish(swServer *serv, zval *data, swEventData *current_task)
{
    int flags = 0;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;
    char *data_str;
    int data_len = 0;
    int ret;

    //need serialize
    if (Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        flags |= SW_TASK_SERIALIZE;

        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, data, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        data_str = ZSTR_VAL(serialized_data.s);
        data_len = ZSTR_LEN(serialized_data.s);

    }
    else
    {
        data_str = Z_STRVAL_P(data);
        data_len = Z_STRLEN_P(data);
    }

    ret = swTaskWorker_finish(serv, data_str, data_len, flags, current_task);
    smart_str_free(&serialized_data);
    return ret;
}

static void php_swoole_onPipeMessage(swServer *serv, swEventData *req)
{
    zend_fcall_info_cache *fci_cache = server_callbacks[SW_SERVER_CB_onPipeMessage];
    zval *zserv = (zval *) serv->ptr2;
    zval *zdata = php_swoole_task_unpack(req);
    zval args[3];

    if (UNEXPECTED(zdata == NULL))
    {
        return;
    }
    swTraceLog(SW_TRACE_SERVER, "PipeMessage: fd=%d|len=%d|from_id=%d|data=%.*s\n", req->info.fd, req->info.len, req->info.reactor_id, req->info.len, req->data);
    args[0] = *zserv;
    ZVAL_LONG(&args[1], (zend_long) req->info.reactor_id);
    args[2] = *zdata;

    if (UNEXPECTED(!zend::function::call(fci_cache, 3, args, NULL, is_enable_coroutine(serv))))
    {
        php_swoole_error(E_WARNING, "%s->onPipeMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    sw_zval_free(zdata);
}

int php_swoole_onReceive(swServer *serv, swEventData *req)
{
    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onReceive);
    zval *zserv = (zval *) serv->ptr2;
    zval args[4];

    args[0] = *zserv;
    ZVAL_LONG(&args[1], (zend_long) req->info.fd);
    ZVAL_LONG(&args[2], (zend_long) req->info.reactor_id);
    php_swoole_get_recv_data(serv, &args[3], req, NULL, 0);

    if (UNEXPECTED(!zend::function::call(fci_cache, 4, args, NULL, SwooleG.enable_coroutine)))
    {
        php_swoole_error(E_WARNING, "%s->onReceive handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        serv->close(serv, req->info.fd, 0);
    }

    zval_ptr_dtor(&args[3]);
    return SW_OK;
}

int php_swoole_onPacket(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval zaddr;

    char *buffer;
    swWorker_get_data(serv, req, &buffer);

    array_init(&zaddr);

    swDgramPacket *packet = (swDgramPacket*) buffer;

    add_assoc_long(&zaddr, "server_socket", req->info.server_fd);
    swConnection *from_sock = swServer_connection_get(serv, req->info.server_fd);
    if (from_sock)
    {
        add_assoc_long(&zaddr, "server_port", swConnection_get_port(from_sock));
    }

    char address[INET6_ADDRSTRLEN];

    dgram_server_socket = req->info.server_fd;

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        inet_ntop(AF_INET, &packet->info.addr.inet_v4.sin_addr, address, sizeof(address));
        add_assoc_string(&zaddr, "address", address);
        add_assoc_long(&zaddr, "port", ntohs(packet->info.addr.inet_v4.sin_port));
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        inet_ntop(AF_INET6, &packet->info.addr.inet_v6.sin6_addr, address, sizeof(address));
        add_assoc_string(&zaddr, "address", address);
        add_assoc_long(&zaddr, "port", packet->info.addr.inet_v6.sin6_port);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        add_assoc_string(&zaddr, "address", packet->info.addr.un.sun_path);
    }

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onPacket);
    zval args[3];
    args[0] = *zserv;
    ZVAL_STRINGL(&args[1], packet->data, packet->length);
    args[2] = zaddr;

    if (UNEXPECTED(!zend::function::call(fci_cache, 3, args, NULL, SwooleG.enable_coroutine)))
    {
        php_swoole_error(E_WARNING, "%s->onPipeMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    zval_ptr_dtor(&zaddr);
    zval_ptr_dtor(&args[1]);

    return SW_OK;
}

static int php_swoole_onTask(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zdata = php_swoole_task_unpack(req);

    if (zdata == NULL)
    {
        return SW_ERR;
    }
    sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);

    zval args[4];
    zval retval;

    args[0] = *zserv;
    ZVAL_LONG(&args[1], (zend_long) req->info.fd);
    ZVAL_LONG(&args[2], (zend_long) req->info.reactor_id);
    args[3] = *zdata;


    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onTask], 4, args, &retval, false)))
    {
        php_swoole_error(E_WARNING, "%s->onTask handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    sw_zval_free(zdata);

    if (!ZVAL_IS_NULL(&retval))
    {
        php_swoole_task_finish(serv, &retval, req);
        zval_ptr_dtor(&retval);
    }

    return SW_OK;
}

static int php_swoole_onTaskCo(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;

    sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);

    zval *zdata = php_swoole_task_unpack(req);
    if (zdata == NULL)
    {
        return SW_ERR;
    }

    zval ztask;
    object_init_ex(&ztask, swoole_server_task_ce);
    swoole_set_object(&ztask, serv);

    swDataHead *info = (swDataHead *) swoole_get_property(&ztask, 0);
    *info = req->info;

    zend_update_property_long(swoole_server_task_ce, &ztask, ZEND_STRL("worker_id"), (long) req->info.reactor_id);
    zend_update_property_long(swoole_server_task_ce, &ztask, ZEND_STRL("id"), (long) req->info.fd);
    zend_update_property(swoole_server_task_ce, &ztask, ZEND_STRL("data"), zdata);
    zend_update_property_long(swoole_server_task_ce, &ztask, ZEND_STRL("flags"), (long) swTask_type(req));

    zval args[2];
    args[0] = *zserv;
    args[1] = ztask;

    if (UNEXPECTED(PHPCoroutine::create(server_callbacks[SW_SERVER_CB_onTask], 2, args) < 0))
    {
        php_swoole_error(E_WARNING, "%s->onTaskCo handler error", ZSTR_VAL(swoole_server_ce->name));
    }

    zval_ptr_dtor(&ztask);
    sw_zval_free(zdata);

    return SW_OK;
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[3];

    zval *zdata = php_swoole_task_unpack(req);
    if (zdata == NULL)
    {
        return SW_ERR;
    }

    if (swTask_type(req) & SW_TASK_COROUTINE)
    {
        int task_id = req->info.fd;
        auto task_co_iterator = task_coroutine_map.find(task_id);

        if (task_co_iterator == task_coroutine_map.end())
        {
            swWarn("task[%d] has expired", task_id);
            _fail:
            sw_zval_free(zdata);
            return SW_OK;
        }
        swTaskCo *task_co = task_co_iterator->second;
        //Server->taskwait
        if (task_co->list == NULL)
        {
            zval *retval = NULL;
            if (task_co->timer)
            {
                swTimer_del(&SwooleG.timer, task_co->timer);
            }
            php_coro_context *context = &task_co->context;
            int ret = PHPCoroutine::resume_m(context, zdata, retval);
            if (ret == SW_CORO_ERR_END && retval)
            {
                zval_ptr_dtor(retval);
            }
            efree(task_co);
            sw_zval_free(zdata);
            task_coroutine_map.erase(task_id);
            return SW_OK;
        }
        //Server->taskCo
        uint32_t i;
        int task_index = -1;
        zval *result = task_co->result;
        for (i = 0; i < task_co->count; i++)
        {
            if (task_co->list[i] == task_id)
            {
                task_index = i;
                break;
            }
        }
        if (task_index < 0)
        {
            php_swoole_fatal_error(E_WARNING, "task[%d] is invalid", task_id);
            goto _fail;
        }
        (void) add_index_zval(result, task_index, zdata);
        efree(zdata);
        task_coroutine_map.erase(task_id);

        if (php_swoole_array_length(result) == task_co->count)
        {
            zval *retval = NULL;
            if (task_co->timer)
            {
                swTimer_del(&SwooleG.timer, task_co->timer);
                task_co->timer = NULL;
            }
            php_coro_context *context = &task_co->context;
            int ret = PHPCoroutine::resume_m(context, result, retval);
            if (ret == SW_CORO_ERR_END && retval)
            {
                zval_ptr_dtor(retval);
            }
            sw_zval_free(result);
            efree(task_co);
        }
        return SW_OK;
    }

    args[0] = *zserv;
    ZVAL_LONG(&args[1], (zend_long) req->info.fd);
    args[2] = *zdata;

    zend_fcall_info_cache *fci_cache = NULL;
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        auto callback_iterator = task_callbacks.find(req->info.fd);
        if (callback_iterator == task_callbacks.end())
        {
            swTask_type(req) = swTask_type(req) & (~SW_TASK_CALLBACK);
        }
        else
        {
            fci_cache = &callback_iterator->second;
        }
    }
    else
    {
        fci_cache = server_callbacks[SW_SERVER_CB_onFinish];
    }
    if (UNEXPECTED(fci_cache == NULL))
    {
        sw_zval_free(zdata);
        php_swoole_fatal_error(E_WARNING, "require onFinish callback");
        return SW_ERR;
    }
    if (UNEXPECTED(!zend::function::call(fci_cache, 3, args, NULL, SwooleG.enable_coroutine)))
    {
        php_swoole_error(E_WARNING, "%s->onFinish handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        sw_zend_fci_cache_discard(fci_cache);
        task_callbacks.erase(req->info.fd);
    }
    sw_zval_free(zdata);

    return SW_OK;
}

static void php_swoole_onStart(swServer *serv)
{
    swServer_lock(serv);
    zval *zserv = (zval *) serv->ptr2;
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);
    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onStart], 1, zserv, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    swServer_unlock(serv);
}

static void php_swoole_onManagerStart(swServer *serv)
{
    zval *zserv = (zval *) serv->ptr2;
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);
    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onManagerStart], 1, zserv, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onManagerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_onManagerStop(swServer *serv)
{
    zval *zserv = (zval *) serv->ptr2;
    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onManagerStop], 1, zserv, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onManagerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_onShutdown(swServer *serv)
{
    swServer_lock(serv);
    zval *zserv = (zval *) serv->ptr2;
    if (server_callbacks[SW_SERVER_CB_onShutdown] != NULL)
    {
        if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onShutdown], 1, zserv, NULL, false)))
        {
            php_swoole_error(E_WARNING, "%s->onShutdown handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
    swServer_unlock(serv);
}

static void php_swoole_onWorkerStart(swServer *serv, int worker_id)
{
    zend_fcall_info_cache *fci_cache = server_callbacks[SW_SERVER_CB_onWorkerStart];
    zval *zserv = (zval *) serv->ptr2;

    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("worker_id"), worker_id);
    zend_update_property_bool(swoole_server_ce, zserv, ZEND_STRL("taskworker"), worker_id >= serv->worker_num);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("worker_pid"), getpid());

    if (!is_enable_coroutine(serv))
    {
        SwooleG.enable_coroutine = 0;
        PHPCoroutine::disable_hook();
    }

    if (fci_cache)
    {
        zval args[2];
        args[0] = *zserv;
        ZVAL_LONG(&args[1], worker_id);
        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, is_enable_coroutine(serv))))
        {
            php_swoole_error(E_WARNING, "%s->onWorkerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

static void php_swoole_onWorkerStop(swServer *serv, int worker_id)
{
    if (SwooleWG.shutdown)
    {
        return;
    }
    SwooleWG.shutdown = 1;

    zval *zserv = (zval *) serv->ptr2;
    zval args[2];
    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);
    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onWorkerStop], 2, args, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onWorkerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_onWorkerExit(swServer *serv, int worker_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[2];
    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);
    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onWorkerExit], 2, args, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onWorkerExit handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker)
{
    if (serv->enable_coroutine)
    {
        SwooleG.enable_coroutine = 1;
    }
    zval *object = (zval *) worker->ptr;
    zend_update_property_long(swoole_process_ce, object, ZEND_STRL("id"), SwooleWG.id);

    zval *zserv = (zval *) serv->ptr2;
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    php_swoole_process_start(worker, object);
}

static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[5];

    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);
    ZVAL_LONG(&args[2], worker_pid);
    ZVAL_LONG(&args[3], exit_code);
    ZVAL_LONG(&args[4], signo);

    if (UNEXPECTED(!zend::function::call(server_callbacks[SW_SERVER_CB_onWorkerError], 5, args, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onWorkerError handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

void php_swoole_onConnect(swServer *serv, swDataHead *info)
{
    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onConnect);
    if (fci_cache)
    {
        zval *zserv = (zval *) serv->ptr2;
        zval args[3];
        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);
        ZVAL_LONG(&args[2], info->reactor_id);
        if (UNEXPECTED(!zend::function::call(fci_cache, 3, args, NULL, SwooleG.enable_coroutine)))
        {
            php_swoole_error(E_WARNING, "%s->onConnect handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

void php_swoole_onClose(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;

    if (SwooleG.enable_coroutine && serv->send_yield)
    {
        unordered_map<int, list<php_coro_context *> *>::iterator _i_coros_list = send_coroutine_map.find(info->fd);
        if (_i_coros_list != send_coroutine_map.end())
        {
            list<php_coro_context *> *coros_list = _i_coros_list->second;
            if (coros_list->size() == 0)
            {
                php_swoole_fatal_error(E_WARNING, "nothing can be resumed");
            }
            else
            {
                php_coro_context *context = coros_list->front();
                coros_list->pop_front();
                SwooleG.error = ECONNRESET;
                zval_ptr_dtor(&context->coro_params);
                ZVAL_NULL(&context->coro_params);
                //resume coroutine
                php_swoole_server_send_resume(serv, context, info->fd);
                //free memory
                delete coros_list;
                send_coroutine_map.erase(info->fd);
            }
        }
    }

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onClose);
    if (fci_cache)
    {
        zval args[3];
        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);
        ZVAL_LONG(&args[2], info->reactor_id);
        if (UNEXPECTED(!zend::function::call(fci_cache, 3, args, NULL, SwooleG.enable_coroutine)))
        {
            php_swoole_error(E_WARNING, "%s->onClose handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

void php_swoole_onBufferFull(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;
    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onBufferFull);

    if (fci_cache)
    {
        zval args[2];

        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, false)))
        {
            php_swoole_error(E_WARNING, "%s->onBufferFull handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

static void php_swoole_onSendTimeout(swTimer *timer, swTimer_node *tnode)
{
    php_coro_context *context = (php_coro_context *) tnode->data;
    zval *zdata = &context->coro_params;
    zval result;
    zval *retval = NULL;

    SwooleG.error = ETIMEDOUT;
    ZVAL_FALSE(&result);

    int fd = (int) (long) context->private_data;

    unordered_map<int, list<php_coro_context *> *>::iterator _i_coros_list = send_coroutine_map.find(fd);
    if (_i_coros_list != send_coroutine_map.end())
    {
        list<php_coro_context *> *coros_list = _i_coros_list->second;
        coros_list->remove(context);
        //free memory
        if (coros_list->size() == 0)
        {
            delete coros_list;
            send_coroutine_map.erase(fd);
        }
    }
    else
    {
        swWarn("send coroutine[fd=%d] not exists", fd);
        return;
    }

    context->private_data = NULL;

    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zdata);
    efree(context);
}

static int php_swoole_server_send_resume(swServer *serv, php_coro_context *context, int fd)
{
    char *data;
    zval *zdata = &context->coro_params;
    zval result;
    zval *retval = NULL;

    if (ZVAL_IS_NULL(zdata))
    {
        _fail:
        ZVAL_FALSE(&result);
    }
    else
    {
        size_t length = php_swoole_get_send_data(zdata, &data);
        if (length == 0)
        {
            goto _fail;
        }
        int ret = serv->send(serv, fd, data, length);
        if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && serv->send_yield)
        {
            return SW_AGAIN;
        }
        ZVAL_BOOL(&result, ret == SW_OK);
    }

    if (context->timer)
    {
        swTimer_del(&SwooleG.timer, (swTimer_node *) context->timer);
        context->timer = NULL;
    }

    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zdata);
    efree(context);
    return SW_OK;
}

void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value)
{
    list<php_coro_context *> *coros_list;
    auto coroutine_iterator = send_coroutine_map.find(fd);

    if (coroutine_iterator == send_coroutine_map.end())
    {
        coros_list = new list<php_coro_context *>;
        send_coroutine_map[fd] = coros_list;
    }
    else
    {
        coros_list = coroutine_iterator->second;
    }

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));
    coros_list->push_back(context);
    if (serv->send_timeout > 0)
    {
        context->private_data = (void*) (long) fd;
        context->timer = swTimer_add(&SwooleG.timer, (long) (serv->send_timeout * 1000), 0, context, php_swoole_onSendTimeout);
    }
    else
    {
        context->timer = NULL;
    }
    context->coro_params = *zdata;
    PHPCoroutine::yield_m(return_value, context);
}

static int php_swoole_server_dispatch_func(swServer *serv, swConnection *conn, swSendData *data)
{
    swServer_lock(serv);

    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache*) serv->private_data_3;
    zval args[4];
    zval *zserv = &args[0], *zfd = &args[1], *ztype = &args[2], *zdata = NULL;
    zval retval;
    int worker_id = -1;

    *zserv = *((zval *) serv->ptr2);
    ZVAL_LONG(zfd, (zend_long) (conn ? conn->session_id : data->info.fd));
    ZVAL_LONG(ztype, (zend_long) data->info.type);
    if (sw_zend_function_max_num_args(fci_cache->function_handler) > 3)
    {
        // TODO: reduce memory copy
        zdata = &args[3];
        ZVAL_STRINGL(zdata, data->data, data->info.len > SW_IPC_BUFFER_SIZE ? SW_IPC_BUFFER_SIZE : data->info.len);
    }
    if (UNEXPECTED(sw_zend_call_function_ex(NULL, fci_cache, zdata ? 4 : 3, args, &retval) != SUCCESS))
    {
        php_swoole_error(E_WARNING, "%s->onDispatch handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    else if (!ZVAL_IS_NULL(&retval))
    {
        worker_id = (int) zval_get_long(&retval);
        if (worker_id >= serv->worker_num)
        {
            php_swoole_fatal_error(E_WARNING, "invalid target worker-id[%d]", worker_id);
            worker_id = -1;
        }
        zval_ptr_dtor(&retval);
    }
    if (zdata)
    {
        zval_ptr_dtor(zdata);
    }

    swServer_unlock(serv);

    /* the exception should only be thrown after unlocked */
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    return worker_id;
}


void php_swoole_onBufferEmpty(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;
    zend_fcall_info_cache *fci_cache;

    if (serv->send_yield == 0)
    {
        goto _callback;
    }
    else
    {
        unordered_map<int, list<php_coro_context *> *>::iterator _i_coros_list = send_coroutine_map.find(info->fd);
        if (_i_coros_list != send_coroutine_map.end())
        {
            list<php_coro_context *> *coros_list = _i_coros_list->second;
            if (coros_list->size() == 0)
            {
                php_swoole_fatal_error(E_WARNING, "nothing can resume");
                goto _callback;
            }
            php_coro_context *context = coros_list->front();
            //resume coroutine
            if (php_swoole_server_send_resume(serv, context, info->fd) == SW_AGAIN)
            {
                return;
            }
            else
            {
                coros_list->pop_front();
                if (coros_list->size() == 0)
                {
                    delete coros_list;
                    send_coroutine_map.erase(info->fd);
                }
            }
        }
    }

    _callback:
    fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onBufferEmpty);
    if (fci_cache)
    {
        zval args[2];

        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, false)))
        {
            php_swoole_error(E_WARNING, "%s->onBufferEmpty handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

static PHP_METHOD(swoole_server, __construct)
{
    zval *zserv = ZEND_THIS;
    const char *host;
    size_t host_len = 0;
    zend_long sock_type = SW_SOCK_TCP;
    zend_long serv_port = 0;
    zend_long serv_mode = SW_MODE_PROCESS;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        zend_throw_exception_ex(swoole_exception_ce, -1, "%s can only be used in CLI mode", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;

        php_swoole_fatal_error(E_ERROR, "%s can only be used in CLI mode", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor)
    {
        zend_throw_exception_ex(swoole_exception_ce, -2, "eventLoop has already been created. unable to create %s", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    if (SwooleG.serv != NULL)
    {
        zend_throw_exception_ex(swoole_exception_ce, -3, "server is running. unable to create %s", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    swServer *serv = (swServer *) sw_malloc(sizeof (swServer));
    if (!serv)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "malloc(%ld) failed", sizeof(swServer));
        RETURN_FALSE;
    }

    swServer_init(serv);

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lll", &host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
    {
        php_swoole_fatal_error(E_ERROR, "invalid %s parameters", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    if (serv_mode != SW_MODE_BASE && serv_mode != SW_MODE_PROCESS)
    {
        php_swoole_fatal_error(E_ERROR, "invalid $mode parameters %d", (int) serv_mode);
        RETURN_FALSE;
    }

    if (serv_mode == SW_MODE_BASE)
    {
        serv->reactor_num = 1;
        serv->worker_num = 1;
    }
    serv->factory_mode = serv_mode;

    if (serv_port == 0 && strcasecmp(host, "SYSTEMD") == 0)
    {
        if (swServer_add_systemd_socket(serv) <= 0)
        {
            php_swoole_fatal_error(E_ERROR, "failed to add systemd socket");
            RETURN_FALSE;
        }
    }
    else
    {
        swListenPort *port = swServer_add_port(serv, sock_type, host, serv_port);
        if (!port)
        {
            zend_throw_exception_ex(
                swoole_exception_ce, errno,
                "failed to listen server port[%s:" ZEND_LONG_FMT "], Error: %s[%d]",
                host, serv_port, strerror(errno), errno
            );
            RETURN_FALSE;
        }
    }

    zval connection_iterator_object;
    object_init_ex(&connection_iterator_object, swoole_connection_iterator_ce);
    zend_update_property(swoole_server_ce, zserv, ZEND_STRL("connections"), &connection_iterator_object);
    zval_ptr_dtor(&connection_iterator_object);

    swConnectionIterator *i = (swConnectionIterator *) ecalloc(1, sizeof(swConnectionIterator));
    i->serv = serv;
    swoole_set_object(&connection_iterator_object, i);

    zend_update_property_stringl(swoole_server_ce, zserv, ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("port"), (long) serv->listen_list->port);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("mode"), serv->factory_mode);
    zend_update_property_long(swoole_server_ce, zserv, ZEND_STRL("type"), sock_type);
    swoole_set_object(zserv, serv);

    zval *ports = sw_malloc_zval();
    array_init(ports);
    server_port_list.zports = ports;

#ifdef HT_ALLOW_COW_VIOLATION
    HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(ports));
#endif

    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        php_swoole_server_add_port(serv, ls);
    }

    server_port_list.primary_port = (swoole_server_port_property *) serv->listen_list->ptr;

    zend_update_property(swoole_server_ce, zserv, ZEND_STRL("ports"), ports);
}

static PHP_METHOD(swoole_server, __destruct)
{
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (serv->private_data_3)
    {
        sw_zend_fci_cache_discard((zend_fcall_info_cache *) serv->private_data_3);
        efree(serv->private_data_3);
    }
    if (serv->ptr2)
    {
        efree(serv->ptr2);
        serv->ptr2 = NULL;
    }
    for (int i = 0; i < PHP_SWOOLE_SERVER_CALLBACK_NUM; i++)
    {
        zend_fcall_info_cache *fci_cache = server_callbacks[i];
        if (fci_cache)
        {
            efree(fci_cache);
            server_callbacks[i] = NULL;
        }
    }
    for (int i = 0; i < server_port_list.num; i++)
    {
        sw_zval_free(server_port_list.zobjects[i]);
        server_port_list.zobjects[i] = NULL;
    }
    sw_zval_free(server_port_list.zports);
    server_port_list.zports = NULL;
}

static PHP_METHOD(swoole_server, set)
{
    zval *zserv = ZEND_THIS;
    zval *zset = NULL, *v;
    HashTable *vht;

    swServer *serv = (swServer *) swoole_get_object(zserv);
    if (serv->gs->start > 0)
    {
        php_swoole_fatal_error(E_WARNING, "server is running, unable to execute %s->set", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    //chroot
    if (php_swoole_array_get_value(vht, "chroot", v))
    {
        if (SwooleG.chroot)
        {
            sw_free(SwooleG.chroot);
        }
        SwooleG.chroot = zend::string(v).dup();
    }
    //user
    if (php_swoole_array_get_value(vht, "user", v))
    {
        if (SwooleG.user)
        {
            sw_free(SwooleG.user);
        }
        SwooleG.user = zend::string(v).dup();
    }
    //group
    if (php_swoole_array_get_value(vht, "group", v))
    {
        if (SwooleG.group)
        {
            sw_free(SwooleG.group);
        }
        SwooleG.group = zend::string(v).dup();
    }
    //daemonize
    if (php_swoole_array_get_value(vht, "daemonize", v))
    {
        serv->daemonize = zval_is_true(v);
    }
#ifdef SW_DEBUG
    //debug
    if (php_swoole_array_get_value(vht, "debug_mode", v))
    {
        if (zval_is_true(v))
        {
            SwooleG.log_level = 0;
        }
    }
#endif
    if (php_swoole_array_get_value(vht, "trace_flags", v))
    {
        SwooleG.trace_flags = (uint32_t) SW_MAX(0, zval_get_long(v));
    }
    //pid file
    if (php_swoole_array_get_value(vht, "pid_file", v))
    {
        if (serv->pid_file)
        {
            sw_free(serv->pid_file);
        }
        serv->pid_file = zend::string(v).dup();
    }
    //reactor thread num
    if (php_swoole_array_get_value(vht, "reactor_num", v))
    {
        serv->reactor_num = (uint16_t) zval_get_long(v);
        if (serv->reactor_num <= 0)
        {
            serv->reactor_num = SwooleG.cpu_num;
        }
    }
    if (php_swoole_array_get_value(vht, "single_thread", v))
    {
        serv->single_thread = zval_is_true(v);
    }
    //worker_num
    if (php_swoole_array_get_value(vht, "worker_num", v))
    {
        serv->worker_num = (uint16_t) zval_get_long(v);
        if (serv->worker_num <= 0)
        {
            serv->worker_num = SwooleG.cpu_num;
        }
    }
    //max wait time
    if (php_swoole_array_get_value(vht, "max_wait_time", v))
    {
        serv->max_wait_time = (uint32_t) zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "enable_coroutine", v))
    {
        serv->enable_coroutine = SwooleG.enable_coroutine = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "max_coro_num", v) || php_swoole_array_get_value(vht, "max_coroutine", v))
    {
        zend_long max_num;
        max_num = zval_get_long(v);
        PHPCoroutine::set_max_num(max_num <= 0 ? SW_DEFAULT_MAX_CORO_NUM : max_num);
    }
    if (php_swoole_array_get_value(vht, "send_yield", v))
    {
        serv->send_yield = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "send_timeout", v))
    {
        serv->send_timeout = zval_get_double(v);
    }
    //dispatch_mode
    if (php_swoole_array_get_value(vht, "dispatch_mode", v))
    {
        serv->dispatch_mode = (uint8_t) zval_get_long(v);
    }
    //dispatch function
    if (php_swoole_array_get_value(vht, "dispatch_func", v))
    {
        swServer_dispatch_function c_dispatch_func = NULL;
        while(1)
        {
            if (Z_TYPE_P(v) == IS_STRING)
            {
                c_dispatch_func = (swServer_dispatch_function) swoole_get_function(Z_STRVAL_P(v), Z_STRLEN_P(v));
                if (c_dispatch_func)
                {
                    break;
                }
            }
#ifdef ZTS
            if (serv->factory_mode == SW_MODE_PROCESS && !serv->single_thread)
            {
                php_swoole_fatal_error(E_ERROR, "option [dispatch_func] does not support with ZTS");
            }
#endif
            char *func_name = NULL;
            zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
            if (!sw_zend_is_callable_ex(v, NULL, 0, &func_name, NULL, fci_cache, NULL))
            {
                php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
                return;
            }
            efree(func_name);
            sw_zend_fci_cache_persist(fci_cache);
            if (serv->private_data_3)
            {
                sw_zend_fci_cache_discard((zend_fcall_info_cache *) serv->private_data_3);
                efree(serv->private_data_3);
            }
            serv->private_data_3 = (void *) fci_cache;
            c_dispatch_func = php_swoole_server_dispatch_func;
            break;
        }
        serv->dispatch_func = c_dispatch_func;
    }
    //log_file
    if (php_swoole_array_get_value(vht, "log_file", v))
    {
        if (SwooleG.log_file)
        {
            sw_free(SwooleG.log_file);
        }
        SwooleG.log_file = zend::string(v).dup();
    }
    //log_level
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        zend_long level;
        level = zval_get_long(v);
        SwooleG.log_level = (uint32_t) (level < 0 ? UINT32_MAX : level);
    }
    /**
     * for dispatch_mode = 1/3
     */
    if (php_swoole_array_get_value(vht, "discard_timeout_request", v))
    {
        serv->discard_timeout_request = zval_is_true(v);
    }
    //onConnect/onClose event
    if (php_swoole_array_get_value(vht, "enable_unsafe_event", v))
    {
        serv->enable_unsafe_event = zval_is_true(v);
    }
    //delay receive
    if (php_swoole_array_get_value(vht, "enable_delay_receive", v))
    {
        serv->enable_delay_receive = zval_is_true(v);
    }
    //task coroutine
    if (php_swoole_array_get_value(vht, "task_enable_coroutine", v))
    {
        serv->task_enable_coroutine = zval_is_true(v);
    }
    //task_worker_num
    if (php_swoole_array_get_value(vht, "task_worker_num", v))
    {
        serv->task_worker_num = (uint16_t) zval_get_long(v);
    }
    //slowlog
    if (php_swoole_array_get_value(vht, "trace_event_worker", v))
    {
        serv->trace_event_worker = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "request_slowlog_timeout", v))
    {
        serv->request_slowlog_timeout = (uint8_t) zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "request_slowlog_file", v))
    {
        zend::string str_v(v);
        if (serv->request_slowlog_file)
        {
            fclose(serv->request_slowlog_file);
        }
        serv->request_slowlog_file = fopen(str_v.val(), "a+");
        if (serv->request_slowlog_file == NULL)
        {
            php_swoole_fatal_error(E_ERROR, "Unable to open request_slowlog_file[%s]", str_v.val());
            return;
        }
        if (serv->request_slowlog_timeout == 0)
        {
            serv->request_slowlog_timeout = 1;
        }
    }
    //task ipc mode, 1,2,3
    if (php_swoole_array_get_value(vht, "task_ipc_mode", v))
    {
        serv->task_ipc_mode = (uint8_t) zval_get_long(v);
    }
    /**
     * Temporary file directory for task_worker
     */
    if (php_swoole_array_get_value(vht, "task_tmpdir", v))
    {
        zend::string str_v(v);
        if (php_swoole_create_dir(str_v.val(), str_v.len()) < 0)
        {
            php_swoole_fatal_error(E_ERROR, "Unable to create task_tmpdir[%s]", str_v.val());
            return;
        }
        if (SwooleG.task_tmpdir)
        {
            sw_free(SwooleG.task_tmpdir);
        }
        SwooleG.task_tmpdir = (char*) sw_malloc(str_v.len() + sizeof(SW_TASK_TMP_FILE) + 1);
        if (!SwooleG.task_tmpdir)
        {
            php_swoole_fatal_error(E_ERROR, "malloc() failed");
            RETURN_FALSE;
        }
        SwooleG.task_tmpdir_len = sw_snprintf(SwooleG.task_tmpdir, SW_TASK_TMPDIR_SIZE, "%s/swoole.task.XXXXXX", str_v.val()) + 1;
    }
    //task_max_request
    if (php_swoole_array_get_value(vht, "task_max_request", v))
    {
        serv->task_max_request = (uint16_t) zval_get_long(v);
    }
    //max_connection
    if (php_swoole_array_get_value(vht, "max_connection", v) || php_swoole_array_get_value(vht, "max_conn", v))
    {
        serv->max_connection = (uint32_t) zval_get_long(v);
    }
    //heartbeat_check_interval
    if (php_swoole_array_get_value(vht, "heartbeat_check_interval", v))
    {
        serv->heartbeat_check_interval = (uint16_t) zval_get_long(v);
    }
    //heartbeat idle time
    if (php_swoole_array_get_value(vht, "heartbeat_idle_time", v))
    {
        serv->heartbeat_idle_time = (uint16_t) zval_get_long(v);

        if (serv->heartbeat_check_interval > serv->heartbeat_idle_time)
        {
            php_swoole_fatal_error(E_WARNING, "heartbeat_idle_time must be greater than heartbeat_check_interval");
            serv->heartbeat_check_interval = serv->heartbeat_idle_time / 2;
        }
    }
    else if (serv->heartbeat_check_interval > 0)
    {
        serv->heartbeat_idle_time = serv->heartbeat_check_interval * 2;
    }
    //max_request
    if (php_swoole_array_get_value(vht, "max_request", v))
    {
        serv->max_request = (uint32_t) zval_get_long(v);
    }
    //reload async
    if (php_swoole_array_get_value(vht, "reload_async", v))
    {
        serv->reload_async = zval_is_true(v);
    }
    //cpu affinity
    if (php_swoole_array_get_value(vht, "open_cpu_affinity", v))
    {
        serv->open_cpu_affinity = zval_is_true(v);
    }
    //cpu affinity set
    if (php_swoole_array_get_value(vht, "cpu_affinity_ignore", v))
    {
        int ignore_num = zend_hash_num_elements(Z_ARRVAL_P(v));
        if (ignore_num >= SW_CPU_NUM)
        {
            php_swoole_fatal_error(E_ERROR, "cpu_affinity_ignore num must be less than cpu num (%d)", SW_CPU_NUM);
            RETURN_FALSE;
        }
        int available_num = SW_CPU_NUM - ignore_num;
        int *available_cpu = (int *) sw_malloc(sizeof(int) * available_num);
        if (!available_cpu)
        {
            php_swoole_fatal_error(E_WARNING, "malloc() failed");
            RETURN_FALSE;
        }
        int flag, i, available_i = 0;

        zval *zval_core = NULL;
        for (i = 0; i < SW_CPU_NUM; i++)
        {
            flag = 1;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(v), zval_core)
                int core = (int) zval_get_long(zval_core);
                if (i == core)
                {
                    flag = 0;
                    break;
                }
            SW_HASHTABLE_FOREACH_END();
            if (flag)
            {
                available_cpu[available_i] = i;
                available_i++;
            }
        }
        serv->cpu_affinity_available_num = available_num;
        if (serv->cpu_affinity_available)
        {
            sw_free(serv->cpu_affinity_available);
        }
        serv->cpu_affinity_available = available_cpu;
    }
    //parse cookie header
    if (php_swoole_array_get_value(vht, "http_parse_cookie", v))
    {
        serv->http_parse_cookie = zval_is_true(v);
    }
    //parse x-www-form-urlencoded form data
    if (php_swoole_array_get_value(vht, "http_parse_post", v))
    {
        serv->http_parse_post = zval_is_true(v);
    }
#ifdef SW_HAVE_ZLIB
    //http content compression
    if (php_swoole_array_get_value(vht, "http_compression", v))
    {
        serv->http_compression = zval_is_true(v);
        serv->http_compression_level = Z_BEST_SPEED;
    }
    if (php_swoole_array_get_value(vht, "http_gzip_level", v) || php_swoole_array_get_value(vht, "http_compression_level", v))
    {
        zend_long level = zval_get_long(v);
        if (level > UINT8_MAX)
        {
            level = UINT8_MAX;
        }
        else if (level < 0)
        {
            level = 0;
        }
        serv->http_compression_level = level;
    }
#endif
    //temporary directory for HTTP uploaded file.
    if (php_swoole_array_get_value(vht, "upload_tmp_dir", v))
    {
        zend::string str_v(v);
        if (php_swoole_create_dir(str_v.val(), str_v.len()) < 0)
        {
            php_swoole_fatal_error(E_ERROR, "Unable to create upload_tmp_dir[%s]", str_v.val());
            return;
        }
        if (serv->upload_tmp_dir)
        {
            sw_free(serv->upload_tmp_dir);
        }
        serv->upload_tmp_dir = str_v.dup();
    }
    /**
     * http static file handler
     */
    if (php_swoole_array_get_value(vht, "enable_static_handler", v))
    {
        serv->enable_static_handler = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "document_root", v))
    {
        zend::string str_v(v);
        if (str_v.len() >= PATH_MAX)
        {
            php_swoole_fatal_error(E_ERROR, "The length of document_root must be less than %d", PATH_MAX);
            return;
        }
        if (serv->document_root)
        {
            sw_free(serv->document_root);
        }
        serv->document_root = (char *) sw_malloc(PATH_MAX);
        if (!serv->document_root)
        {
            php_swoole_fatal_error(E_ERROR, "malloc() failed");
            RETURN_FALSE;
        }
        if (!realpath(str_v.val(), serv->document_root))
        {
            php_swoole_fatal_error(E_ERROR, "document_root[%s] does not exist", serv->document_root);
            sw_free(serv->document_root);
            serv->document_root = nullptr;
            RETURN_FALSE;
        }
        serv->document_root_len = strlen(serv->document_root);
    }
    /**
     * [static_handler] locations
     */
    if (php_swoole_array_get_value(vht, "static_handler_locations", v))
    {
        if (ZVAL_IS_ARRAY(v))
        {
            zval *_location;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(v), _location)
                zend::string __location(_location);
                if (__location.len() > 0 && __location.val()[0] == '/')
                {
                    swHttp_static_handler_add_location(serv, __location.val(), __location.len());
                }
            SW_HASHTABLE_FOREACH_END();
        }
        else
        {
            php_swoole_fatal_error(E_ERROR, "static_handler_locations num must be array");
            RETURN_FALSE;
        }
    }
    /**
     * buffer input size
     */
    if (php_swoole_array_get_value(vht, "buffer_input_size", v))
    {
        serv->buffer_input_size = (uint32_t) zval_get_long(v);
    }
    /**
     * buffer output size
     */
    if (php_swoole_array_get_value(vht, "buffer_output_size", v))
    {
        serv->buffer_output_size = (uint32_t) zval_get_long(v);
    }
    //message queue key
    if (php_swoole_array_get_value(vht, "message_queue_key", v))
    {
        serv->message_queue_key = (uint64_t) zval_get_long(v);
    }

    if (serv->task_enable_coroutine
            && (serv->task_ipc_mode == SW_TASK_IPC_MSGQUEUE || serv->task_ipc_mode == SW_TASK_IPC_PREEMPTIVE))
    {
        php_swoole_fatal_error(E_ERROR, "cannot use msgqueue when task_enable_coroutine is enable");
        RETURN_FALSE;
    }

    sw_zend_call_method_with_1_params(server_port_list.zobjects[0], swoole_server_port_ce, NULL, "set", NULL, zset);

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, on)
{
    zval *name;
    zval *cb;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (serv->gs->start > 0)
    {
        php_swoole_fatal_error(E_WARNING, "server is running, unable to register event callback function");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &name, &cb) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, NULL, 0, &func_name, NULL, fci_cache, NULL))
    {
        php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    zend::string _event_name_ori(name);
    zend::string _event_name_tolower(zend_string_tolower(_event_name_ori.get()));

    auto i = server_event_map.find(_event_name_tolower.to_std_string());
    if (i == server_event_map.end())
    {
        zval *port_object = server_port_list.zobjects[0];
        zval retval;
        efree(fci_cache);
        sw_zend_call_method_with_2_params(port_object, swoole_server_port_ce, NULL, "on", &retval, name, cb);
        RETURN_BOOL(Z_BVAL_P(&retval));
    }
    else
    {
        int event_type = i->second.type;
        string property_name = "on" + i->second.name;

        zend_update_property(swoole_server_ce, ZEND_THIS, property_name.c_str(), property_name.length(), cb);

        if (server_callbacks[event_type])
        {
            efree(server_callbacks[event_type]);
        }
        server_callbacks[event_type] = fci_cache;

        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, getCallback)
{
    zval *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(name)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend::string _event_name_ori(name);
    zend::string _event_name_tolower(zend_string_tolower(_event_name_ori.get()));
    auto i = server_event_map.find(_event_name_tolower.to_std_string());
    if (i != server_event_map.end())
    {
        string property_name = "on" + i->second.name;
        // Notice: we should use Z_OBJCE_P instead of swoole_server_ce, because we need to consider the subclasses.
        zval rv, *property = zend_read_property(Z_OBJCE_P(ZEND_THIS), ZEND_THIS, property_name.c_str(), property_name.length(), 1, &rv);
        if (!ZVAL_IS_NULL(property))
        {
            RETURN_ZVAL(property, 1, 0);
        }
    }
    sw_zend_call_method_with_1_params(server_port_list.zobjects[0], swoole_server_port_ce, NULL, "getcallback", return_value, name);
}

static PHP_METHOD(swoole_server, listen)
{
    char *host;
    size_t host_len;
    long sock_type;
    long port;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (serv->gs->start > 0)
    {
        php_swoole_fatal_error(E_WARNING, "server is running, can't add listener");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &host, &host_len, &port, &sock_type) == FAILURE)
    {
        RETURN_FALSE;
    }

    swListenPort *ls = swServer_add_port(serv, (int) sock_type, host, (int) port);
    if (!ls)
    {
        RETURN_FALSE;
    }

    zval *port_object = php_swoole_server_add_port(serv, ls);
    RETURN_ZVAL(port_object, 1, NULL);
}

static PHP_METHOD(swoole_server, addProcess)
{
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (serv->gs->start > 0)
    {
        php_swoole_fatal_error(E_WARNING, "server is running, can't add process");
        RETURN_FALSE;
    }

    zval *process = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &process) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (ZVAL_IS_NULL(process))
    {
        php_swoole_fatal_error(E_WARNING, "the first parameter can't be empty");
        RETURN_FALSE;
    }

    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_ce))
    {
        php_swoole_fatal_error(E_ERROR, "object is not instanceof swoole_process");
        RETURN_FALSE;
    }

    if (serv->onUserWorkerStart == NULL)
    {
        serv->onUserWorkerStart = php_swoole_onUserWorkerStart;
    }

    zval *tmp_process = (zval *) emalloc(sizeof(zval));
    memcpy(tmp_process, process, sizeof(zval));
    process = tmp_process;

    Z_TRY_ADDREF_P(process);

    swWorker *worker = (swWorker *) swoole_get_object(process);
    worker->ptr = process;

    int id = swServer_add_worker(serv, worker);
    if (id < 0)
    {
        php_swoole_fatal_error(E_WARNING, "swServer_add_worker failed");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_process_ce, process, ZEND_STRL("id"), id);
    RETURN_LONG(id);
}

static inline zend_bool is_websocket_server(zval *zobject)
{
    return instanceof_function(Z_OBJCE_P(zobject), swoole_websocket_server_ce);
}

static inline zend_bool is_http_server(zval *zobject)
{
    return instanceof_function(Z_OBJCE_P(zobject), swoole_http_server_ce);
}

static PHP_METHOD(swoole_server, start)
{
    zval *zserv = ZEND_THIS;

    swServer *serv = (swServer *) swoole_get_object(zserv);
    if (serv->gs->start > 0)
    {
        php_swoole_fatal_error(E_WARNING, "server is running, unable to execute %s->start", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    php_swoole_server_register_callbacks(serv);

    serv->onReceive = php_swoole_onReceive;

    if (is_websocket_server(zserv) || is_http_server(zserv))
    {
        zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        add_assoc_bool(zsetting, "open_http_protocol", 1);
        add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
        add_assoc_bool(zsetting, "open_eof_check", 0);
        add_assoc_bool(zsetting, "open_length_check", 0);

        enum protocol_flags
        {
            SW_HTTP2_PROTOCOL = 1u << 1,
            SW_WEBSOCKET_PROTOCOL = 1u << 2
        };
        uint8_t protocol_flag = 0;
        swListenPort *ls = serv->listen_list;
        if (ls->open_http2_protocol)
        {
            add_assoc_bool(zsetting, "open_http2_protocol", 1);
            protocol_flag |= SW_HTTP2_PROTOCOL;
        }
        if (ls->open_websocket_protocol || is_websocket_server(zserv))
        {
            add_assoc_bool(zsetting, "open_websocket_protocol", 1);
            protocol_flag |= SW_WEBSOCKET_PROTOCOL;
        }
        swPort_clear_protocol(serv->listen_list);
        ls->open_http_protocol = 1;
        ls->open_http2_protocol = !!(protocol_flag & SW_HTTP2_PROTOCOL);
        ls->open_websocket_protocol = !!(protocol_flag & SW_WEBSOCKET_PROTOCOL);
    }

    php_swoole_server_before_start(serv, zserv);

    if (swServer_start(serv) < 0)
    {
        php_swoole_fatal_error(E_ERROR, "failed to start server. Error: %s", sw_error);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, send)
{
    int ret;
    zend_long fd;
    zval *zfd;
    zval *zdata;
    zend_long server_socket = -1;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_ZVAL(zfd)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(server_socket)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(ZVAL_IS_NULL(zfd)))
    {
        php_swoole_fatal_error(E_WARNING, "fd can not be null");
        RETURN_FALSE;
    }

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0)
    {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    //UNIX DGRAM SOCKET
    if (serv->have_dgram_sock && Z_TYPE_P(zfd) == IS_STRING && Z_STRVAL_P(zfd)[0] == '/')
    {
        struct sockaddr_un addr_un;
        memcpy(addr_un.sun_path, Z_STRVAL_P(zfd), Z_STRLEN_P(zfd));
        addr_un.sun_family = AF_UNIX;
        addr_un.sun_path[Z_STRLEN_P(zfd)] = 0;
        ret = swSocket_sendto_blocking(
            server_socket == -1 ? dgram_server_socket : server_socket,
            data, length, 0,
            (struct sockaddr *) &addr_un, sizeof(addr_un)
        );
        SW_CHECK_RETURN(ret);
    }

    fd = zval_get_long(zfd);
    if (UNEXPECTED((int) fd <= 0))
    {
        php_swoole_fatal_error(E_WARNING, "invalid fd[" ZEND_LONG_FMT "]", fd);
        RETURN_FALSE;
    }
    ret = serv->send(serv, fd, data, length);
    if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && serv->send_yield)
    {
        zval_add_ref(zdata);
        php_swoole_server_send_yield(serv, fd, zdata, return_value);
    }
    else
    {
        SW_CHECK_RETURN(ret);
    }
}

static PHP_METHOD(swoole_server, sendto)
{
    char *ip;
    size_t ip_len;
    zend_long port;
    char *data;
    size_t len;
    zend_long server_socket = -1;

    zend_bool ipv6 = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(3, 4)
        Z_PARAM_STRING(ip, ip_len)
        Z_PARAM_LONG(port)
        Z_PARAM_STRING(data, len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(server_socket)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (len == 0)
    {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    if (strchr(ip, ':'))
    {
        ipv6 = 1;
    }

    if (ipv6 == 0 && serv->udp_socket_ipv4 <= 0)
    {
        php_swoole_fatal_error(E_WARNING, "UDP listener has to be added before executing sendto");
        RETURN_FALSE;
    }
    else if (ipv6 == 1 && serv->udp_socket_ipv6 <= 0)
    {
        php_swoole_fatal_error(E_WARNING, "UDP6 listener has to be added before executing sendto");
        RETURN_FALSE;
    }

    if (server_socket < 0)
    {
        server_socket = ipv6 ?  serv->udp_socket_ipv6 : serv->udp_socket_ipv4;
    }

    int ret;
    if (ipv6)
    {
        ret = swSocket_udp_sendto6(server_socket, ip, port, data, len);
    }
    else
    {
        ret = swSocket_udp_sendto(server_socket, ip, port, data, len);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_server, sendfile)
{
    size_t len;

    char *filename;
    long fd;
    zend_long offset = 0;
    zend_long length = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls|ll", &fd, &filename, &len, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        php_swoole_fatal_error(E_WARNING, "can't sendfile[%s] to the connections in master process", filename);
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(serv->sendfile(serv, (int) fd, filename, len, offset, length));
}

static PHP_METHOD(swoole_server, close)
{
    zend_long fd;
    zend_bool reset = SW_FALSE;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        php_swoole_fatal_error(E_WARNING, "can't close the connections in master process");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(fd)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(reset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(serv->close(serv, (int )fd, (int )reset));
}

static PHP_METHOD(swoole_server, confirm)
{
    long fd;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        php_swoole_fatal_error(E_WARNING, "can't confirm the connections in master process");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(serv->feedback(serv, fd, SW_EVENT_CONFIRM));
}

static PHP_METHOD(swoole_server, pause)
{
    long fd;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(serv->feedback(serv, fd, SW_EVENT_PAUSE_RECV));
}

static PHP_METHOD(swoole_server, resume)
{
    long fd;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(serv->feedback(serv, fd, SW_EVENT_RESUME_RECV));
}

static PHP_METHOD(swoole_server, stats)
{
    int i;
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("start_time"), serv->stats->start_time);
    add_assoc_long_ex(return_value, ZEND_STRL("connection_num"), serv->stats->connection_num);
    add_assoc_long_ex(return_value, ZEND_STRL("accept_count"), serv->stats->accept_count);
    add_assoc_long_ex(return_value, ZEND_STRL("close_count"), serv->stats->close_count);
    /**
     * reset
     */
    int tasking_num = serv->stats->tasking_num;
    if (tasking_num < 0)
    {
        tasking_num = serv->stats->tasking_num = 0;
    }

    uint16_t worker_num = serv->task_worker_num + serv->worker_num + serv->user_worker_num;
    uint16_t idle_worker_num = 0;
    add_assoc_long_ex(return_value, ZEND_STRL("worker_num"), worker_num);
    for (i = 0; i < worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (worker->status == SW_WORKER_IDLE)
        {
            idle_worker_num ++;
        }
    }
    add_assoc_long_ex(return_value, ZEND_STRL("idle_worker_num"), idle_worker_num);
    add_assoc_long_ex(return_value, ZEND_STRL("tasking_num"), tasking_num);
    add_assoc_long_ex(return_value, ZEND_STRL("request_count"), serv->stats->request_count);
    if (SwooleWG.worker)
    {
        add_assoc_long_ex(return_value, ZEND_STRL("worker_request_count"), SwooleWG.worker->request_count);
        add_assoc_long_ex(return_value, ZEND_STRL("worker_dispatch_count"), SwooleWG.worker->dispatch_count);
    }

    if (serv->task_ipc_mode > SW_TASK_IPC_UNIXSOCK && serv->gs->task_workers.queue)
    {
        int queue_num = -1;
        int queue_bytes = -1;
        if (swMsgQueue_stat(serv->gs->task_workers.queue, &queue_num, &queue_bytes) == 0)
        {
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_num"), queue_num);
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_bytes"), queue_bytes);
        }
    }

    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
}

static PHP_METHOD(swoole_server, reload)
{
    zend_bool only_reload_taskworker = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &only_reload_taskworker) == FAILURE)
    {
        RETURN_FALSE;
    }

    int sig = only_reload_taskworker ? SIGUSR2 : SIGUSR1;
    if (swoole_kill(serv->gs->manager_pid, sig) < 0)
    {
        php_swoole_sys_error(E_WARNING, "failed to send the reload signal");
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, heartbeat)
{
    zend_bool close_connection = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &close_connection) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (serv->heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    array_init(return_value);

    int fd;
    int checktime = (int) serv->gs->now - serv->heartbeat_idle_time;
    swConnection *conn;

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        swTrace("heartbeat check fd=%d", fd);
        conn = &serv->connection_list[fd];

        if (1 == conn->active && conn->last_time < checktime)
        {
            conn->close_force = 1;
            /**
             * Close the connection
             */
            if (close_connection)
            {
                serv->factory.end(&serv->factory, fd);
            }
            add_next_index_long(return_value, conn->session_id);
        }
    }
}

static PHP_METHOD(swoole_server, taskwait)
{
    swEventData buf;
    zval *data;
    double timeout = SW_TASKWAIT_TIMEOUT;
    zend_long dst_worker_id = -1;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (!swIsWorker())
    {
        php_swoole_fatal_error(E_WARNING, "taskwait method can only be used in the worker process");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|dl", &data, &timeout, &dst_worker_id) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, data) < 0)
    {
        RETURN_FALSE;
    }

    int _dst_worker_id = (int) dst_worker_id;

    //coroutine
    if (PHPCoroutine::get_cid() >= 0)
    {
        php_swoole_task_wait_co(serv, &buf, timeout, _dst_worker_id, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    int task_id = buf.info.fd;

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);

    //clear history task
    while (read(efd, &notify, sizeof(notify)) > 0);

    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);

    if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        task_notify_pipe->timeout = timeout;
        while(1)
        {
            if (task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify)) > 0)
            {
                if (task_result->info.fd != task_id)
                {
                    continue;
                }
                zval *task_notify_data = php_swoole_task_unpack(task_result);
                if (task_notify_data == NULL)
                {
                    RETURN_FALSE;
                }
                else
                {
                    RETVAL_ZVAL(task_notify_data, 0, 0);
                    efree(task_notify_data);
                    return;
                }
                break;
            }
            else
            {
                php_swoole_sys_error(E_WARNING, "taskwait failed");
                break;
            }
        }
    }
    else
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
    }
    RETURN_FALSE;
}

static PHP_METHOD(swoole_server, taskWaitMulti)
{
    swEventData buf;
    zval *tasks;
    zval *task;
    double timeout = SW_TASKWAIT_TIMEOUT;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (!swIsWorker())
    {
        php_swoole_fatal_error(E_WARNING, "taskWaitMulti method can only be used in the worker process");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &tasks, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    array_init(return_value);

    int dst_worker_id;
    int task_id;
    int i = 0;
    int n_task = php_swoole_array_length(tasks);

    if (n_task >= SW_MAX_CONCURRENT_TASK)
    {
        php_swoole_fatal_error(E_WARNING, "too many concurrent tasks");
        RETURN_FALSE;
    }

    int list_of_id[SW_MAX_CONCURRENT_TASK] = {0};

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    char _tmpfile[sizeof(SW_TASK_TMP_FILE)] = SW_TASK_TMP_FILE;
    int _tmpfile_fd = swoole_tmpfile(_tmpfile);
    if (_tmpfile_fd < 0)
    {
        RETURN_FALSE;
    }
    close(_tmpfile_fd);
    int *finish_count = (int *) task_result->data;

    worker->lock.lock(&worker->lock);
    *finish_count = 0;
    memcpy(task_result->data + 4, _tmpfile, sizeof(_tmpfile));
    worker->lock.unlock(&worker->lock);

    //clear history task
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);
    while (read(efd, &notify, sizeof(notify)) > 0);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(tasks), task)
        task_id = php_swoole_task_pack(&buf, task);
        if (task_id < 0)
        {
            php_swoole_fatal_error(E_WARNING, "task pack failed");
            goto _fail;
        }
        swTask_type(&buf) |= SW_TASK_WAITALL;
        dst_worker_id = -1;
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &dst_worker_id) < 0)
        {
            php_swoole_sys_error(E_WARNING, "taskwait failed");
            task_id = -1;
            _fail:
            add_index_bool(return_value, i, 0);
            n_task --;
        }
        else
        {
            sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        }
        list_of_id[i] = task_id;
        i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0)
    {
        SwooleG.error = SW_ERROR_TASK_DISPATCH_FAIL;
        RETURN_FALSE;
    }

    double _now = swoole_microtime();
    while (n_task > 0)
    {
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        if (ret > 0 && *finish_count < n_task)
        {
            if (swoole_microtime() - _now < timeout)
            {
                continue;
            }
        }
        break;
    }

    worker->lock.lock(&worker->lock);
    swString *content = swoole_file_get_contents(_tmpfile);
    worker->lock.unlock(&worker->lock);

    if (content == NULL)
    {
        RETURN_FALSE;
    }

    swEventData *result;
    zval *zdata;
    uint32_t j;

    do
    {
        result = (swEventData *) (content->str + content->offset);
        task_id = result->info.fd;
        zdata = php_swoole_task_unpack(result);
        if (zdata == NULL)
        {
            goto _next;
        }
        for (j = 0; j < php_swoole_array_length(tasks); j++)
        {
            if (list_of_id[j] == task_id)
            {
                break;
            }
        }
        (void) add_index_zval(return_value, j, zdata);
        efree(zdata);
        _next:
        content->offset += sizeof(swDataHead) + result->info.len;
    } while (content->offset < 0 || (size_t) content->offset < content->length);
    //free memory
    swString_free(content);
    //delete tmp file
    unlink(_tmpfile);
}

static PHP_METHOD(swoole_server, taskCo)
{
    swEventData buf;
    bzero(&buf.info, sizeof(buf.info));
    zval *tasks;
    zval *task;
    double timeout = SW_TASKWAIT_TIMEOUT;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (!swIsWorker())
    {
        php_swoole_fatal_error(E_WARNING, "taskCo method can only be used in the worker process");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &tasks, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    int dst_worker_id = -1;
    int task_id;
    int i = 0;
    uint32_t n_task = php_swoole_array_length(tasks);

    if (n_task >= SW_MAX_CONCURRENT_TASK)
    {
        php_swoole_fatal_error(E_WARNING, "too many concurrent tasks");
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    int *list = (int *) ecalloc(n_task, sizeof(int));
    if (list == NULL)
    {
        RETURN_FALSE;
    }

    swTaskCo *task_co = (swTaskCo *) emalloc(sizeof(swTaskCo));
    if (task_co == NULL)
    {
        efree(list);
        RETURN_FALSE;
    }

    zval *result = sw_malloc_zval();
    array_init(result);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(tasks), task)
        task_id = php_swoole_task_pack(&buf, task);
        if (task_id < 0)
        {
            php_swoole_fatal_error(E_WARNING, "failed to pack task");
            goto _fail;
        }
        swTask_type(&buf) |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);
        dst_worker_id = -1;
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        if (swProcessPool_dispatch(&serv->gs->task_workers, &buf, &dst_worker_id) < 0)
        {
            task_id = -1;
            _fail:
            add_index_bool(result, i, 0);
            n_task --;
            sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        }
        else
        {
            task_coroutine_map[buf.info.fd] = task_co;
        }
        list[i] = task_id;
        i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0)
    {
        SwooleG.error = SW_ERROR_TASK_DISPATCH_FAIL;
        RETURN_FALSE;
    }

    long ms = (long) (timeout * 1000);

    task_co->result = result;
    task_co->list = list;
    task_co->count = n_task;
    task_co->context.state = SW_CORO_CONTEXT_RUNNING;

    swTimer_node *timer = swTimer_add(&SwooleG.timer, ms, 0, task_co, php_swoole_task_onTimeout);
    if (timer)
    {
        task_co->timer = timer;
    }
    PHPCoroutine::yield_m(return_value, &task_co->context);
}

static PHP_METHOD(swoole_server, task)
{
    swEventData buf;
    bzero(&buf.info, sizeof(buf.info));
    zval *data;
    zend_long dst_worker_id = -1;
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(dst_worker_id)
        Z_PARAM_FUNC_EX(fci, fci_cache, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, data) < 0)
    {
        RETURN_FALSE;
    }

    if (!swIsWorker())
    {
        swTask_type(&buf) |= SW_TASK_NOREPLY;
    }
    else if (fci.size)
    {
        swTask_type(&buf) |= SW_TASK_CALLBACK;
        sw_zend_fci_cache_persist(&fci_cache);
        task_callbacks[buf.info.fd] = fci_cache;
    }

    swTask_type(&buf) |= SW_TASK_NONBLOCK;

    int _dst_worker_id = (int) dst_worker_id;
    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);

    if (swProcessPool_dispatch(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        RETURN_LONG(buf.info.fd);
    }
    else
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_server, sendMessage)
{
    swEventData buf;
    bzero(&buf.info, sizeof(buf.info));

    zval *message;
    long worker_id = -1;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zl", &message, &worker_id) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_id == SwooleWG.id)
    {
        php_swoole_fatal_error(E_WARNING, "can't send messages to self");
        RETURN_FALSE;
    }

    if (worker_id >= serv->worker_num + serv->task_worker_num)
    {
        php_swoole_fatal_error(E_WARNING, "worker_id[%d] is invalid", (int) worker_id);
        RETURN_FALSE;
    }

    if (!serv->onPipeMessage)
    {
        php_swoole_fatal_error(E_WARNING, "onPipeMessage is null, can't use sendMessage");
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, message) < 0)
    {
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_PIPE_MESSAGE;
    buf.info.reactor_id = SwooleWG.id;

    swWorker *to_worker = swServer_get_worker(serv, worker_id);
    SW_CHECK_RETURN(swWorker_send2worker(to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK));
}

static PHP_METHOD(swoole_server, finish)
{
    zval *data;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (unlikely(serv->task_enable_coroutine))
    {
        php_swoole_fatal_error(E_ERROR, "please use %s->finish instead when task_enable_coroutine is enable", ZSTR_VAL(swoole_server_task_ce->name));
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(php_swoole_task_finish(serv, data, NULL));
}

static PHP_METHOD(swoole_server_task, finish)
{
    zval *data;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swDataHead *info = (swDataHead *) swoole_get_property(ZEND_THIS, 0);
    SW_CHECK_RETURN(php_swoole_task_finish(serv, data, (swEventData* )info));
}

static PHP_METHOD(swoole_server, bind)
{
    zend_long fd = 0;
    zend_long uid = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &fd, &uid) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (uid > UINT32_MAX)
    {
        php_swoole_fatal_error(E_WARNING, "uid can not be greater than %u", UINT32_MAX);
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        RETURN_FALSE;
    }

    sw_spinlock(&conn->lock);
    if (conn->uid != 0)
    {
        RETVAL_FALSE;
    }
    else
    {
        conn->uid = (uint32_t) uid;
        RETVAL_TRUE;
    }
    sw_spinlock_release(&conn->lock);
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server, getSocket)
{
    long port = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &port) == FAILURE)
    {
        RETURN_FALSE;
    }

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);

    int sock = swServer_get_socket(serv, port);
    php_socket *socket_object = swoole_convert_to_socket(sock);

    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
}
#endif

static PHP_METHOD(swoole_server, getClientInfo)
{
    zend_long fd;
    zend_long reactor_id = -1;
    zend_bool dont_check_connection = 0;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|lb", &fd, &reactor_id, &dont_check_connection) == FAILURE)
    {
        RETURN_FALSE;
    }

    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 && !dont_check_connection)
    {
        RETURN_FALSE;
    }
    else
    {
        array_init(return_value);

        if (conn->uid > 0 || serv->dispatch_mode == SW_DISPATCH_UIDMOD)
        {
            add_assoc_long(return_value, "uid", conn->uid);
        }

        swListenPort *port = swServer_get_port(serv, conn->fd);
        if (port && port->open_websocket_protocol)
        {
            add_assoc_long(return_value, "websocket_status", conn->websocket_status);
        }

#ifdef SW_USE_OPENSSL
        if (conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid)
        {
            add_assoc_stringl(return_value, "ssl_client_cert", conn->ssl_client_cert->str, conn->ssl_client_cert->length);
        }
#endif
        //server socket
        swConnection *from_sock = swServer_connection_get(serv, conn->server_fd);
        if (from_sock)
        {
            add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        }
        add_assoc_long(return_value, "server_fd", conn->server_fd);
        add_assoc_long(return_value, "socket_fd", conn->fd);
        add_assoc_long(return_value, "socket_type", conn->socket_type);
        add_assoc_long(return_value, "remote_port", swConnection_get_port(conn));
        add_assoc_string(return_value, "remote_ip", (char *) swConnection_get_ip(conn));
        add_assoc_long(return_value, "reactor_id", conn->reactor_id);
        add_assoc_long(return_value, "connect_time", conn->connect_time);
        add_assoc_long(return_value, "last_time", conn->last_time);
        add_assoc_long(return_value, "close_errno", conn->close_errno);
    }
}

static PHP_METHOD(swoole_server, getClientList)
{
    long start_fd = 0;
    long find_count = 10;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ll", &start_fd, &find_count) == FAILURE)
    {
        RETURN_FALSE;
    }

    // exceeded the maximum number of searches
    if (find_count > SW_MAX_FIND_COUNT)
    {
        php_swoole_fatal_error(E_WARNING, "swoole connection list max_find_count=%d", SW_MAX_FIND_COUNT);
        RETURN_FALSE;
    }

    // copy it out to avoid being overwritten by other processes
    int serv_max_fd = swServer_get_maxfd(serv);

    if (start_fd == 0)
    {
        start_fd = swServer_get_minfd(serv);
    }
    else
    {
        swConnection *conn = swWorker_get_connection(serv, start_fd);
        if (!conn)
        {
            RETURN_FALSE;
        }
        start_fd = conn->fd;
    }

    if ((int) start_fd >= serv_max_fd)
    {
        RETURN_FALSE;
    }

    array_init(return_value);
    int fd = start_fd + 1;
    swConnection *conn;

    for (; fd <= serv_max_fd; fd++)
    {
        swTrace("maxfd=%d, fd=%d, find_count=%ld, start_fd=%ld", serv_max_fd, fd, find_count, start_fd);
        conn = &serv->connection_list[fd];

        if (conn->active && !conn->closed)
        {
#ifdef SW_USE_OPENSSL
            if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
            {
                continue;
            }
#endif
            add_next_index_long(return_value, conn->session_id);
            find_count--;
        }
        //finish fetch
        if (find_count <= 0)
        {
            break;
        }
    }
}

static PHP_METHOD(swoole_server, sendwait)
{
    long fd;
    zval *zdata;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz", &fd, &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0)
    {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    if (serv->factory_mode != SW_MODE_BASE || swIsTaskWorker())
    {
        php_swoole_fatal_error(E_WARNING, "can't sendwait");
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(serv->sendwait(serv, fd, data, length));
}

static PHP_METHOD(swoole_server, exists)
{
    zend_long fd;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 || conn->closed)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, protect)
{
    long fd;
    zend_bool value = 1;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|b", &fd, &value) == FAILURE)
    {
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 || conn->closed)
    {
        RETURN_FALSE;
    }
    else
    {
        conn->protect = value;
        RETURN_TRUE;
    }
}

#ifdef SW_BUFFER_RECV_TIME
static PHP_METHOD(swoole_server, getReceivedTime)
{
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (serv->last_receive_usec > 0)
    {
        RETURN_DOUBLE(serv->last_receive_usec);
    }
    else
    {
        RETURN_FALSE;
    }
}
#endif

static PHP_METHOD(swoole_server, shutdown)
{
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (swoole_kill(serv->gs->master_pid, SIGTERM) < 0)
    {
        php_swoole_sys_error(E_WARNING, "failed to shutdown. swKill(%d, SIGTERM) failed", serv->gs->master_pid);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, stop)
{
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (unlikely(!serv->gs->start))
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_bool wait_reactor = 0;
    long worker_id = SwooleWG.id;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lb", &worker_id, &wait_reactor) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_id == SwooleWG.id && wait_reactor == 0)
    {
        if (SwooleG.main_reactor != NULL)
        {
            SwooleG.main_reactor->running = 0;
        }
        SwooleG.running = 0;
    }
    else
    {
        swWorker *worker = swServer_get_worker(serv, worker_id);
        if (worker == NULL)
        {
            RETURN_FALSE;
        }
        else if (swoole_kill(worker->pid, SIGTERM) < 0)
        {
            php_swoole_sys_error(E_WARNING, "swKill(%d, SIGTERM) failed", worker->pid);
            RETURN_FALSE;
        }
    }
    RETURN_TRUE;
}

// swoole_connection_iterator

static PHP_METHOD(swoole_connection_iterator, __construct)
{
    php_swoole_fatal_error(E_ERROR, "please use the Swoole\\Server->connections");
    return;
}

static PHP_METHOD(swoole_connection_iterator, rewind)
{
    swConnectionIterator *itearator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    itearator->index = 0;
    itearator->current_fd = swServer_get_minfd(itearator->serv);
}

static PHP_METHOD(swoole_connection_iterator, valid)
{
    swConnectionIterator *itearator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    int fd = itearator->current_fd;
    swConnection *conn;

    int max_fd = swServer_get_maxfd(itearator->serv);
    for (; fd <= max_fd; fd++)
    {
        conn = &itearator->serv->connection_list[fd];

        if (conn->active && !conn->closed)
        {
#ifdef SW_USE_OPENSSL
            if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
            {
                continue;
            }
#endif
            if (itearator->port && (itearator->port->sock < 0 || conn->server_fd != (uint32_t) itearator->port->sock))
            {
                continue;
            }
            itearator->session_id = conn->session_id;
            itearator->current_fd = fd;
            itearator->index++;
            RETURN_TRUE;
        }
    }

    RETURN_FALSE;
}

static PHP_METHOD(swoole_connection_iterator, current)
{
    swConnectionIterator *itearator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    RETURN_LONG(itearator->session_id);
}

static PHP_METHOD(swoole_connection_iterator, next)
{
    swConnectionIterator *itearator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    itearator->current_fd++;
}

static PHP_METHOD(swoole_connection_iterator, key)
{
    swConnectionIterator *itearator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    RETURN_LONG(itearator->index);
}

static PHP_METHOD(swoole_connection_iterator, count)
{
    swConnectionIterator *i = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    if (i->port)
    {
        RETURN_LONG(i->port->connection_num);
    }
    else
    {
        RETURN_LONG(i->serv->stats->connection_num);
    }
}

static PHP_METHOD(swoole_connection_iterator, offsetExists)
{
    swConnectionIterator *i = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    zval *zserv = (zval *) i->serv->ptr2;
    zval *zfd;
    zval retval;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(zserv, swoole_server_ce, NULL, "exists", &retval, zfd);
    RETVAL_BOOL(Z_BVAL_P(&retval));
}

static PHP_METHOD(swoole_connection_iterator, offsetGet)
{
    swConnectionIterator *i = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    zval *zserv = (zval *) i->serv->ptr2;
    zval *zfd;
    zval retval;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(zserv, swoole_server_ce, NULL, "getClientInfo", &retval, zfd);
    RETVAL_ZVAL(&retval, 0, 0);
}

static PHP_METHOD(swoole_connection_iterator, offsetSet)
{
    return;
}

static PHP_METHOD(swoole_connection_iterator, offsetUnset)
{
    return;
}

static PHP_METHOD(swoole_connection_iterator, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swConnectionIterator *iterator = (swConnectionIterator *) swoole_get_object(ZEND_THIS);
    if (!iterator)
    {
        return;
    }
    efree(iterator);
    swoole_set_object(ZEND_THIS, NULL);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
