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

#include "php_swoole_server.h"
#include "php_swoole_http_server.h"
#include "php_swoole_process.h"
#include "swoole_msg_queue.h"

#include "ext/standard/php_var.h"
#include "zend_smart_str.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

using namespace swoole;

struct ConnectionIterator {
    int current_fd;
    SessionId session_id;
    Server *serv;
    ListenPort *port;
    int index;
};

struct ServerEvent {
    enum php_swoole_server_callback_type type;
    std::string name;
    ServerEvent(enum php_swoole_server_callback_type type, std::string &&name) : type(type), name(name) {}
};

// clang-format off
static std::unordered_map<std::string, ServerEvent> server_event_map({
    { "start",          ServerEvent(SW_SERVER_CB_onStart,           "Start") },
    { "beforeshutdown", ServerEvent(SW_SERVER_CB_onBeforeShutdown,  "BeforeShutdown") },
    { "shutdown",       ServerEvent(SW_SERVER_CB_onShutdown,        "Shutdown") },
    { "workerstart",    ServerEvent(SW_SERVER_CB_onWorkerStart,     "WorkerStart") },
    { "workerstop",     ServerEvent(SW_SERVER_CB_onWorkerStop,      "WorkerStop") },
    { "beforereload",   ServerEvent(SW_SERVER_CB_onBeforeReload,    "BeforeReload") },
    { "afterreload",    ServerEvent(SW_SERVER_CB_onAfterReload,     "AfterReload") },
    { "task",           ServerEvent(SW_SERVER_CB_onTask,            "Task") },
    { "finish",         ServerEvent(SW_SERVER_CB_onFinish,          "Finish") },
    { "workerexit",     ServerEvent(SW_SERVER_CB_onWorkerExit,      "WorkerExit") },
    { "workererror",    ServerEvent(SW_SERVER_CB_onWorkerError,     "WorkerError") },
    { "managerstart",   ServerEvent(SW_SERVER_CB_onManagerStart,    "ManagerStart") },
    { "managerstop",    ServerEvent(SW_SERVER_CB_onManagerStop,     "ManagerStop") },
    { "pipemessage",    ServerEvent(SW_SERVER_CB_onPipeMessage,     "PipeMessage") },
});
// clang-format on

// server event callback
static void php_swoole_server_onStart(Server *);
static void php_swoole_server_onBeforeShutdown(Server *serv);
static void php_swoole_server_onShutdown(Server *);
static void php_swoole_server_onWorkerStart(Server *, int worker_id);
static void php_swoole_server_onBeforeReload(Server *serv);
static void php_swoole_server_onAfterReload(Server *serv);
static void php_swoole_server_onWorkerStop(Server *, int worker_id);
static void php_swoole_server_onWorkerExit(Server *serv, int worker_id);
static void php_swoole_server_onUserWorkerStart(Server *serv, Worker *worker);
static int php_swoole_server_onTask(Server *, EventData *task);
static int php_swoole_server_onFinish(Server *, EventData *task);
static void php_swoole_server_onPipeMessage(Server *serv, EventData *req);
static void php_swoole_server_onWorkerError(Server *serv, int worker_id, const ExitStatus &exit_status);
static void php_swoole_server_onManagerStart(Server *serv);
static void php_swoole_server_onManagerStop(Server *serv);

static int php_swoole_task_finish(Server *serv, zval *zdata, EventData *current_task);
static int php_swoole_server_dispatch_func(Server *serv, Connection *conn, SendData *data);
static zval *php_swoole_server_add_port(ServerObject *server_object, ListenPort *port);

void php_swoole_server_rshutdown() {
    if (!sw_server()) {
        return;
    }

    Server *serv = sw_server();
    serv->drain_worker_pipe();

    if (serv->is_started() && !serv->is_user_worker()) {
        if (php_swoole_is_fatal_error()) {
            swoole_error_log(SW_LOG_ERROR,
                             SW_ERROR_PHP_FATAL_ERROR,
                             "Fatal error: %s in %s on line %d",
                             php_swoole_get_last_error_message(),
                             php_swoole_get_last_error_file(),
                             PG(last_error_lineno));
        } else {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SERVER_WORKER_TERMINATED, "worker process is terminated by exit()/die()");
        }
    }
}

zend_class_entry *swoole_server_ce;
zend_object_handlers swoole_server_handlers;

zend_class_entry *swoole_connection_iterator_ce;
static zend_object_handlers swoole_connection_iterator_handlers;

static zend_class_entry *swoole_server_task_ce;
static zend_object_handlers swoole_server_task_handlers;

static zend_class_entry *swoole_server_event_ce;
static zend_object_handlers swoole_server_event_handlers;

static zend_class_entry *swoole_server_packet_ce;
static zend_object_handlers swoole_server_packet_handlers;

static zend_class_entry *swoole_server_pipe_message_ce;
static zend_object_handlers swoole_server_pipe_message_handlers;

static zend_class_entry *swoole_server_status_info_ce;
static zend_object_handlers swoole_server_status_info_handlers;

static zend_class_entry *swoole_server_task_result_ce;
static zend_object_handlers swoole_server_task_result_handlers;

static sw_inline ServerObject *server_fetch_object(zend_object *obj) {
    return (ServerObject *) ((char *) obj - swoole_server_handlers.offset);
}

static sw_inline Server *server_get_ptr(zval *zobject) {
    return server_fetch_object(Z_OBJ_P(zobject))->serv;
}

Server *php_swoole_server_get_and_check_server(zval *zobject) {
    Server *serv = server_get_ptr(zobject);
    if (UNEXPECTED(!serv)) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return serv;
}

zval *php_swoole_server_get_zval_object(Server *serv) {
    return (zval *) serv->private_data_2;
}

ServerObject *php_swoole_server_get_zend_object(Server *serv) {
    return server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
}

bool php_swoole_server_isset_callback(Server *serv, ListenPort *port, int event_type) {
    ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
    return server_object->isset_callback(port, event_type);
}

static sw_inline void server_set_ptr(zval *zobject, Server *serv) {
    server_fetch_object(Z_OBJ_P(zobject))->serv = serv;
}

static void server_free_object(zend_object *object) {
    ServerObject *server_object = server_fetch_object(object);
    ServerProperty *property = server_object->property;
    Server *serv = server_object->serv;

    if (serv) {
        if (serv->private_data_3) {
            sw_zend_fci_cache_discard((zend_fcall_info_cache *) serv->private_data_3);
            efree(serv->private_data_3);
        }
        if (serv->private_data_2) {
            efree(serv->private_data_2);
        }
        for (int i = 0; i < PHP_SWOOLE_SERVER_CALLBACK_NUM; i++) {
            zend_fcall_info_cache *fci_cache = property->callbacks[i];
            if (fci_cache) {
                efree(fci_cache);
                property->callbacks[i] = nullptr;
            }
        }
        for (auto i = property->user_processes.begin(); i != property->user_processes.end(); i++) {
            sw_zval_free(*i);
        }
        for (auto zport : property->ports) {
            php_swoole_server_port_deref(Z_OBJ_P(zport));
            efree(zport);
        }
        server_object->serv = nullptr;
    }

    for (auto fci_cache : property->command_callbacks) {
        sw_zend_fci_cache_discard(fci_cache);
        efree(fci_cache);
    }

    delete property;

    zend_object_std_dtor(object);
    if (serv && serv->is_master()) {
        delete serv;
    }
}

static zend_object *server_create_object(zend_class_entry *ce) {
    ServerObject *server_object = (ServerObject *) zend_object_alloc(sizeof(ServerObject), ce);
    zend_object_std_init(&server_object->std, ce);
    object_properties_init(&server_object->std, ce);
    server_object->std.handlers = &swoole_server_handlers;
    server_object->property = new ServerProperty();
    return &server_object->std;
}

struct ConnectionIteratorObject {
    ConnectionIterator iterator;
    zend_object std;
};

static sw_inline ConnectionIteratorObject *php_swoole_connection_iterator_fetch_object(zend_object *obj) {
    return (ConnectionIteratorObject *) ((char *) obj - swoole_connection_iterator_handlers.offset);
}

static sw_inline ConnectionIterator *php_swoole_connection_iterator_get_ptr(zval *zobject) {
    return &php_swoole_connection_iterator_fetch_object(Z_OBJ_P(zobject))->iterator;
}

ConnectionIterator *php_swoole_connection_iterator_get_and_check_ptr(zval *zobject) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_ptr(zobject);
    if (UNEXPECTED(!iterator->serv)) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return iterator;
}

static void php_swoole_connection_iterator_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_connection_iterator_create_object(zend_class_entry *ce) {
    ConnectionIteratorObject *connection =
        (ConnectionIteratorObject *) zend_object_alloc(sizeof(ConnectionIteratorObject), ce);
    zend_object_std_init(&connection->std, ce);
    object_properties_init(&connection->std, ce);
    connection->std.handlers = &swoole_connection_iterator_handlers;
    return &connection->std;
}

struct ServerTaskObject {
    Server *serv;
    DataHead info;
    zend_object std;
};

static sw_inline ServerTaskObject *php_swoole_server_task_fetch_object(zend_object *obj) {
    return (ServerTaskObject *) ((char *) obj - swoole_server_task_handlers.offset);
}

static sw_inline Server *php_swoole_server_task_get_server(zval *zobject) {
    Server *serv = php_swoole_server_task_fetch_object(Z_OBJ_P(zobject))->serv;
    if (!serv) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return serv;
}

static sw_inline void php_swoole_server_task_set_server(zval *zobject, Server *serv) {
    php_swoole_server_task_fetch_object(Z_OBJ_P(zobject))->serv = serv;
}

static sw_inline DataHead *php_swoole_server_task_get_info(zval *zobject) {
    ServerTaskObject *task = php_swoole_server_task_fetch_object(Z_OBJ_P(zobject));
    if (!task->serv) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return &task->info;
}

static sw_inline void php_swoole_server_task_set_info(zval *zobject, DataHead *info) {
    php_swoole_server_task_fetch_object(Z_OBJ_P(zobject))->info = *info;
}

static void php_swoole_server_task_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_server_task_create_object(zend_class_entry *ce) {
    ServerTaskObject *server_task = (ServerTaskObject *) zend_object_alloc(sizeof(ServerTaskObject), ce);
    zend_object_std_init(&server_task->std, ce);
    object_properties_init(&server_task->std, ce);
    server_task->std.handlers = &swoole_server_task_handlers;
    return &server_task->std;
}

// arginfo server
// clang-format off
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
    ZEND_ARG_INFO(0, task_worker_index)
    ZEND_ARG_CALLABLE_INFO(0, finish_callback, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, task_worker_index)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task_pack, 0, 0, 1)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_command, 0, 0, 4)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, process_id)
    ZEND_ARG_INFO(0, process_type)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, json_encode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addProcess, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, process, swoole_process, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addCommand, 0, 0, 3)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, accepted_process_types)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientInfo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reactor_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getWorkerStatus, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getWorkerPid, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientList, 0, 0, 1)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

//arginfo connection_iterator
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_rewind, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_next, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_current, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_key, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_valid, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetExists, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetGet, 0, 1, IS_MIXED, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetUnset, 0, 1, IS_VOID, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetSet, 0, 2, IS_VOID, 0)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()
// arginfo end
// clang-format on

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_server, __construct);
static PHP_METHOD(swoole_server, __destruct);
static PHP_METHOD(swoole_server, set);
static PHP_METHOD(swoole_server, on);
static PHP_METHOD(swoole_server, getCallback);
static PHP_METHOD(swoole_server, listen);
static PHP_METHOD(swoole_server, sendMessage);
static PHP_METHOD(swoole_server, addProcess);
static PHP_METHOD(swoole_server, addCommand);
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
static PHP_METHOD(swoole_server, command);
static PHP_METHOD(swoole_server, getClientList);
static PHP_METHOD(swoole_server, getClientInfo);
static PHP_METHOD(swoole_server, getWorkerId);
static PHP_METHOD(swoole_server, getWorkerPid);
static PHP_METHOD(swoole_server, getWorkerStatus);
static PHP_METHOD(swoole_server, getManagerPid);
static PHP_METHOD(swoole_server, getMasterPid);
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
static PHP_METHOD(swoole_server_task, pack);
SW_EXTERN_C_END

// clang-format off

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
    PHP_MALIAS(swoole_server, confirm, resume, arginfo_swoole_server_resume, ZEND_ACC_PUBLIC)
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
    PHP_ME(swoole_server, getClientInfo, arginfo_swoole_server_getClientInfo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getClientList, arginfo_swoole_server_getClientList, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getWorkerId, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getWorkerPid, arginfo_swoole_server_getWorkerPid, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getWorkerStatus, arginfo_swoole_server_getWorkerStatus, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getManagerPid, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getMasterPid, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    //psr-0 style
    PHP_MALIAS(swoole_server, connection_info, getClientInfo, arginfo_swoole_server_getClientInfo, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_server, connection_list, getClientList, arginfo_swoole_server_getClientList, ZEND_ACC_PUBLIC)
    //process
    PHP_ME(swoole_server, sendMessage, arginfo_swoole_server_sendMessage, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, command, arginfo_swoole_server_command, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, addCommand, arginfo_swoole_server_addCommand, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, addProcess, arginfo_swoole_server_addProcess, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_server, getSocket, arginfo_swoole_server_getSocket, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_server, bind, arginfo_swoole_server_bind, ZEND_ACC_PUBLIC)
    {nullptr, nullptr, nullptr}
};

static const zend_function_entry swoole_connection_iterator_methods[] =
{
    PHP_ME(swoole_connection_iterator, __construct,  arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, __destruct,  arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, rewind,      arginfo_swoole_connection_iterator_rewind, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, next,        arginfo_swoole_connection_iterator_next, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, current,     arginfo_swoole_connection_iterator_current, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, key,         arginfo_swoole_connection_iterator_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, valid,       arginfo_swoole_connection_iterator_valid, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, count,       arginfo_swoole_connection_iterator_count, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetExists,    arginfo_swoole_connection_iterator_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetGet,       arginfo_swoole_connection_iterator_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetSet,       arginfo_swoole_connection_iterator_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, offsetUnset,     arginfo_swoole_connection_iterator_offsetUnset, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_server_task_methods[] =
{
    PHP_ME(swoole_server_task, finish, arginfo_swoole_server_finish, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_task, pack, arginfo_swoole_server_task_pack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_server_minit(int module_number) {
    // ---------------------------------------Server-------------------------------------
    SW_INIT_CLASS_ENTRY(swoole_server, "Swoole\\Server", "swoole_server", nullptr, swoole_server_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_server);
    SW_SET_CLASS_CLONEABLE(swoole_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_server, server_create_object, server_free_object, ServerObject, std);

    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "after", &swoole_server_ce->function_table, "after");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "tick", &swoole_server_ce->function_table, "tick");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "clear", &swoole_server_ce->function_table, "clearTimer");

    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "defer", &swoole_server_ce->function_table, "defer");

    // ---------------------------------------Task-------------------------------------
    SW_INIT_CLASS_ENTRY(
        swoole_server_task, "Swoole\\Server\\Task", "swoole_server_task", nullptr, swoole_server_task_methods);
    swoole_server_task_ce->ce_flags |= ZEND_ACC_FINAL;
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_server_task);
    SW_SET_CLASS_CLONEABLE(swoole_server_task, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server_task, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_server_task,
                               php_swoole_server_task_create_object,
                               php_swoole_server_task_free_object,
                               ServerTaskObject,
                               std);
    zend_declare_property_null(swoole_server_task_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    zend_declare_property_double(swoole_server_task_ce, ZEND_STRL("dispatch_time"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("id"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("worker_id"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PUBLIC);
    // ---------------------------------------Event-------------------------------------
    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_server_event, "Swoole\\Server\\Event");
    zend_declare_property_long(swoole_server_event_ce, ZEND_STRL("reactor_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_event_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_double(swoole_server_event_ce, ZEND_STRL("dispatch_time"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_event_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    // ---------------------------------------Packet-------------------------------------
    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_server_packet, "Swoole\\Server\\Packet");
    zend_declare_property_long(swoole_server_packet_ce, ZEND_STRL("server_socket"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_packet_ce, ZEND_STRL("server_port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_double(swoole_server_packet_ce, ZEND_STRL("dispatch_time"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_packet_ce, ZEND_STRL("address"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_packet_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    // ---------------------------------------PipeMessage-------------------------------------
    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_server_pipe_message, "Swoole\\Server\\PipeMessage");
    zend_declare_property_long(swoole_server_pipe_message_ce, ZEND_STRL("source_worker_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_double(swoole_server_pipe_message_ce, ZEND_STRL("dispatch_time"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_pipe_message_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    // ---------------------------------------StatusInfo-------------------------------------
    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_server_status_info, "Swoole\\Server\\StatusInfo");
    zend_declare_property_long(swoole_server_status_info_ce, ZEND_STRL("worker_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_status_info_ce, ZEND_STRL("worker_pid"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_status_info_ce, ZEND_STRL("status"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_status_info_ce, ZEND_STRL("exit_code"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_status_info_ce, ZEND_STRL("signal"), 0, ZEND_ACC_PUBLIC);
    // ---------------------------------------TaskResult-------------------------------------
    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_server_task_result, "Swoole\\Server\\TaskResult");
    zend_declare_property_long(swoole_server_task_result_ce, ZEND_STRL("task_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_task_result_ce, ZEND_STRL("task_worker_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_double(swoole_server_task_result_ce, ZEND_STRL("dispatch_time"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_task_result_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    // ---------------------------------------Connection Iterator-------------------------------------
    SW_INIT_CLASS_ENTRY(swoole_connection_iterator,
                        "Swoole\\Connection\\Iterator",
                        "swoole_connection_iterator",
                        nullptr,
                        swoole_connection_iterator_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_connection_iterator);
    SW_SET_CLASS_CLONEABLE(swoole_connection_iterator, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_connection_iterator, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_connection_iterator,
                               php_swoole_connection_iterator_create_object,
                               php_swoole_connection_iterator_free_object,
                               ConnectionIteratorObject,
                               std);
    zend_class_implements(swoole_connection_iterator_ce, 2, zend_ce_iterator, zend_ce_arrayaccess);
#ifdef SW_HAVE_COUNTABLE
    zend_class_implements(swoole_connection_iterator_ce, 1, zend_ce_countable);
#endif
    // ---------------------------------------Server Property-------------------------------------
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onStart"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onBeforeShutdown"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onShutdown"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerStart"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onWorkerStop"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onBeforeReload"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("onAfterReload"), ZEND_ACC_PRIVATE);
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
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("stats_timer"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_ce, ZEND_STRL("admin_server"), ZEND_ACC_PUBLIC);

    /**
     * mode type
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_BASE", swoole::Server::MODE_BASE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", swoole::Server::MODE_PROCESS);

    /**
     * task ipc mode
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_UNSOCK", Server::TASK_IPC_UNIXSOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_MSGQUEUE", Server::TASK_IPC_MSGQUEUE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_PREEMPTIVE", Server::TASK_IPC_PREEMPTIVE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_MASTER", Server::Command::MASTER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_MANAGER", Server::Command::MANAGER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_REACTOR_THREAD", Server::Command::REACTOR_THREAD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_EVENT_WORKER", Server::Command::EVENT_WORKER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_WORKER", Server::Command::EVENT_WORKER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SERVER_COMMAND_TASK_WORKER", Server::Command::TASK_WORKER);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_ROUND", Server::DISPATCH_ROUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_FDMOD", Server::DISPATCH_FDMOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_IDLE_WORKER", Server::DISPATCH_IDLE_WORKER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_IPMOD", Server::DISPATCH_IPMOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_UIDMOD", Server::DISPATCH_UIDMOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_USERFUNC", Server::DISPATCH_USERFUNC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_STREAM", Server::DISPATCH_STREAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_CO_CONN_LB", Server::DISPATCH_CO_CONN_LB);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_CO_REQ_LB", Server::DISPATCH_CO_REQ_LB);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_DISCARD_PACKET", Server::DISPATCH_RESULT_DISCARD_PACKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_CLOSE_CONNECTION", Server::DISPATCH_RESULT_CLOSE_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DISPATCH_RESULT_USERFUNC_FALLBACK", Server::DISPATCH_RESULT_USERFUNC_FALLBACK);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_TMPFILE", SW_TASK_TMPFILE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_SERIALIZE", SW_TASK_SERIALIZE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_NONBLOCK", SW_TASK_NONBLOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_CALLBACK", SW_TASK_CALLBACK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_WAITALL", SW_TASK_WAITALL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_COROUTINE", SW_TASK_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_PEEK", SW_TASK_PEEK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TASK_NOREPLY", SW_TASK_NOREPLY);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_WORKER_BUSY", SW_WORKER_BUSY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WORKER_IDLE", SW_WORKER_IDLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WORKER_EXIT", SW_WORKER_EXIT);
}

zend_fcall_info_cache *php_swoole_server_get_fci_cache(Server *serv, int server_fd, int event_type) {
    ListenPort *port = serv->get_port_by_server_fd(server_fd);
    ServerPortProperty *property;
    zend_fcall_info_cache *fci_cache;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));

    if (sw_unlikely(!port)) {
        return nullptr;
    }
    if ((property = (ServerPortProperty *) port->ptr) && (fci_cache = property->caches[event_type])) {
        return fci_cache;
    } else {
        return server_object->property->primary_port->caches[event_type];
    }
}

int php_swoole_create_dir(const char *path, size_t length) {
    if (access(path, F_OK) == 0) {
        return 0;
    }
    return php_stream_mkdir(path, 0777, PHP_STREAM_MKDIR_RECURSIVE | REPORT_ERRORS, nullptr) ? 0 : -1;
}

TaskId php_swoole_task_pack(EventData *task, zval *zdata) {
    smart_str serialized_data = {};
    php_serialize_data_t var_hash;

    bool serialized = false;
    char *task_data_str;
    size_t task_data_len = 0;
    // need serialize
    if (Z_TYPE_P(zdata) != IS_STRING) {
        // serialize
        serialized = true;

        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, zdata, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

        if (!serialized_data.s) {
            return -1;
        }
        task_data_str = ZSTR_VAL(serialized_data.s);
        task_data_len = ZSTR_LEN(serialized_data.s);
    } else {
        task_data_str = Z_STRVAL_P(zdata);
        task_data_len = Z_STRLEN_P(zdata);
    }

    if (!Server::task_pack(task, task_data_str, task_data_len)) {
        php_swoole_fatal_error(E_WARNING, "large task pack failed");
        task->info.fd = SW_ERR;
        task->info.len = 0;
    }

    if (serialized) {
        task->info.ext_flags |= SW_TASK_SERIALIZE;
    }

    smart_str_free(&serialized_data);
    return task->info.fd;
}

void php_swoole_get_recv_data(Server *serv, zval *zdata, RecvData *req) {
    const char *data = req->data;
    uint32_t length = req->info.len;
    if (length == 0) {
        ZVAL_EMPTY_STRING(zdata);
    } else {
        if (req->info.flags & SW_EVENT_DATA_OBJ_PTR) {
            zend::assign_zend_string_by_val(zdata, (char *) data, length);
            serv->message_bus.move_packet();
        } else if (req->info.flags & SW_EVENT_DATA_POP_PTR) {
            String *recv_buffer = serv->get_recv_buffer(serv->get_connection_by_session_id(req->info.fd)->socket);
            zend::assign_zend_string_by_val(zdata, recv_buffer->pop(serv->recv_buffer_size), length);
        } else {
            ZVAL_STRINGL(zdata, data, length);
        }
    }
}

static sw_inline int php_swoole_check_task_param(Server *serv, zend_long dst_worker_id) {
    if (UNEXPECTED(serv->task_worker_num == 0)) {
        php_swoole_fatal_error(E_WARNING, "task method can't be executed without task worker");
        return SW_ERR;
    }
    if (UNEXPECTED(dst_worker_id > 0 && dst_worker_id >= serv->task_worker_num)) {
        php_swoole_fatal_error(E_WARNING, "worker_id must be less than task_worker_num[%u]", serv->task_worker_num);
        return SW_ERR;
    }
    if (UNEXPECTED(serv->is_task_worker())) {
        php_swoole_fatal_error(E_WARNING, "Server->task() cannot use in the task-worker");
        return SW_ERR;
    }
    return SW_OK;
}

zval *php_swoole_task_unpack(EventData *task_result) {
    zval *result_data, *result_unserialized_data;
    php_unserialize_data_t var_hash;
    PacketPtr packet;

    if (!Server::task_unpack(task_result, sw_tg_buffer(), &packet)) {
        return nullptr;
    }

    char *result_data_str = packet.data;
    size_t result_data_len = packet.length;

    if (task_result->info.ext_flags & SW_TASK_SERIALIZE) {
        result_unserialized_data = sw_malloc_zval();

        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        // unserialize success
        if (php_var_unserialize(result_unserialized_data,
                                (const unsigned char **) &result_data_str,
                                (const unsigned char *) (result_data_str + result_data_len),
                                &var_hash)) {
            result_data = result_unserialized_data;
        }
        // failed
        else {
            result_data = sw_malloc_zval();
            ZVAL_STRINGL(result_data, result_data_str, result_data_len);
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    } else {
        result_data = sw_malloc_zval();
        ZVAL_STRINGL(result_data, result_data_str, result_data_len);
    }
    return result_data;
}

extern ListenPort *php_swoole_server_port_get_and_check_ptr(zval *zobject);
extern void php_swoole_server_port_set_ptr(zval *zobject, ListenPort *port);
extern ServerPortProperty *php_swoole_server_port_get_property(zval *zobject);

static zval *php_swoole_server_add_port(ServerObject *server_object, ListenPort *port) {
    /* port */
    zval *zport;
    Server *serv = server_object->serv;

    zport = sw_malloc_zval();
    object_init_ex(zport, swoole_server_port_ce);
    server_object->property->ports.push_back(zport);

    /* port ptr */
    php_swoole_server_port_set_ptr(zport, port);

    /* port property */
    ServerPortProperty *property = php_swoole_server_port_get_property(zport);
    property->serv = serv;
    property->port = port;

    /* linked */
    port->ptr = property;

    zend_update_property_string(swoole_server_port_ce, SW_Z8_OBJ_P(zport), ZEND_STRL("host"), port->get_host());
    zend_update_property_long(swoole_server_port_ce, SW_Z8_OBJ_P(zport), ZEND_STRL("port"), port->get_port());
    zend_update_property_long(swoole_server_port_ce, SW_Z8_OBJ_P(zport), ZEND_STRL("type"), port->get_type());
    zend_update_property_long(swoole_server_port_ce, SW_Z8_OBJ_P(zport), ZEND_STRL("sock"), port->get_fd());

    do {
        zval *zserv = (zval *) serv->private_data_2;
        zval *zports = sw_zend_read_and_convert_property_array(Z_OBJCE_P(zserv), zserv, ZEND_STRL("ports"), 0);
        (void) add_next_index_zval(zports, zport);
    } while (0);

    /* iterator */
    do {
        zval connection_iterator;
        object_init_ex(&connection_iterator, swoole_connection_iterator_ce);

        ConnectionIterator *iterator = php_swoole_connection_iterator_get_ptr(&connection_iterator);
        iterator->serv = serv;
        iterator->port = port;

        zend_update_property(swoole_server_port_ce, SW_Z8_OBJ_P(zport), ZEND_STRL("connections"), &connection_iterator);
        zval_ptr_dtor(&connection_iterator);
    } while (0);

    return zport;
}

void ServerObject::on_before_start() {
    /**
     * create swoole server
     */
    if (serv->create() < 0) {
        php_swoole_fatal_error(E_ERROR, "failed to create the server. Error: %s", sw_error);
        return;
    }

    zval *zobject = get_object();
    auto primary_port = serv->get_primary_port();

#ifdef SW_LOG_TRACE_OPEN
    swoole_trace_log(SW_TRACE_SERVER,
                     "Create Server: host=%s, port=%d, mode=%d, type=%d",
                     primary_port->host.c_str(),
                     (int) primary_port->port,
                     serv->is_base_mode() ? Server::MODE_BASE : Server::MODE_PROCESS,
                     (int) primary_port->type);
#endif

    if (serv->enable_coroutine) {
        serv->reload_async = 1;
    }

    if (serv->send_yield) {
        if (serv->onClose == nullptr && serv->is_support_unsafe_events()) {
            serv->onClose = php_swoole_server_onClose;
        }
    }

    serv->message_bus.set_allocator(sw_zend_string_allocator());

    if (serv->is_base_mode()) {
        serv->recv_buffer_allocator = sw_zend_string_allocator();
    }

    /**
     * Master Process ID
     */
    zend_update_property_long(get_ce(), SW_Z8_OBJ_P(zobject), ZEND_STRL("master_pid"), getpid());

    zval *zsetting = sw_zend_read_and_convert_property_array(get_ce(), zobject, ZEND_STRL("setting"), 0);

    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("worker_num"))) {
        add_assoc_long(zsetting, "worker_num", serv->worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("task_worker_num"))) {
        add_assoc_long(zsetting, "task_worker_num", serv->task_worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("output_buffer_size"))) {
        add_assoc_long(zsetting, "output_buffer_size", serv->output_buffer_size);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("max_connection"))) {
        add_assoc_long(zsetting, "max_connection", serv->get_max_connection());
    }
    // for admin_server
    if (zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("admin_server"))) {
        swoole::register_admin_server_commands(serv);
    }

    bool find_http_port = false;
    if (is_redis_server()) {
        add_assoc_bool(zsetting, "open_redis_protocol", 1);
        add_assoc_bool(zsetting, "open_http_protocol", 0);
        add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
        add_assoc_bool(zsetting, "open_eof_check", 0);
        add_assoc_bool(zsetting, "open_length_check", 0);
        primary_port->clear_protocol();
        primary_port->open_redis_protocol = 1;
        serv->onReceive = php_swoole_redis_server_onReceive;
    } else if (is_http_server()) {
        if (is_websocket_server()) {
            if (!isset_callback(primary_port, SW_SERVER_CB_onMessage)) {
                php_swoole_fatal_error(E_ERROR, "require onMessage callback");
                return;
            }
        } else if (!isset_callback(primary_port, SW_SERVER_CB_onRequest)) {
            php_swoole_fatal_error(E_ERROR, "require onRequest callback");
            return;
        }

        add_assoc_bool(zsetting, "open_http_protocol", 1);
        add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
        add_assoc_bool(zsetting, "open_eof_check", 0);
        add_assoc_bool(zsetting, "open_length_check", 0);

        enum protocol_flags { SW_HTTP2_PROTOCOL = 1u << 1, SW_WEBSOCKET_PROTOCOL = 1u << 2 };
        uint8_t protocol_flag = 0;
        if (primary_port->open_http2_protocol) {
            add_assoc_bool(zsetting, "open_http2_protocol", 1);
            protocol_flag |= SW_HTTP2_PROTOCOL;
        }
        if (primary_port->open_websocket_protocol || is_websocket_server()) {
            add_assoc_bool(zsetting, "open_websocket_protocol", 1);
            protocol_flag |= SW_WEBSOCKET_PROTOCOL;
        }
        primary_port->clear_protocol();
        primary_port->open_http_protocol = 1;
        primary_port->open_http2_protocol = !!(protocol_flag & SW_HTTP2_PROTOCOL);
        primary_port->open_websocket_protocol = !!(protocol_flag & SW_WEBSOCKET_PROTOCOL);
        find_http_port = true;
        serv->onReceive = php_swoole_http_server_onReceive;
    } else {
        if (serv->if_require_packet_callback(primary_port, isset_callback(primary_port, SW_SERVER_CB_onPacket))) {
            php_swoole_fatal_error(E_ERROR, "require onPacket callback");
            return;
        }
        if (serv->if_require_receive_callback(primary_port, isset_callback(primary_port, SW_SERVER_CB_onReceive))) {
            php_swoole_fatal_error(E_ERROR, "require onReceive callback");
            return;
        }
        serv->onReceive = php_swoole_server_onReceive;
    }

    for (size_t i = 1; i < property->ports.size(); i++) {
        zval *zport = property->ports.at(i);
        zval *zport_setting =
            sw_zend_read_property_ex(swoole_server_port_ce, zport, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
        // use swoole_server->setting
        if (zport_setting == nullptr || ZVAL_IS_NULL(zport_setting)) {
            Z_TRY_ADDREF_P(zport);
            sw_zend_call_method_with_1_params(zport, swoole_server_port_ce, nullptr, "set", nullptr, zsetting);
        }
    }

    for (size_t i = 0; i < property->ports.size(); i++) {
        zval *zport = property->ports.at(i);
        ListenPort *port = php_swoole_server_port_get_and_check_ptr(zport);

        if (serv->if_require_packet_callback(port, isset_callback(port, SW_SERVER_CB_onPacket))) {
            php_swoole_fatal_error(E_ERROR, "require onPacket callback");
            return;
        }

#ifdef SW_USE_OPENSSL
        if (port->ssl_context && port->ssl_context->verify_peer && port->ssl_context->client_cert_file.empty()) {
            php_swoole_fatal_error(E_ERROR, "server open verify peer require client_cert_file config");
            return;
        }
#endif
        if (port->open_http2_protocol && !serv->is_hash_dispatch_mode()) {
            php_swoole_fatal_error(
                E_ERROR,
                "server dispatch mode should be FDMOD(%d) or IPMOD(%d) if open_http2_protocol is true",
                Server::DISPATCH_FDMOD,
                Server::DISPATCH_IPMOD);
            return;
        }

        if (!port->open_http_protocol) {
            port->open_http_protocol = port->open_websocket_protocol || port->open_http2_protocol;
        }
        if (port->open_http_protocol) {
            find_http_port = true;
            if (port->open_websocket_protocol) {
                if (!isset_callback(port, SW_SERVER_CB_onMessage) && !isset_callback(port, SW_SERVER_CB_onReceive)) {
                    php_swoole_fatal_error(E_ERROR, "require onMessage callback");
                    return;
                }
            } else if (port->open_http_protocol && !isset_callback(port, SW_SERVER_CB_onRequest) &&
                       !isset_callback(port, SW_SERVER_CB_onReceive)) {
                php_swoole_fatal_error(E_ERROR, "require onRequest callback");
                return;
            }
            if (!is_http_server() && isset_callback(port, SW_SERVER_CB_onRequest)) {
                php_swoole_error(
                    E_WARNING,
                    "use %s class and open http related protocols may lead to some errors (inconsistent class type)",
                    SW_Z_OBJCE_NAME_VAL_P(zobject));
            }
        } else if (!port->open_redis_protocol) {
            // redis server does not require to set receive callback
            if (port->is_stream() && !isset_callback(port, SW_SERVER_CB_onReceive)) {
                php_swoole_fatal_error(E_ERROR, "require onReceive callback");
                return;
            }
        }
    }

    if (find_http_port) {
        serv->onReceive = php_swoole_http_server_onReceive;
        php_swoole_http_server_init_global_variant();
    }

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onBeforeStart", 1, zobject);
    }
}

void ServerObject::register_callback() {
    // control plane
    serv->onStart = php_swoole_server_onStart;
    serv->onBeforeShutdown = php_swoole_server_onBeforeShutdown;
    serv->onShutdown = php_swoole_server_onShutdown;
    serv->onWorkerStart = php_swoole_server_onWorkerStart;
    serv->onWorkerStop = php_swoole_server_onWorkerStop;
    serv->onWorkerExit = php_swoole_server_onWorkerExit;
    serv->onBeforeReload = php_swoole_server_onBeforeReload;
    serv->onAfterReload = php_swoole_server_onAfterReload;
    serv->onManagerStart = php_swoole_server_onManagerStart;
    serv->onManagerStop = php_swoole_server_onManagerStop;
    serv->onWorkerError = php_swoole_server_onWorkerError;

    // data plane
    if (property->callbacks[SW_SERVER_CB_onTask] != nullptr) {
        serv->onTask = php_swoole_server_onTask;
        serv->onFinish = php_swoole_server_onFinish;
    }
    if (property->callbacks[SW_SERVER_CB_onPipeMessage] != nullptr) {
        serv->onPipeMessage = php_swoole_server_onPipeMessage;
    }
    if (serv->send_yield && serv->is_support_unsafe_events()) {
        serv->onBufferEmpty = php_swoole_server_onBufferEmpty;
    }
}

static int php_swoole_task_finish(Server *serv, zval *zdata, EventData *current_task) {
    int flags = 0;
    smart_str serialized_data = {};
    php_serialize_data_t var_hash;
    char *data_str;
    size_t data_len = 0;
    int ret;

    // need serialize
    if (Z_TYPE_P(zdata) != IS_STRING) {
        // serialize
        flags |= SW_TASK_SERIALIZE;

        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, zdata, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        data_str = ZSTR_VAL(serialized_data.s);
        data_len = ZSTR_LEN(serialized_data.s);

    } else {
        data_str = Z_STRVAL_P(zdata);
        data_len = Z_STRLEN_P(zdata);
    }

    ret = serv->reply_task_result(data_str, data_len, flags, current_task);
    smart_str_free(&serialized_data);
    return ret;
}

static void php_swoole_server_onPipeMessage(Server *serv, EventData *req) {
    ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
    zend_fcall_info_cache *fci_cache = server_object->property->callbacks[SW_SERVER_CB_onPipeMessage];
    zval *zserv = (zval *) serv->private_data_2;

    zval *zdata = php_swoole_task_unpack(req);
    if (UNEXPECTED(zdata == nullptr)) {
        return;
    }

    swoole_trace_log(SW_TRACE_SERVER,
                     "PipeMessage: fd=%ld|len=%d|src_worker_id=%d|data=%.*s\n",
                     req->info.fd,
                     req->info.len,
                     req->info.reactor_id,
                     req->info.len,
                     req->data);

    zval args[3];
    int argc;
    args[0] = *zserv;

    if (serv->event_object) {
        zval *object = &args[1];
        object_init_ex(object, swoole_server_pipe_message_ce);
        zend_update_property_long(swoole_server_pipe_message_ce,
                                  SW_Z8_OBJ_P(object),
                                  ZEND_STRL("worker_id"),
                                  (zend_long) req->info.reactor_id);
        zend_update_property_double(
            swoole_server_pipe_message_ce, SW_Z8_OBJ_P(object), ZEND_STRL("dispatch_time"), req->info.time);
        zend_update_property(swoole_server_pipe_message_ce, SW_Z8_OBJ_P(object), ZEND_STRL("data"), zdata);
        argc = 2;
    } else {
        ZVAL_LONG(&args[1], (zend_long) req->info.reactor_id);
        args[2] = *zdata;
        argc = 3;
    }

    if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onPipeMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    if (serv->event_object) {
        zval_ptr_dtor(&args[1]);
    }

    sw_zval_free(zdata);
}

int php_swoole_server_onReceive(Server *serv, RecvData *req) {
    auto fci_cache = php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onReceive);

    if (fci_cache) {
        zval *zserv = (zval *) serv->private_data_2;
        zval args[4];
        int argc;

        args[0] = *zserv;

        if (serv->event_object) {
            zval *object = &args[1];
            zval data;
            object_init_ex(object, swoole_server_event_ce);
            zend_update_property_long(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("fd"), (zend_long) req->info.fd);
            zend_update_property_long(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("reactor_id"), (zend_long) req->info.reactor_id);
            zend_update_property_double(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("dispatch_time"), req->info.time);
            php_swoole_get_recv_data(serv, &data, req);
            zend_update_property(swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("data"), &data);
            zval_ptr_dtor(&data);
            argc = 2;
        } else {
            ZVAL_LONG(&args[1], (zend_long) req->info.fd);
            ZVAL_LONG(&args[2], (zend_long) req->info.reactor_id);
            php_swoole_get_recv_data(serv, &args[3], req);
            argc = 4;
        }

        if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->enable_coroutine))) {
            php_swoole_error(E_WARNING, "%s->onReceive handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
            serv->close(req->info.fd, false);
        }
        if (serv->event_object) {
            zval_ptr_dtor(&args[1]);
        } else {
            zval_ptr_dtor(&args[3]);
        }
    }

    return SW_OK;
}

int php_swoole_server_onPacket(Server *serv, RecvData *req) {
    zval *zserv = (zval *) serv->private_data_2;
    zval args[3];
    int argc;

    args[0] = *zserv;

    DgramPacket *packet = (DgramPacket *) req->data;

    if (serv->event_object) {
        zval zobject;
        object_init_ex(&zobject, swoole_server_packet_ce);
        zend_update_property_long(
            swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("server_socket"), req->info.server_fd);
        zend_update_property_double(
            swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("dispatch_time"), req->info.time);

        Connection *server_sock = serv->get_connection(req->info.server_fd);
        if (server_sock) {
            zend_update_property_long(
                swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("server_port"), server_sock->info.get_port());
        }

        char address[INET6_ADDRSTRLEN];
        if (packet->socket_type == SW_SOCK_UDP) {
            inet_ntop(AF_INET, &packet->socket_addr.addr.inet_v4.sin_addr, address, sizeof(address));
            zend_update_property_string(swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("address"), address);
            zend_update_property_long(swoole_server_packet_ce,
                                      SW_Z8_OBJ_P(&zobject),
                                      ZEND_STRL("port"),
                                      ntohs(packet->socket_addr.addr.inet_v4.sin_port));
        } else if (packet->socket_type == SW_SOCK_UDP6) {
            inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, address, sizeof(address));
            zend_update_property_string(swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("address"), address);
            zend_update_property_long(swoole_server_packet_ce,
                                      SW_Z8_OBJ_P(&zobject),
                                      ZEND_STRL("port"),
                                      ntohs(packet->socket_addr.addr.inet_v6.sin6_port));
        } else if (packet->socket_type == SW_SOCK_UNIX_DGRAM) {
            zend_update_property_string(swoole_server_packet_ce,
                                        SW_Z8_OBJ_P(&zobject),
                                        ZEND_STRL("address"),
                                        packet->socket_addr.addr.un.sun_path);
        }
        zend_update_property_stringl(
            swoole_server_packet_ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("data"), packet->data, packet->length);
        args[1] = zobject;
        argc = 2;
    } else {
        zval zaddr;
        array_init(&zaddr);
        add_assoc_long(&zaddr, "server_socket", req->info.server_fd);
        add_assoc_double(&zaddr, "dispatch_time", req->info.time);
        Connection *server_sock = serv->get_connection(req->info.server_fd);
        if (server_sock) {
            add_assoc_long(&zaddr, "server_port", server_sock->info.get_port());
        }

        char address[INET6_ADDRSTRLEN];
        if (packet->socket_type == SW_SOCK_UDP) {
            inet_ntop(AF_INET, &packet->socket_addr.addr.inet_v4.sin_addr, address, sizeof(address));
            add_assoc_string(&zaddr, "address", address);
            add_assoc_long(&zaddr, "port", ntohs(packet->socket_addr.addr.inet_v4.sin_port));
        } else if (packet->socket_type == SW_SOCK_UDP6) {
            inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, address, sizeof(address));
            add_assoc_string(&zaddr, "address", address);
            add_assoc_long(&zaddr, "port", ntohs(packet->socket_addr.addr.inet_v6.sin6_port));
        } else if (packet->socket_type == SW_SOCK_UNIX_DGRAM) {
            add_assoc_string(&zaddr, "address", packet->socket_addr.addr.un.sun_path);
        }

        ZVAL_STRINGL(&args[1], packet->data, packet->length);
        args[2] = zaddr;
        argc = 3;
    }

    auto fci_cache = php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onPacket);
    if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onPipeMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    zval_ptr_dtor(&args[1]);
    if (!serv->event_object) {
        zval_ptr_dtor(&args[2]);
    }

    return SW_OK;
}

static sw_inline void php_swoole_create_task_object(zval *ztask, Server *serv, EventData *req, zval *zdata) {
    object_init_ex(ztask, swoole_server_task_ce);
    php_swoole_server_task_set_server(ztask, serv);
    php_swoole_server_task_set_info(ztask, &req->info);

    zend_update_property_long(
        swoole_server_task_ce, SW_Z8_OBJ_P(ztask), ZEND_STRL("worker_id"), (zend_long) req->info.reactor_id);
    zend_update_property_long(swoole_server_task_ce, SW_Z8_OBJ_P(ztask), ZEND_STRL("id"), (zend_long) req->info.fd);
    zend_update_property(swoole_server_task_ce, SW_Z8_OBJ_P(ztask), ZEND_STRL("data"), zdata);
    zend_update_property_double(swoole_server_task_ce, SW_Z8_OBJ_P(ztask), ZEND_STRL("dispatch_time"), req->info.time);
    zend_update_property_long(
        swoole_server_task_ce, SW_Z8_OBJ_P(ztask), ZEND_STRL("flags"), (zend_long) req->info.ext_flags);
}

static int php_swoole_server_onTask(Server *serv, EventData *req) {
    sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);

    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    zval *zdata = php_swoole_task_unpack(req);

    if (zdata == nullptr) {
        return SW_ERR;
    }

    zval retval;
    uint32_t argc;
    zval argv[4];

    if (serv->task_enable_coroutine || serv->task_object) {
        argc = 2;
        argv[0] = *zserv;
        php_swoole_create_task_object(&argv[1], serv, req, zdata);
    } else {
        argc = 4;
        argv[0] = *zserv;
        ZVAL_LONG(&argv[1], (zend_long) req->info.fd);
        ZVAL_LONG(&argv[2], (zend_long) req->info.reactor_id);
        argv[3] = *zdata;
    }

    if (UNEXPECTED(!zend::function::call(server_object->property->callbacks[SW_SERVER_CB_onTask],
                                         argc,
                                         argv,
                                         &retval,
                                         serv->task_enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onTask handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    if (argc == 2) {
        zval_ptr_dtor(&argv[1]);
    }
    sw_zval_free(zdata);

    if (!ZVAL_IS_NULL(&retval)) {
        php_swoole_task_finish(serv, &retval, req);
        zval_ptr_dtor(&retval);
    }

    return SW_OK;
}

static int php_swoole_server_onFinish(Server *serv, EventData *req) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));

    zval *zdata = php_swoole_task_unpack(req);
    if (zdata == nullptr) {
        return SW_ERR;
    }

    if (req->info.ext_flags & SW_TASK_COROUTINE) {
        TaskId task_id = req->info.fd;
        auto task_co_iterator = server_object->property->task_coroutine_map.find(task_id);

        if (task_co_iterator == server_object->property->task_coroutine_map.end()) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_TASK_TIMEOUT, "task[%ld] has expired", task_id);
        _fail:
            sw_zval_free(zdata);
            return SW_OK;
        }
        TaskCo *task_co = task_co_iterator->second;
        // Server->taskwait
        if (task_co->list == nullptr) {
            ZVAL_COPY_VALUE(task_co->result, zdata);
            task_co->co->resume();
            return SW_OK;
        }
        // Server->taskCo
        uint32_t i;
        int task_index = -1;
        zval *result = task_co->result;
        for (i = 0; i < task_co->count; i++) {
            if (task_co->list[i] == task_id) {
                task_index = i;
                break;
            }
        }
        if (task_index < 0) {
            php_swoole_fatal_error(E_WARNING, "task[%ld] is invalid", task_id);
            goto _fail;
        }
        (void) add_index_zval(result, task_index, zdata);
        efree(zdata);
        server_object->property->task_coroutine_map.erase(task_id);

        if (php_swoole_array_length(result) == task_co->count) {
            task_co->co->resume();
        }
        return SW_OK;
    }

    zend_fcall_info_cache *fci_cache = nullptr;
    if (req->info.ext_flags & SW_TASK_CALLBACK) {
        auto callback_iterator = server_object->property->task_callbacks.find(req->info.fd);
        if (callback_iterator == server_object->property->task_callbacks.end()) {
            req->info.ext_flags = req->info.ext_flags & (~SW_TASK_CALLBACK);
        } else {
            fci_cache = &callback_iterator->second;
        }
    } else {
        fci_cache = server_object->property->callbacks[SW_SERVER_CB_onFinish];
    }
    if (UNEXPECTED(fci_cache == nullptr)) {
        sw_zval_free(zdata);
        php_swoole_fatal_error(E_WARNING, "require onFinish callback");
        return SW_ERR;
    }

    zval args[3];
    int argc;
    args[0] = *zserv;

    if (serv->event_object) {
        zval *object = &args[1];
        object_init_ex(object, swoole_server_task_result_ce);
        zend_update_property_long(
            swoole_server_task_result_ce, SW_Z8_OBJ_P(object), ZEND_STRL("task_id"), (zend_long) req->info.fd);
        zend_update_property_long(swoole_server_task_result_ce,
                                  SW_Z8_OBJ_P(object),
                                  ZEND_STRL("task_worker_id"),
                                  (zend_long) req->info.reactor_id);
        zend_update_property_double(
            swoole_server_task_result_ce, SW_Z8_OBJ_P(object), ZEND_STRL("dispatch_time"), req->info.time);
        zend_update_property(swoole_server_task_result_ce, SW_Z8_OBJ_P(object), ZEND_STRL("data"), zdata);
        argc = 2;
    } else {
        ZVAL_LONG(&args[1], req->info.fd);
        args[2] = *zdata;
        argc = 3;
    }

    if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onFinish handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    if (req->info.ext_flags & SW_TASK_CALLBACK) {
        sw_zend_fci_cache_discard(fci_cache);
        server_object->property->task_callbacks.erase(req->info.fd);
    }
    sw_zval_free(zdata);
    if (serv->event_object) {
        zval_ptr_dtor(&args[1]);
    }

    return SW_OK;
}

static void php_swoole_server_onStart(Server *serv) {
    serv->lock();
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onStart];

    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onStart", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    serv->unlock();
}

static void php_swoole_server_onManagerStart(Server *serv) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onManagerStart];

    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onManagerStart", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onManagerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onManagerStop(Server *serv) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onManagerStop];

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onManagerStop", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onManagerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onBeforeShutdown(Server *serv) {
    serv->lock();
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onBeforeShutdown];

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onBeforeShutdown", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onBeforeShutdown handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    serv->unlock();
}

static void php_swoole_server_onShutdown(Server *serv) {
    serv->lock();
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onShutdown];

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onShutdown", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onShutdown handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
    serv->unlock();
}

static void php_swoole_server_onWorkerStart(Server *serv, int worker_id) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onWorkerStart];

    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("manager_pid"), serv->gs->manager_pid);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("worker_id"), worker_id);
    zend_update_property_bool(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("taskworker"), serv->is_task_worker());
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("worker_pid"), getpid());

    if (serv->is_task_worker() && !serv->task_enable_coroutine) {
        PHPCoroutine::disable_hook();
    }

    zval args[2];
    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onWorkerStart", 2, args);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onWorkerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onBeforeReload(Server *serv) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onBeforeReload];

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onBeforeReload", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onBeforeReload handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onAfterReload(Server *serv) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onAfterReload];

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onAfterReload", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 1, zserv, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onAfterReload handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onWorkerStop(Server *serv, int worker_id) {
    if (SwooleWG.shutdown) {
        return;
    }
    SwooleWG.shutdown = true;

    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onWorkerStop];
    zval args[2];
    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onWorkerStop", 2, args);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onWorkerExit(Server *serv, int worker_id) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onWorkerExit];

    zval args[2];
    args[0] = *zserv;
    ZVAL_LONG(&args[1], worker_id);

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onWorkerExit", 2, args);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerExit handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }
}

static void php_swoole_server_onUserWorkerStart(Server *serv, Worker *worker) {
    zval *object = (zval *) worker->ptr;
    zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(object), ZEND_STRL("id"), SwooleG.process_id);

    zval *zserv = (zval *) serv->private_data_2;
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    php_swoole_process_start(worker, object);
}

static void php_swoole_server_onWorkerError(Server *serv, int worker_id, const ExitStatus &exit_status) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    auto fci_cache = server_object->property->callbacks[SW_SERVER_CB_onWorkerError];

    zval args[5];
    int argc;
    args[0] = *zserv;

    if (serv->event_object) {
        zval *object = &args[1];
        object_init_ex(object, swoole_server_status_info_ce);
        zend_update_property_long(swoole_server_status_info_ce, SW_Z8_OBJ_P(object), ZEND_STRL("worker_id"), worker_id);
        zend_update_property_long(
            swoole_server_status_info_ce, SW_Z8_OBJ_P(object), ZEND_STRL("worker_pid"), exit_status.get_pid());
        zend_update_property_long(
            swoole_server_status_info_ce, SW_Z8_OBJ_P(object), ZEND_STRL("status"), exit_status.get_status());
        zend_update_property_long(
            swoole_server_status_info_ce, SW_Z8_OBJ_P(object), ZEND_STRL("exit_code"), exit_status.get_code());
        zend_update_property_long(
            swoole_server_status_info_ce, SW_Z8_OBJ_P(object), ZEND_STRL("signal"), exit_status.get_signal());
        argc = 2;
    } else {
        ZVAL_LONG(&args[1], worker_id);
        ZVAL_LONG(&args[2], exit_status.get_pid());
        ZVAL_LONG(&args[3], exit_status.get_code());
        ZVAL_LONG(&args[4], exit_status.get_signal());
        argc = 5;
    }

    if (SWOOLE_G(enable_library)) {
        zend::function::call("\\Swoole\\Server\\Helper::onWorkerError", 1, zserv);
    }

    if (fci_cache && UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerError handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    if (serv->event_object) {
        zval_ptr_dtor(&args[1]);
    }
}

void php_swoole_server_onConnect(Server *serv, DataHead *info) {
    auto fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onConnect);
    if (!fci_cache) {
        return;
    }

    zval *zserv = (zval *) serv->private_data_2;
    zval args[3];
    int argc;
    args[0] = *zserv;

    if (serv->event_object) {
        zval *object = &args[1];
        object_init_ex(object, swoole_server_event_ce);
        zend_update_property_long(swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("fd"), (zend_long) info->fd);
        zend_update_property_long(
            swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("reactor_id"), (zend_long) info->reactor_id);
        zend_update_property_double(
            swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("dispatch_time"), info->time);
        argc = 2;
    } else {
        ZVAL_LONG(&args[1], info->fd);
        ZVAL_LONG(&args[2], info->reactor_id);
        argc = 3;
    }

    if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onConnect handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    }

    if (serv->event_object) {
        zval_ptr_dtor(&args[1]);
    }
}

void php_swoole_server_onClose(Server *serv, DataHead *info) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));
    SessionId session_id = info->fd;

    if (serv->enable_coroutine && serv->send_yield) {
        auto _i_co_list = server_object->property->send_coroutine_map.find(session_id);
        if (_i_co_list != server_object->property->send_coroutine_map.end()) {
            auto co_list = _i_co_list->second;
            server_object->property->send_coroutine_map.erase(session_id);
            while (!co_list->empty()) {
                Coroutine *co = co_list->front();
                co_list->pop_front();
                swoole_set_last_error(ECONNRESET);
                co->resume();
            }
            delete co_list;
        }
    }

    auto *fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onClose);
    Connection *conn = serv->get_connection_by_session_id(session_id);
    if (!conn) {
        return;
    }
    if (conn->websocket_status != swoole::websocket::STATUS_ACTIVE) {
        ListenPort *port = serv->get_port_by_server_fd(info->server_fd);
        if (port && port->open_websocket_protocol &&
            php_swoole_server_isset_callback(serv, port, SW_SERVER_CB_onDisconnect)) {
            fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onDisconnect);
        }
    }
    if (fci_cache) {
        zval *zserv = (zval *) serv->private_data_2;
        zval args[3];
        int argc;
        args[0] = *zserv;

        if (serv->event_object) {
            zval *object = &args[1];
            object_init_ex(object, swoole_server_event_ce);
            zend_update_property_long(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("fd"), (zend_long) session_id);
            zend_update_property_long(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("reactor_id"), (zend_long) info->reactor_id);
            zend_update_property_double(
                swoole_server_event_ce, SW_Z8_OBJ_P(object), ZEND_STRL("dispatch_time"), info->time);
            argc = 2;
        } else {
            ZVAL_LONG(&args[1], session_id);
            ZVAL_LONG(&args[2], info->reactor_id);
            argc = 3;
        }

        if (UNEXPECTED(!zend::function::call(fci_cache, argc, args, nullptr, serv->enable_coroutine))) {
            php_swoole_error(E_WARNING, "%s->onClose handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }

        if (serv->event_object) {
            zval_ptr_dtor(&args[1]);
        }
    }

#ifdef SW_USE_HTTP2
    if (conn->http2_stream) {
        swoole_http2_server_session_free(conn);
    }
#endif
}

void php_swoole_server_onBufferFull(Server *serv, DataHead *info) {
    zval *zserv = (zval *) serv->private_data_2;
    auto fci_cache = php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onBufferFull);

    if (fci_cache) {
        zval args[2];

        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, false))) {
            php_swoole_error(E_WARNING, "%s->onBufferFull handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

void php_swoole_server_send_yield(Server *serv, SessionId session_id, zval *zdata, zval *return_value) {
    ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
    Coroutine *co = Coroutine::get_current_safe();
    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0) {
        RETURN_FALSE;
    }

    SW_LOOP {
        auto coroutine_iterator = server_object->property->send_coroutine_map.find(session_id);
        std::list<Coroutine *> *co_list;
        if (coroutine_iterator == server_object->property->send_coroutine_map.end()) {
            co_list = new std::list<Coroutine *>;
            server_object->property->send_coroutine_map[session_id] = co_list;
        } else {
            co_list = coroutine_iterator->second;
        }
        co_list->push_back(co);
        auto iter = std::prev(co_list->end());
        if (!co->yield_ex(serv->send_timeout)) {
            co_list->erase(iter);
            RETURN_FALSE;
        }
        bool ret = serv->send(session_id, data, length);
        if (!ret && swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD && serv->send_yield) {
            continue;
        } else {
            RETURN_BOOL(ret);
        }
    }
}

static int php_swoole_server_dispatch_func(Server *serv, Connection *conn, SendData *data) {
    serv->lock();

    auto fci_cache = (zend_fcall_info_cache *) serv->private_data_3;
    zval args[4];
    zval *zserv = &args[0], *zfd = &args[1], *ztype = &args[2], *zdata = nullptr;
    zval retval;
    zend_long worker_id = -1;

    *zserv = *((zval *) serv->private_data_2);
    ZVAL_LONG(zfd, conn ? conn->session_id : data->info.fd);
    ZVAL_LONG(ztype, (zend_long)(data ? data->info.type : (int) SW_SERVER_EVENT_CLOSE));
    if (data && sw_zend_function_max_num_args(fci_cache->function_handler) > 3) {
        // TODO: reduce memory copy
        zdata = &args[3];
        ZVAL_STRINGL(zdata, data->data, data->info.len > SW_IPC_BUFFER_SIZE ? SW_IPC_BUFFER_SIZE : data->info.len);
    }
    if (UNEXPECTED(sw_zend_call_function_ex(nullptr, fci_cache, zdata ? 4 : 3, args, &retval) != SUCCESS)) {
        php_swoole_error(E_WARNING, "%s->onDispatch handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
    } else if (!ZVAL_IS_NULL(&retval)) {
        worker_id = zval_get_long(&retval);
        if (worker_id >= (zend_long) serv->worker_num) {
            php_swoole_fatal_error(E_WARNING, "invalid target worker-id[" ZEND_LONG_FMT "]", worker_id);
            worker_id = -1;
        }
        zval_ptr_dtor(&retval);
    }
    if (zdata) {
        zval_ptr_dtor(zdata);
    }

    serv->unlock();

    /* the exception should only be thrown after unlocked */
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }

    return worker_id;
}

void php_swoole_server_onBufferEmpty(Server *serv, DataHead *info) {
    zval *zserv = (zval *) serv->private_data_2;
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(zserv));

    if (serv->send_yield) {
        auto _i_co_list = server_object->property->send_coroutine_map.find(info->fd);
        if (_i_co_list != server_object->property->send_coroutine_map.end()) {
            auto co_list = _i_co_list->second;
            server_object->property->send_coroutine_map.erase(info->fd);
            while (!co_list->empty()) {
                Coroutine *co = co_list->front();
                co_list->pop_front();
                co->resume();
            }
            delete co_list;
        }
    }

    zend_fcall_info_cache *fci_cache =
        php_swoole_server_get_fci_cache(serv, info->server_fd, SW_SERVER_CB_onBufferEmpty);
    if (fci_cache) {
        zval args[2];

        args[0] = *zserv;
        ZVAL_LONG(&args[1], info->fd);

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, false))) {
            php_swoole_error(E_WARNING, "%s->onBufferEmpty handler error", SW_Z_OBJCE_NAME_VAL_P(zserv));
        }
    }
}

static PHP_METHOD(swoole_server, __construct) {
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    Server *serv = server_object->serv;
    if (serv) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    zval *zserv = ZEND_THIS;
    char *host;
    size_t host_len = 0;
    zend_long sock_type = SW_SOCK_TCP;
    zend_long serv_port = 0;
    zend_long serv_mode = Server::MODE_PROCESS;

    // only cli env
    if (!SWOOLE_G(cli)) {
        zend_throw_exception_ex(
            swoole_exception_ce, -1, "%s can only be used in CLI mode", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    if (sw_server() != nullptr) {
        zend_throw_exception_ex(
            swoole_exception_ce, -3, "server is running. unable to create %s", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 4)
    Z_PARAM_STRING(host, host_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(serv_port)
    Z_PARAM_LONG(serv_mode)
    Z_PARAM_LONG(sock_type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (serv_mode != Server::MODE_BASE && serv_mode != Server::MODE_PROCESS) {
        php_swoole_fatal_error(E_ERROR, "invalid $mode parameters %d", (int) serv_mode);
        RETURN_FALSE;
    }

    serv = new Server((enum Server::Mode) serv_mode);
    serv->private_data_2 = sw_zval_dup(zserv);
    server_set_ptr(zserv, serv);

    if (serv_mode == Server::MODE_BASE) {
        serv->reactor_num = 1;
        serv->worker_num = 1;
    }

    /* primary port */
    do {
        if (serv_port == 0 && strcasecmp(host, "SYSTEMD") == 0) {
            if (serv->add_systemd_socket() <= 0) {
                php_swoole_fatal_error(E_ERROR, "failed to add systemd socket");
                RETURN_FALSE;
            }
        } else {
            ListenPort *port = serv->add_port((enum swSocketType) sock_type, host, serv_port);
            if (!port) {
                zend_throw_exception_ex(swoole_exception_ce,
                                        errno,
                                        "failed to listen server port[%s:" ZEND_LONG_FMT "], Error: %s[%d]",
                                        host,
                                        serv_port,
                                        strerror(errno),
                                        errno);
                RETURN_FALSE;
            }
        }

        for (auto ls : serv->ports) {
            php_swoole_server_add_port(server_object, ls);
        }

        server_object->property->primary_port = (ServerPortProperty *) serv->get_primary_port()->ptr;
    } while (0);

    /* iterator */
    do {
        zval connection_iterator;
        object_init_ex(&connection_iterator, swoole_connection_iterator_ce);

        ConnectionIterator *iterator = php_swoole_connection_iterator_get_ptr(&connection_iterator);
        iterator->serv = serv;

        zend_update_property(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("connections"), &connection_iterator);
        zval_ptr_dtor(&connection_iterator);
    } while (0);

    /* info */
    zend_update_property_stringl(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(
        swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("port"), (zend_long) serv->get_primary_port()->port);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("mode"), serv_mode);
    zend_update_property_long(swoole_server_ce, SW_Z8_OBJ_P(zserv), ZEND_STRL("type"), sock_type);
}

static PHP_METHOD(swoole_server, __destruct) {}

static PHP_METHOD(swoole_server, set) {
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (serv->is_started()) {
        php_swoole_fatal_error(
            E_WARNING, "server is running, unable to execute %s->set", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zval *zset = nullptr, *ztmp;
    HashTable *vht;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    php_swoole_set_global_option(vht);
    php_swoole_set_coroutine_option(vht);
    php_swoole_set_aio_option(vht);

    if (php_swoole_array_get_value(vht, "chroot", ztmp)) {
        serv->chroot_ = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "user", ztmp)) {
        serv->user_ = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "group", ztmp)) {
        serv->group_ = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "daemonize", ztmp)) {
        serv->daemonize = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "pid_file", ztmp)) {
        serv->pid_file = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "reactor_num", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->reactor_num = SW_MAX(0, SW_MIN(v, UINT16_MAX));
        if (serv->reactor_num == 0) {
            serv->reactor_num = SW_CPU_NUM;
        }
    }
    if (php_swoole_array_get_value(vht, "single_thread", ztmp)) {
        serv->single_thread = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "worker_num", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->worker_num = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        if (serv->worker_num == 0) {
            serv->worker_num = SW_CPU_NUM;
        }
    }
    if (php_swoole_array_get_value(vht, "max_wait_time", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->max_wait_time = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    if (php_swoole_array_get_value(vht, "max_queued_bytes", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->max_queued_bytes = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        serv->enable_coroutine = zval_is_true(ztmp);
    } else {
        serv->enable_coroutine = SWOOLE_G(enable_coroutine);
    }
    if (php_swoole_array_get_value(vht, "send_timeout", ztmp)) {
        serv->send_timeout = zval_get_double(ztmp);
    }
    if (php_swoole_array_get_value(vht, "dispatch_mode", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->dispatch_mode = SW_MAX(0, SW_MIN(v, UINT8_MAX));
    }
    if (php_swoole_array_get_value(vht, "send_yield", ztmp)) {
        serv->send_yield = zval_is_true(ztmp);
        if (serv->send_yield &&
            !(serv->dispatch_mode == Server::DISPATCH_FDMOD || serv->dispatch_mode == Server::DISPATCH_IPMOD)) {
            php_swoole_error(E_WARNING, "'send_yield' option can only be set when using dispatch_mode=2/4");
            serv->send_yield = false;
        }
    } else {
        serv->send_yield = serv->enable_coroutine;
    }
    if (php_swoole_array_get_value(vht, "dispatch_func", ztmp)) {
        Server::DispatchFunction c_dispatch_func = nullptr;
        while (1) {
            if (Z_TYPE_P(ztmp) == IS_STRING) {
                c_dispatch_func = (Server::DispatchFunction) swoole_get_function(Z_STRVAL_P(ztmp), Z_STRLEN_P(ztmp));
                if (c_dispatch_func) {
                    break;
                }
            }
#ifdef ZTS
            if (serv->is_process_mode() && !serv->single_thread) {
                php_swoole_fatal_error(E_ERROR, "option [dispatch_func] does not support with ZTS");
            }
#endif
            char *func_name = nullptr;
            zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
            if (!sw_zend_is_callable_ex(ztmp, nullptr, 0, &func_name, nullptr, fci_cache, nullptr)) {
                php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
                return;
            }
            efree(func_name);
            sw_zend_fci_cache_persist(fci_cache);
            if (serv->private_data_3) {
                sw_zend_fci_cache_discard((zend_fcall_info_cache *) serv->private_data_3);
                efree(serv->private_data_3);
            }
            serv->private_data_3 = (void *) fci_cache;
            c_dispatch_func = php_swoole_server_dispatch_func;
            break;
        }
        serv->dispatch_func = c_dispatch_func;
    }
    /**
     * for dispatch_mode = 1/3
     */
    if (php_swoole_array_get_value(vht, "discard_timeout_request", ztmp)) {
        serv->discard_timeout_request = zval_is_true(ztmp);
    }
    // onConnect/onClose event
    if (php_swoole_array_get_value(vht, "enable_unsafe_event", ztmp)) {
        serv->enable_unsafe_event = zval_is_true(ztmp);
    }
    // delay receive
    if (php_swoole_array_get_value(vht, "enable_delay_receive", ztmp)) {
        serv->enable_delay_receive = zval_is_true(ztmp);
    }
#if defined(__linux__) and defined(HAVE_REUSEPORT)
    if (php_swoole_array_get_value(vht, "enable_reuse_port", ztmp)) {
        serv->enable_reuse_port = zval_is_true(ztmp);
    }
#endif
    // task use object
    if (php_swoole_array_get_value(vht, "task_use_object", ztmp) ||
        php_swoole_array_get_value(vht, "task_object", ztmp)) {
        serv->task_object = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "event_object", ztmp)) {
        serv->event_object = zval_is_true(ztmp);
        if (serv->event_object) {
            serv->task_object = true;
        }
    }
    // task coroutine
    if (php_swoole_array_get_value(vht, "task_enable_coroutine", ztmp)) {
        serv->task_enable_coroutine = zval_is_true(ztmp);
    }
    // task_worker_num
    if (php_swoole_array_get_value(vht, "task_worker_num", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->task_worker_num = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    // task ipc mode, 1,2,3
    if (php_swoole_array_get_value(vht, "task_ipc_mode", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->task_ipc_mode = SW_MAX(0, SW_MIN(v, UINT8_MAX));
    }
    /**
     * Temporary file directory for task_worker
     */
    if (php_swoole_array_get_value(vht, "task_tmpdir", ztmp)) {
        zend::String str_v(ztmp);
        swoole_set_task_tmpdir(str_v.to_std_string());
    }
    // task_max_request
    if (php_swoole_array_get_value(vht, "task_max_request", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->task_max_request = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        // task_max_request_grace
        if (php_swoole_array_get_value(vht, "task_max_request_grace", ztmp)) {
            zend_long v = zval_get_long(ztmp);
            serv->task_max_request_grace = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        } else if (serv->task_max_request > SW_WORKER_MIN_REQUEST) {
            serv->task_max_request_grace = serv->task_max_request / 2;
        }
    }
    // max_connection
    if (php_swoole_array_get_value(vht, "max_connection", ztmp) || php_swoole_array_get_value(vht, "max_conn", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->set_max_connection(SW_MAX(0, SW_MIN(v, UINT32_MAX)));
    }
    if (php_swoole_array_get_value(vht, "start_session_id", ztmp)) {
        serv->set_start_session_id(zval_get_long(ztmp));
    }
    // heartbeat_check_interval
    if (php_swoole_array_get_value(vht, "heartbeat_check_interval", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->heartbeat_check_interval = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    } else if (php_swoole_array_get_value(vht, "heartbeat_idle_time", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->heartbeat_check_interval = v > 2 ? v / 2 : 1;
    }
    // max_request
    if (php_swoole_array_get_value(vht, "max_request", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->max_request = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        // max_request_grace
        if (php_swoole_array_get_value(vht, "max_request_grace", ztmp)) {
            zend_long v = zval_get_long(ztmp);
            serv->max_request_grace = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        } else if (serv->max_request > SW_WORKER_MIN_REQUEST) {
            serv->max_request_grace = serv->max_request / 2;
        }
    }
    // reload async
    if (php_swoole_array_get_value(vht, "reload_async", ztmp)) {
        serv->reload_async = zval_is_true(ztmp);
    }
    // cpu affinity
    if (php_swoole_array_get_value(vht, "open_cpu_affinity", ztmp)) {
        serv->open_cpu_affinity = zval_is_true(ztmp);
    }
    // cpu affinity set
    if (php_swoole_array_get_value(vht, "cpu_affinity_ignore", ztmp)) {
        int ignore_num = zend_hash_num_elements(Z_ARRVAL_P(ztmp));
        if (ignore_num >= SW_CPU_NUM) {
            php_swoole_fatal_error(E_ERROR, "cpu_affinity_ignore num must be less than cpu num (%d)", SW_CPU_NUM);
            RETURN_FALSE;
        }
        int available_num = SW_CPU_NUM - ignore_num;
        int *available_cpu = (int *) sw_malloc(sizeof(int) * available_num);
        if (!available_cpu) {
            php_swoole_fatal_error(E_WARNING, "malloc() failed");
            RETURN_FALSE;
        }
        int flag, i, available_i = 0;

        zval *zval_core = nullptr;
        for (i = 0; i < SW_CPU_NUM; i++) {
            flag = 1;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztmp), zval_core)
            if (i == zval_get_long(zval_core)) {
                flag = 0;
                break;
            }
            SW_HASHTABLE_FOREACH_END();
            if (flag) {
                available_cpu[available_i] = i;
                available_i++;
            }
        }
        serv->cpu_affinity_available_num = available_num;
        if (serv->cpu_affinity_available) {
            sw_free(serv->cpu_affinity_available);
        }
        serv->cpu_affinity_available = available_cpu;
    }
    // parse cookie header
    if (php_swoole_array_get_value(vht, "http_parse_cookie", ztmp)) {
        serv->http_parse_cookie = zval_is_true(ztmp);
    }
    // parse x-www-form-urlencoded form data
    if (php_swoole_array_get_value(vht, "http_parse_post", ztmp)) {
        serv->http_parse_post = zval_is_true(ztmp);
    }
    // parse multipart/form-data file uploads
    if (php_swoole_array_get_value(vht, "http_parse_files", ztmp)) {
        serv->http_parse_files = zval_is_true(ztmp);
    }
#ifdef SW_HAVE_COMPRESSION
    // http content compression
    if (php_swoole_array_get_value(vht, "http_compression", ztmp)) {
        serv->http_compression = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "http_compression_level", ztmp) ||
        php_swoole_array_get_value(vht, "http_gzip_level", ztmp)) {
        zend_long level = zval_get_long(ztmp);
        if (level > UINT8_MAX) {
            level = UINT8_MAX;
        } else if (level < 0) {
            level = 0;
        }
        serv->http_compression_level = level;
    }
    if (php_swoole_array_get_value(vht, "compression_min_length", ztmp)) {
        serv->compression_min_length = zval_get_long(ztmp);
    }
#endif

#ifdef SW_HAVE_ZLIB
    if (php_swoole_array_get_value(vht, "websocket_compression", ztmp)) {
        serv->websocket_compression = zval_is_true(ztmp);
    }
#endif

    // temporary directory for HTTP uploaded file.
    if (php_swoole_array_get_value(vht, "upload_tmp_dir", ztmp)) {
        zend::String str_v(ztmp);
        if (php_swoole_create_dir(str_v.val(), str_v.len()) < 0) {
            php_swoole_fatal_error(E_ERROR, "Unable to create upload_tmp_dir[%s]", str_v.val());
            return;
        }
        serv->upload_tmp_dir = str_v.to_std_string();
    }
    /**
     * http static file handler
     */
    if (php_swoole_array_get_value(vht, "enable_static_handler", ztmp)) {
        serv->enable_static_handler = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "document_root", ztmp)) {
        zend::String str_v(ztmp);
        if (str_v.len() >= PATH_MAX) {
            php_swoole_fatal_error(E_ERROR, "The length of document_root must be less than %d", PATH_MAX);
            return;
        }
        serv->set_document_root(std::string(str_v.val(), str_v.len()));
    }
    if (php_swoole_array_get_value(vht, "http_autoindex", ztmp)) {
        serv->http_autoindex = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "http_index_files", ztmp)) {
        if (ZVAL_IS_ARRAY(ztmp)) {
            zval *_http_index_files;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztmp), _http_index_files)
            zend::String __http_index_files(_http_index_files);
            if (__http_index_files.len() > 0) {
                serv->add_static_handler_index_files(__http_index_files.to_std_string());
            }
            SW_HASHTABLE_FOREACH_END();
        } else {
            php_swoole_fatal_error(E_ERROR, "http_index_files must be array");
            RETURN_FALSE;
        }
    }
    /**
     * [static_handler] locations
     */
    if (php_swoole_array_get_value(vht, "static_handler_locations", ztmp)) {
        if (ZVAL_IS_ARRAY(ztmp)) {
            zval *_location;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztmp), _location)
            zend::String __location(_location);
            if (__location.len() > 0 && __location.val()[0] == '/') {
                serv->add_static_handler_location(__location.to_std_string());
            }
            SW_HASHTABLE_FOREACH_END();
        } else {
            php_swoole_fatal_error(E_ERROR, "static_handler_locations num must be array");
            RETURN_FALSE;
        }
    }
    /**
     * buffer input size
     */
    if (php_swoole_array_get_value(vht, "input_buffer_size", ztmp) ||
        php_swoole_array_get_value(vht, "buffer_input_size", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->input_buffer_size = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    /**
     * buffer output size
     */
    if (php_swoole_array_get_value(vht, "output_buffer_size", ztmp) ||
        php_swoole_array_get_value(vht, "buffer_output_size", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->output_buffer_size = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    // message queue key
    if (php_swoole_array_get_value(vht, "message_queue_key", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        serv->message_queue_key = SW_MAX(0, SW_MIN(v, INT64_MAX));
    }

    if (serv->task_enable_coroutine &&
        (serv->task_ipc_mode == Server::TASK_IPC_MSGQUEUE || serv->task_ipc_mode == Server::TASK_IPC_PREEMPTIVE)) {
        php_swoole_fatal_error(E_ERROR, "cannot use msgqueue when task_enable_coroutine is enable");
        RETURN_FALSE;
    }

    sw_zend_call_method_with_1_params(
        server_object->property->ports.at(0), swoole_server_port_ce, nullptr, "set", nullptr, zset);

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, on) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "server is running, unable to register event callback function");
        RETURN_FALSE;
    }

    zval *name;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &name, &cb) == FAILURE) {
        RETURN_FALSE;
    }

    char *func_name = nullptr;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, nullptr, 0, &func_name, nullptr, fci_cache, nullptr)) {
        php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    zend::String _event_name_ori(name);
    zend::String _event_name_tolower(zend_string_tolower(_event_name_ori.get()), false);

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));

    auto i = server_event_map.find(_event_name_tolower.to_std_string());
    if (i == server_event_map.end()) {
        zval *port_object = server_object->property->ports.at(0);
        zval retval;
        efree(fci_cache);
        sw_zend_call_method_with_2_params(port_object, swoole_server_port_ce, nullptr, "on", &retval, name, cb);
        RETURN_BOOL(Z_BVAL_P(&retval));
    } else {
        int event_type = i->second.type;
        std::string property_name = "on" + i->second.name;

        zend_update_property(
            swoole_server_ce, SW_Z8_OBJ_P(ZEND_THIS), property_name.c_str(), property_name.length(), cb);

        if (server_object->property->callbacks[event_type]) {
            efree(server_object->property->callbacks[event_type]);
        }
        server_object->property->callbacks[event_type] = fci_cache;

        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, getCallback) {
    zval *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(name)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend::String _event_name_ori(name);
    zend::String _event_name_tolower(zend_string_tolower(_event_name_ori.get()), false);
    auto i = server_event_map.find(_event_name_tolower.to_std_string());
    if (i != server_event_map.end()) {
        std::string property_name = "on" + i->second.name;
        // Notice: we should use Z_OBJCE_P instead of swoole_server_ce, because we need to consider the subclasses.
        zval rv,
            *property = zend_read_property(
                Z_OBJCE_P(ZEND_THIS), SW_Z8_OBJ_P(ZEND_THIS), property_name.c_str(), property_name.length(), 1, &rv);
        if (!ZVAL_IS_NULL(property)) {
            RETURN_ZVAL(property, 1, 0);
        }
    }

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    sw_zend_call_method_with_1_params(
        server_object->property->ports.at(0), swoole_server_port_ce, nullptr, "getcallback", return_value, name);
}

static PHP_METHOD(swoole_server, listen) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "server is running, can't add listener");
        RETURN_FALSE;
    }

    char *host;
    size_t host_len;
    long sock_type;
    long port;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &host, &host_len, &port, &sock_type) == FAILURE) {
        RETURN_FALSE;
    }

    ListenPort *ls = serv->add_port((enum swSocketType) sock_type, host, (int) port);
    if (!ls) {
        RETURN_FALSE;
    }

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    zval *port_object = php_swoole_server_add_port(server_object, ls);
    RETURN_ZVAL(port_object, 1, 0);
}

extern Worker *php_swoole_process_get_and_check_worker(zval *zobject);

static PHP_METHOD(swoole_server, addProcess) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "server is running, can't add process");
        RETURN_FALSE;
    }

    zval *process = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &process) == FAILURE) {
        RETURN_FALSE;
    }

    if (ZVAL_IS_NULL(process)) {
        php_swoole_fatal_error(E_WARNING, "the first parameter can't be empty");
        RETURN_FALSE;
    }

    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_ce)) {
        php_swoole_fatal_error(E_ERROR, "object is not instanceof swoole_process");
        RETURN_FALSE;
    }

    if (serv->onUserWorkerStart == nullptr) {
        serv->onUserWorkerStart = php_swoole_server_onUserWorkerStart;
    }

    zval *tmp_process = (zval *) emalloc(sizeof(zval));
    memcpy(tmp_process, process, sizeof(zval));
    process = tmp_process;

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    server_object->property->user_processes.push_back(process);

    Z_TRY_ADDREF_P(process);

    Worker *worker = php_swoole_process_get_and_check_worker(process);
    worker->ptr = process;

    int id = serv->add_worker(worker);
    if (id < 0) {
        php_swoole_fatal_error(E_WARNING, "Server::add_worker() failed");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(process), ZEND_STRL("id"), id);
    RETURN_LONG(id);
}

static PHP_METHOD(swoole_server, addCommand) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "server is running, can't add command");
        RETURN_FALSE;
    }

    char *name;
    size_t l_name;
    zend_long accepted_process_types;
    zend_fcall_info fci;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) ecalloc(1, sizeof(zend_fcall_info_cache));

    ZEND_PARSE_PARAMETERS_START(3, 3)
    Z_PARAM_STRING(name, l_name)
    Z_PARAM_LONG(accepted_process_types)
    Z_PARAM_FUNC(fci, *fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (accepted_process_types & Server::Command::REACTOR_THREAD) {
        php_swoole_fatal_error(E_WARNING, "only support worker/task_worker process");
        RETURN_FALSE;
    }

    Server::Command::Handler fn = [fci_cache](Server *serv, const std::string &msg) {
        zval *zserv = (zval *) serv->private_data_2;
        zval argv[2];
        argv[0] = *zserv;
        ZVAL_STRINGL(&argv[1], msg.c_str(), msg.length());
        zval return_value;

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, argv, &return_value, false))) {
            php_swoole_fatal_error(E_WARNING, "%s: command handler error", ZSTR_VAL(swoole_server_ce->name));
            return std::string("{\"data\": \"failed to call function\", \"code\": -1}");
        }

        if (!ZVAL_IS_STRING(&return_value)) {
            return std::string("{\"data\": \"wrong return type\", \"code\": -2}");
        }

        return std::string(Z_STRVAL(return_value), Z_STRLEN(return_value));
    };

    if (!serv->add_command(std::string(name, l_name), accepted_process_types, fn)) {
        RETURN_FALSE;
    }

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));
    sw_zend_fci_cache_persist(fci_cache);
    server_object->property->command_callbacks.push_back(fci_cache);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, start) {
    zval *zserv = ZEND_THIS;
    Server *serv = php_swoole_server_get_and_check_server(zserv);

    if (serv->is_started()) {
        php_swoole_fatal_error(
            E_WARNING, "server is running, unable to execute %s->start()", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }
    if (serv->is_shutdown()) {
        php_swoole_fatal_error(
            E_WARNING, "server have been shutdown, unable to execute %s->start()", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    if (SwooleTG.reactor) {
        php_swoole_fatal_error(
            E_WARNING, "eventLoop has already been created, unable to start %s", SW_Z_OBJCE_NAME_VAL_P(zserv));
        RETURN_FALSE;
    }

    ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
    server_object->register_callback();
    server_object->on_before_start();

    if (serv->start() < 0) {
        php_swoole_fatal_error(E_ERROR, "failed to start server. Error: %s", sw_error);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, send) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    zval *zfd;
    zval *zdata;
    zend_long server_socket = -1;

    ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(server_socket)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(ZVAL_IS_NULL(zfd))) {
        php_swoole_fatal_error(E_WARNING, "fd can not be null");
        RETURN_FALSE;
    }

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0) {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    // UNIX DGRAM SOCKET
    if (serv->have_dgram_sock && Z_TYPE_P(zfd) == IS_STRING && Z_STRVAL_P(zfd)[0] == '/') {
        network::Socket *sock = server_socket == -1 ? serv->dgram_socket : serv->get_server_socket(server_socket);
        if (sock == nullptr) {
            RETURN_FALSE;
        }
        RETURN_BOOL(sock->sendto(Z_STRVAL_P(zfd), 0, data, length) > 0);
    }

    fd = zval_get_long(zfd);
    if (UNEXPECTED(fd <= 0)) {
        php_swoole_fatal_error(E_WARNING, "invalid fd[" ZEND_LONG_FMT "]", fd);
        RETURN_FALSE;
    }
    bool ret = serv->send(fd, data, length);
    if (!ret && swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD) {
        php_swoole_server_send_yield(serv, fd, zdata, return_value);
    } else {
        RETURN_BOOL(ret);
    }
}

static PHP_METHOD(swoole_server, sendto) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    char *addr;
    size_t addr_len;
    zend_long port;
    char *data;
    size_t len;
    zend_long server_socket_fd = -1;
    enum swSocketType type;

    ZEND_PARSE_PARAMETERS_START(3, 4)
    Z_PARAM_STRING(addr, addr_len)
    Z_PARAM_LONG(port)
    Z_PARAM_STRING(data, len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(server_socket_fd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (len == 0) {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    if (addr[0] == '/') {
        type = SW_SOCK_UNIX_DGRAM;
    } else if (strchr(addr, ':')) {
        type = SW_SOCK_UDP6;
    } else {
        type = SW_SOCK_UDP;
    }

    network::Socket *server_socket = nullptr;

    switch (type) {
    case SW_SOCK_UDP:
        if (!serv->udp_socket_ipv4) {
            php_swoole_fatal_error(E_WARNING, "UDP listener has to be added before executing sendto");
            RETURN_FALSE;
        } else {
            server_socket = server_socket_fd < 0 ? serv->udp_socket_ipv4 : serv->get_server_socket(server_socket_fd);
        }
        break;
    case SW_SOCK_UDP6:
        if (!serv->udp_socket_ipv6) {
            php_swoole_fatal_error(E_WARNING, "UDP6 listener has to be added before executing sendto");
            RETURN_FALSE;
        } else {
            server_socket = server_socket_fd < 0 ? serv->udp_socket_ipv6 : serv->get_server_socket(server_socket_fd);
        }
        break;
    case SW_SOCK_UNIX_DGRAM:
        if (!serv->dgram_socket) {
            php_swoole_fatal_error(E_WARNING, "UnixDgram listener has to be added before executing sendto");
            RETURN_FALSE;
        } else {
            server_socket = server_socket_fd < 0 ? serv->dgram_socket : serv->get_server_socket(server_socket_fd);
        }
        break;
    default:
        abort();
        break;
    }
    SW_CHECK_RETURN(server_socket->sendto(addr, port, data, len));
}

static PHP_METHOD(swoole_server, sendfile) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    char *filename;
    size_t len;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls|ll", &fd, &filename, &len, &offset, &length) == FAILURE) {
        RETURN_FALSE;
    }

    if (serv->is_master()) {
        php_swoole_fatal_error(E_WARNING, "can't sendfile[%s] to the connections in master process", filename);
        RETURN_FALSE;
    }

    RETURN_BOOL(serv->sendfile(fd, filename, len, offset, length));
}

static PHP_METHOD(swoole_server, close) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    zend_bool reset = false;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(fd)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(reset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(serv->close(fd, reset));
}

static PHP_METHOD(swoole_server, pause) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE) {
        RETURN_FALSE;
    }
    Connection *conn = serv->get_connection_verify(fd);
    if (!conn) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        RETURN_FALSE;
    }
    RETURN_BOOL(serv->feedback(conn, SW_SERVER_EVENT_PAUSE_RECV));
}

static PHP_METHOD(swoole_server, resume) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE) {
        RETURN_FALSE;
    }
    Connection *conn = serv->get_connection_verify(fd);
    if (!conn) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        RETURN_FALSE;
    }
    RETURN_BOOL(serv->feedback(conn, SW_SERVER_EVENT_RESUME_RECV));
}

static PHP_METHOD(swoole_server, stats) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("start_time"), serv->gs->start_time);
    add_assoc_long_ex(return_value, ZEND_STRL("connection_num"), serv->gs->connection_num);
    add_assoc_long_ex(return_value, ZEND_STRL("abort_count"), serv->gs->abort_count);
    add_assoc_long_ex(return_value, ZEND_STRL("accept_count"), serv->gs->accept_count);
    add_assoc_long_ex(return_value, ZEND_STRL("close_count"), serv->gs->close_count);
    add_assoc_long_ex(return_value, ZEND_STRL("worker_num"), serv->worker_num);
    add_assoc_long_ex(return_value, ZEND_STRL("task_worker_num"), serv->task_worker_num);
    add_assoc_long_ex(return_value, ZEND_STRL("user_worker_num"), serv->get_user_worker_num());
    add_assoc_long_ex(return_value, ZEND_STRL("idle_worker_num"), serv->get_idle_worker_num());
    add_assoc_long_ex(return_value, ZEND_STRL("dispatch_count"), serv->gs->dispatch_count);
    add_assoc_long_ex(return_value, ZEND_STRL("request_count"), serv->gs->request_count);
    add_assoc_long_ex(return_value, ZEND_STRL("response_count"), serv->gs->response_count);
    add_assoc_long_ex(return_value, ZEND_STRL("total_recv_bytes"), serv->gs->total_recv_bytes);
    add_assoc_long_ex(return_value, ZEND_STRL("total_send_bytes"), serv->gs->total_send_bytes);
    add_assoc_long_ex(return_value, ZEND_STRL("pipe_packet_msg_id"), serv->gs->pipe_packet_msg_id);
    add_assoc_long_ex(return_value, ZEND_STRL("session_round"), serv->gs->session_round);
    add_assoc_long_ex(return_value, ZEND_STRL("min_fd"), serv->gs->min_fd);
    add_assoc_long_ex(return_value, ZEND_STRL("max_fd"), serv->gs->max_fd);

    if (SwooleWG.worker) {
        add_assoc_long_ex(return_value, ZEND_STRL("worker_request_count"), SwooleWG.worker->request_count);
        add_assoc_long_ex(return_value, ZEND_STRL("worker_response_count"), SwooleWG.worker->response_count);
        add_assoc_long_ex(return_value, ZEND_STRL("worker_dispatch_count"), SwooleWG.worker->dispatch_count);
    }

    if (serv->task_ipc_mode > Server::TASK_IPC_UNIXSOCK && serv->gs->task_workers.queue) {
        size_t queue_num = -1;
        size_t queue_bytes = -1;
        if (serv->gs->task_workers.queue->stat(&queue_num, &queue_bytes)) {
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_num"), queue_num);
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_bytes"), queue_bytes);
        }
    }

    if (serv->task_worker_num > 0) {
        add_assoc_long_ex(return_value, ZEND_STRL("task_idle_worker_num"), serv->get_idle_task_worker_num());
        add_assoc_long_ex(return_value, ZEND_STRL("tasking_num"), serv->get_task_count());
    }

    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peek_num"), Coroutine::get_peak_num());
}

static PHP_METHOD(swoole_server, reload) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_bool only_reload_taskworker = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &only_reload_taskworker) == FAILURE) {
        RETURN_FALSE;
    }

    int sig = only_reload_taskworker ? SIGUSR2 : SIGUSR1;
    if (swoole_kill(serv->gs->manager_pid, sig) < 0) {
        php_swoole_sys_error(E_WARNING, "failed to send the reload signal");
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_server, heartbeat) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_bool close_connection = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &close_connection) == FAILURE) {
        RETURN_FALSE;
    }

    if (serv->heartbeat_check_interval < 1) {
        RETURN_FALSE;
    }

    array_init(return_value);
    double now = microtime();

    serv->foreach_connection([serv, now, close_connection, return_value](Connection *conn) {
        SessionId session_id = conn->session_id;
        if (session_id <= 0) {
            return;
        }
        swoole_trace("heartbeat check fd=%d", conn->fd);
        if (serv->is_healthy_connection(now, conn)) {
            return;
        }
        if (close_connection) {
            conn->close_force = 1;
            serv->close(session_id, false);
        }
        add_next_index_long(return_value, session_id);
    });
}

static PHP_METHOD(swoole_server, taskwait) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (!serv->is_worker()) {
        php_swoole_fatal_error(E_WARNING, "taskwait method can only be used in the worker process");
        RETURN_FALSE;
    }

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    zval *zdata;
    double timeout = SW_TASKWAIT_TIMEOUT;
    // It's the index of task workers [0, task_worker_num)
    // not taskWorkerId (worker_num, worker_num+task_worker_num]
    zend_long task_worker_index = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|dl", &zdata, &timeout, &task_worker_index) == FAILURE) {
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, task_worker_index) < 0) {
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, zdata) < 0) {
        RETURN_FALSE;
    }

    int _dst_worker_id = (int) task_worker_index;
    TaskId task_id = buf.info.fd;

    // coroutine
    if (swoole_coroutine_is_in()) {
        ServerObject *server_object = server_fetch_object(Z_OBJ_P((zval *) serv->private_data_2));
        buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);

        TaskCo task_co{};
        task_co.co = Coroutine::get_current_safe();
        task_co.count = 1;
        task_co.result = return_value;

        sw_atomic_fetch_add(&serv->gs->tasking_num, 1);
        if (serv->gs->task_workers.dispatch(&buf, &_dst_worker_id) < 0) {
            sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);
            RETURN_FALSE;
        }

        server_object->property->task_coroutine_map[task_id] = &task_co;
        auto retval = task_co.co->yield_ex(timeout);
        server_object->property->task_coroutine_map.erase(task_id);

        if (!retval) {
            RETURN_FALSE;
        }
        return;
    }

    uint64_t notify;
    EventData *task_result = &(serv->task_result[SwooleG.process_id]);
    sw_memset_zero(task_result, sizeof(*task_result));
    Pipe *pipe = serv->task_notify_pipes.at(SwooleG.process_id).get();
    network::Socket *task_notify_socket = pipe->get_socket(false);

    // clear history task
    while (task_notify_socket->wait_event(0, SW_EVENT_READ) == SW_OK) {
        if (task_notify_socket->read(&notify, sizeof(notify)) <= 0) {
            break;
        }
    }

    sw_atomic_fetch_add(&serv->gs->tasking_num, 1);

    if (serv->gs->task_workers.dispatch_blocking(&buf, &_dst_worker_id) == SW_OK) {
        while (1) {
            if (task_notify_socket->wait_event((int) (timeout * 1000), SW_EVENT_READ) != SW_OK) {
                break;
            }
            if (pipe->read(&notify, sizeof(notify)) > 0) {
                if (task_result->info.fd != task_id) {
                    continue;
                }
                zval *task_notify_data = php_swoole_task_unpack(task_result);
                if (task_notify_data == nullptr) {
                    RETURN_FALSE;
                } else {
                    RETVAL_ZVAL(task_notify_data, 0, 0);
                    efree(task_notify_data);
                    return;
                }
                break;
            } else {
                php_swoole_sys_error(E_WARNING, "taskwait failed");
                break;
            }
        }
    } else {
        sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);
    }
    RETURN_FALSE;
}

static PHP_METHOD(swoole_server, taskWaitMulti) {
    if (swoole_coroutine_is_in()) {
        return ZEND_MN(swoole_server_taskCo)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    }

    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (!serv->is_worker()) {
        php_swoole_fatal_error(E_WARNING, "taskWaitMulti method can only be used in the worker process");
        RETURN_FALSE;
    }

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    zval *ztasks;
    double timeout = SW_TASKWAIT_TIMEOUT;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(ztasks)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    array_init(return_value);

    int dst_worker_id;
    int i = 0;
    int n_task = php_swoole_array_length(ztasks);

    if (n_task >= SW_MAX_CONCURRENT_TASK) {
        php_swoole_fatal_error(E_WARNING, "too many concurrent tasks");
        RETURN_FALSE;
    }

    int list_of_id[SW_MAX_CONCURRENT_TASK] = {};

    uint64_t notify;
    EventData *task_result = &(serv->task_result[SwooleG.process_id]);
    sw_memset_zero(task_result, sizeof(*task_result));
    Pipe *pipe = serv->task_notify_pipes.at(SwooleG.process_id).get();
    Worker *worker = serv->get_worker(SwooleG.process_id);

    File fp = swoole::make_tmpfile();
    if (!fp.ready()) {
        RETURN_FALSE;
    }
    std::string file_path = fp.get_path();
    fp.close();

    int *finish_count = (int *) task_result->data;

    worker->lock->lock();
    *finish_count = 0;

    swoole_strlcpy(task_result->data + 4, file_path.c_str(), SW_TASK_TMP_PATH_SIZE);
    worker->lock->unlock();

    // clear history task
    network::Socket *task_notify_socket = pipe->get_socket(false);
    task_notify_socket->set_nonblock();
    while (task_notify_socket->read(&notify, sizeof(notify)) > 0) {
    }
    task_notify_socket->set_block();

    zval *ztask;
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztasks), ztask)
    TaskId task_id = php_swoole_task_pack(&buf, ztask);
    if (task_id < 0) {
        php_swoole_fatal_error(E_WARNING, "task pack failed");
        goto _fail;
    }
    buf.info.ext_flags |= SW_TASK_WAITALL;
    dst_worker_id = -1;
    sw_atomic_fetch_add(&serv->gs->tasking_num, 1);
    if (serv->gs->task_workers.dispatch_blocking(&buf, &dst_worker_id) < 0) {
        php_swoole_sys_error(E_WARNING, "taskwait failed");
        task_id = -1;
    _fail:
        add_index_bool(return_value, i, 0);
        n_task--;
    } else {
        sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);
    }
    list_of_id[i] = task_id;
    i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0) {
        swoole_set_last_error(SW_ERROR_TASK_DISPATCH_FAIL);
        RETURN_FALSE;
    }

    pipe->set_timeout(timeout);
    double _now = microtime();
    while (n_task > 0) {
        int ret = pipe->read(&notify, sizeof(notify));
        if (ret > 0 && *finish_count < n_task) {
            if (microtime() - _now < timeout) {
                continue;
            }
        }
        break;
    }

    worker->lock->lock();
    auto content = swoole::file_get_contents(file_path);
    worker->lock->unlock();

    if (content.get() == nullptr) {
        RETURN_FALSE;
    }

    EventData *result;
    zval *zdata;
    uint32_t j;

    do {
        result = (EventData *) (content->str + content->offset);
        TaskId task_id = result->info.fd;
        zdata = php_swoole_task_unpack(result);
        if (zdata == nullptr) {
            goto _next;
        }
        for (j = 0; j < php_swoole_array_length(ztasks); j++) {
            if (list_of_id[j] == task_id) {
                break;
            }
        }
        (void) add_index_zval(return_value, j, zdata);
        efree(zdata);
    _next:
        content->offset += sizeof(DataHead) + result->info.len;
    } while (content->offset < 0 || (size_t) content->offset < content->length);
    // delete tmp file
    unlink(file_path.c_str());
}

static PHP_METHOD(swoole_server, taskCo) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (!serv->is_worker()) {
        php_swoole_fatal_error(E_WARNING, "taskCo method can only be used in the worker process");
        RETURN_FALSE;
    }

    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));

    zval *ztasks;
    double timeout = SW_TASKWAIT_TIMEOUT;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(ztasks)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int dst_worker_id = -1;
    TaskId task_id;
    int i = 0;
    uint32_t n_task = php_swoole_array_length(ztasks);

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    if (n_task >= SW_MAX_CONCURRENT_TASK) {
        php_swoole_fatal_error(E_WARNING, "too many concurrent tasks");
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0) {
        RETURN_FALSE;
    }

    int *list = (int *) ecalloc(n_task, sizeof(int));
    if (list == nullptr) {
        RETURN_FALSE;
    }

    TaskCo task_co;
    task_co.co = Coroutine::get_current_safe();

    array_init_size(return_value, n_task);

    zval *ztask;
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztasks), ztask) {
        task_id = php_swoole_task_pack(&buf, ztask);
        if (task_id < 0) {
            php_swoole_fatal_error(E_WARNING, "failed to pack task");
            goto _fail;
        }
        buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);
        dst_worker_id = -1;
        sw_atomic_fetch_add(&serv->gs->tasking_num, 1);
        if (serv->gs->task_workers.dispatch(&buf, &dst_worker_id) < 0) {
            task_id = -1;
        _fail:
            add_index_bool(return_value, i, 0);
            n_task--;
            sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);
        } else {
            server_object->property->task_coroutine_map[task_id] = &task_co;
        }
        list[i] = task_id;
        i++;
    }
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0) {
        swoole_set_last_error(SW_ERROR_TASK_DISPATCH_FAIL);
        RETURN_FALSE;
    }

    task_co.result = return_value;
    task_co.list = list;
    task_co.count = n_task;

    if (!task_co.co->yield_ex(timeout)) {
        bool is_called_in_taskCo = strcasecmp(EX(func)->internal_function.function_name->val, "taskCo") == 0;
        for (uint32_t i = 0; i < n_task; i++) {
            if (!zend_hash_index_exists(Z_ARRVAL_P(return_value), i)) {
                if (is_called_in_taskCo) {
                    add_index_bool(return_value, i, 0);
                }
                server_object->property->task_coroutine_map.erase(list[i]);
            }
        }
    }
}

static PHP_METHOD(swoole_server, task) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    ServerObject *server_object = server_fetch_object(Z_OBJ_P(ZEND_THIS));

    zval *zdata;
    zend_long task_worker_index = -1;
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(task_worker_index)
    Z_PARAM_FUNC_EX(fci, fci_cache, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_check_task_param(serv, task_worker_index) < 0) {
        RETURN_FALSE;
    }

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    if (php_swoole_task_pack(&buf, zdata) < 0) {
        RETURN_FALSE;
    }

    if (!serv->is_worker()) {
        buf.info.ext_flags |= SW_TASK_NOREPLY;
    } else if (fci.size) {
        buf.info.ext_flags |= SW_TASK_CALLBACK;
        sw_zend_fci_cache_persist(&fci_cache);
        server_object->property->task_callbacks[buf.info.fd] = fci_cache;
    }

    buf.info.ext_flags |= SW_TASK_NONBLOCK;

    int dst_task_worker_index = (int) task_worker_index;
    sw_atomic_fetch_add(&serv->gs->tasking_num, 1);

    if (serv->gs->task_workers.dispatch(&buf, &dst_task_worker_index) >= 0) {
        RETURN_LONG(buf.info.fd);
    }

    sw_atomic_fetch_sub(&serv->gs->tasking_num, 1);
    RETURN_FALSE;
}

static PHP_METHOD(swoole_server, command) {
    char *name;
    size_t l_name;
    zend_long process_id, process_type;
    zval *zdata;
    zend_bool json_decode = true;

    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(4, 5)
    Z_PARAM_STRING(name, l_name)
    Z_PARAM_LONG(process_id)
    Z_PARAM_LONG(process_type)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(json_decode)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    std::string msg;

    auto result = zend::function::call("json_encode", 1, zdata);
    if (!ZVAL_IS_STRING(&result.value)) {
        RETURN_FALSE;
    }
    msg.append(Z_STRVAL(result.value), Z_STRLEN(result.value));

    auto co = Coroutine::get_current_safe();
    bool donot_yield = false;
    Server::Command::Callback fn = [co, return_value, json_decode, &donot_yield](Server *serv, const std::string &msg) {
        if (json_decode) {
            zval argv[2];
            ZVAL_STRINGL(&argv[0], msg.c_str(), msg.length());
            ZVAL_BOOL(&argv[1], true);
            auto result = zend::function::call("json_decode", 2, argv);
            if (!zend_is_true(&result.value)) {
                RETURN_FALSE;
            } else {
                ZVAL_DUP(return_value, &result.value);
            }
            zval_dtor(&argv[0]);
        } else {
            ZVAL_STRINGL(return_value, msg.c_str(), msg.length());
        }

        if (co->is_suspending()) {
            co->resume();
        } else {
            donot_yield = true;
        }
    };

    if (!serv->command(
            (uint16_t) process_id, (Server::Command::ProcessType) process_type, std::string(name, l_name), msg, fn)) {
        RETURN_FALSE;
    }
    if (!donot_yield) {
        co->yield();
    }
}

static PHP_METHOD(swoole_server, sendMessage) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (!serv->onPipeMessage) {
        php_swoole_fatal_error(E_WARNING, "onPipeMessage is null, can't use sendMessage");
        RETURN_FALSE;
    }

    zval *zmessage;
    zend_long worker_id = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zl", &zmessage, &worker_id) == FAILURE) {
        RETURN_FALSE;
    }

    if ((serv->is_worker() || serv->is_task_worker()) && worker_id == SwooleG.process_id) {
        php_swoole_fatal_error(E_WARNING, "can't send messages to self");
        RETURN_FALSE;
    }
    if (worker_id < 0 || worker_id >= serv->worker_num + serv->task_worker_num) {
        php_swoole_fatal_error(E_WARNING, "worker_id[%d] is invalid", (int) worker_id);
        RETURN_FALSE;
    }

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    if (php_swoole_task_pack(&buf, zmessage) < 0) {
        RETURN_FALSE;
    }

    buf.info.type = SW_SERVER_EVENT_PIPE_MESSAGE;

    Worker *to_worker = serv->get_worker(worker_id);
    SW_CHECK_RETURN(serv->send_to_worker_from_worker(
        to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK));
}

static PHP_METHOD(swoole_server, finish) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }
    if (sw_unlikely(serv->task_enable_coroutine)) {
        php_swoole_fatal_error(E_ERROR,
                               "please use %s->finish instead when task_enable_coroutine is enable",
                               ZSTR_VAL(swoole_server_task_ce->name));
        RETURN_FALSE;
    }

    zval *zdata;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zdata)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(php_swoole_task_finish(serv, zdata, nullptr));
}

static PHP_METHOD(swoole_server_task, finish) {
    Server *serv = php_swoole_server_task_get_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zval *zdata;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zdata)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    DataHead *info = php_swoole_server_task_get_info(ZEND_THIS);
    SW_CHECK_RETURN(php_swoole_task_finish(serv, zdata, (EventData *) info));
}

static PHP_METHOD(swoole_server_task, pack) {
    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    zval *zdata;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zdata)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_task_pack(&buf, zdata) < 0) {
        RETURN_FALSE;
    }
    buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_NOREPLY);

    RETURN_STRINGL((char *) &buf, sizeof(buf.info) + buf.info.len);
}

static PHP_METHOD(swoole_server, bind) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd = 0;
    zend_long uid = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &fd, &uid) == FAILURE) {
        RETURN_FALSE;
    }

    if (uid > UINT32_MAX || uid < INT32_MIN) {
        php_swoole_fatal_error(E_WARNING, "uid can not be greater than %u or less than %d", UINT32_MAX, INT32_MIN);
        RETURN_FALSE;
    }

    Connection *conn = serv->get_connection_verify(fd);
    if (conn == nullptr) {
        RETURN_FALSE;
    }

    sw_spinlock(&conn->lock);
    if (conn->uid != 0) {
        RETVAL_FALSE;
    } else {
        conn->uid = (uint32_t) uid;
        RETVAL_TRUE;
    }
    sw_spinlock_release(&conn->lock);
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server, getSocket) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);

    zend_long port = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &port) == FAILURE) {
        RETURN_FALSE;
    }

    ListenPort *lp = serv->get_port(port);
    php_socket *socket_object = php_swoole_convert_to_socket(lp->get_fd());

    if (!socket_object) {
        RETURN_FALSE;
    }
    SW_ZVAL_SOCKET(return_value, socket_object);
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
}
#endif

static PHP_METHOD(swoole_server, getClientInfo) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    zend_long reactor_id = -1;
    zend_bool dont_check_connection = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|lb", &fd, &reactor_id, &dont_check_connection) == FAILURE) {
        RETURN_FALSE;
    }

    Connection *conn = serv->get_connection_verify(fd);
    if (!conn) {
        RETURN_FALSE;
    }
    // connection is closed
    if (conn->active == 0 && !dont_check_connection) {
        RETURN_FALSE;
    } else {
        array_init(return_value);

        if (conn->uid > 0 || serv->dispatch_mode == Server::DISPATCH_UIDMOD) {
            add_assoc_long(return_value, "uid", conn->uid);
        }
        if (conn->worker_id > 0 || serv->dispatch_mode == Server::DISPATCH_CO_CONN_LB) {
            add_assoc_long(return_value, "worker_id", conn->worker_id);
        }

        ListenPort *port = serv->get_port_by_fd(conn->fd);
        if (port && port->open_websocket_protocol) {
            add_assoc_long(return_value, "websocket_status", conn->websocket_status);
        }

#ifdef SW_USE_OPENSSL
        if (conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid) {
            add_assoc_stringl(
                return_value, "ssl_client_cert", conn->ssl_client_cert->str, conn->ssl_client_cert->length);
        }
#endif
        // server socket
        Connection *server_socket = serv->get_connection(conn->server_fd);
        if (server_socket) {
            add_assoc_long(return_value, "server_port", server_socket->info.get_port());
        }
        add_assoc_long(return_value, "server_fd", conn->server_fd);
        add_assoc_long(return_value, "socket_fd", conn->fd);
        add_assoc_long(return_value, "socket_type", conn->socket_type);
        add_assoc_long(return_value, "remote_port", conn->info.get_port());
        add_assoc_string(return_value, "remote_ip", (char *) conn->info.get_ip());
        add_assoc_long(return_value, "reactor_id", conn->reactor_id);
        add_assoc_long(return_value, "connect_time", conn->connect_time);
        add_assoc_long(return_value, "last_time", (int) conn->last_recv_time);
        add_assoc_double(return_value, "last_recv_time", conn->last_recv_time);
        add_assoc_double(return_value, "last_send_time", conn->last_send_time);
        add_assoc_double(return_value, "last_dispatch_time", conn->last_dispatch_time);
        add_assoc_long(return_value, "close_errno", conn->close_errno);
        add_assoc_long(return_value, "recv_queued_bytes", conn->recv_queued_bytes);
        add_assoc_long(return_value, "send_queued_bytes", conn->send_queued_bytes);
    }
}

static PHP_METHOD(swoole_server, getClientList) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long start_session_id = 0;
    zend_long find_count = 10;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ll", &start_session_id, &find_count) == FAILURE) {
        RETURN_FALSE;
    }

    // exceeded the maximum number of searches
    if (find_count > SW_MAX_FIND_COUNT) {
        php_swoole_fatal_error(E_WARNING, "swoole connection list max_find_count=%d", SW_MAX_FIND_COUNT);
        RETURN_FALSE;
    }

    // copy it out to avoid being overwritten by other processes
    int serv_max_fd = serv->get_maxfd();
    int start_fd;

    if (start_session_id == 0) {
        start_fd = serv->get_minfd();
    } else {
        Connection *conn = serv->get_connection_verify(start_session_id);
        if (!conn) {
            RETURN_FALSE;
        }
        start_fd = conn->fd;
    }

    if ((int) start_fd >= serv_max_fd) {
        RETURN_FALSE;
    }

    array_init(return_value);
    int fd = start_fd + 1;

    for (; fd <= serv_max_fd; fd++) {
        swoole_trace("maxfd=%d, fd=%d, find_count=%ld, start_fd=%ld", serv_max_fd, fd, find_count, start_session_id);
        Connection *conn = serv->get_connection_for_iterator(fd);
        if (conn) {
            SessionId session_id = conn->session_id;
            if (session_id <= 0) {
                continue;
            }
            add_next_index_long(return_value, session_id);
            find_count--;
        }
        // finish fetch
        if (find_count <= 0) {
            break;
        }
    }
}

static PHP_METHOD(swoole_server, sendwait) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd;
    zval *zdata;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz", &fd, &zdata) == FAILURE) {
        RETURN_FALSE;
    }

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0) {
        php_swoole_fatal_error(E_WARNING, "data is empty");
        RETURN_FALSE;
    }

    if (serv->is_process_mode() || serv->is_task_worker()) {
        php_swoole_fatal_error(E_WARNING, "can't sendwait");
        RETURN_FALSE;
    }

    RETURN_BOOL(serv->sendwait(fd, data, length));
}

static PHP_METHOD(swoole_server, exists) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long session_id;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(session_id)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Connection *conn = serv->get_connection_verify(session_id);
    if (!conn || conn->closed) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, protect) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long session_id;
    zend_bool value = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|b", &session_id, &value) == FAILURE) {
        RETURN_FALSE;
    }

    Connection *conn = serv->get_connection_verify(session_id);
    if (!conn || conn->closed) {
        RETURN_FALSE;
    } else {
        conn->protect = value;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, getWorkerId) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (!serv->is_worker() && !serv->is_task_worker()) {
        RETURN_FALSE;
    } else {
        RETURN_LONG(SwooleG.process_id);
    }
}

static PHP_METHOD(swoole_server, getWorkerStatus) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long worker_id = -1;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &worker_id) == FAILURE) {
        RETURN_FALSE;
    }

    Worker *worker;
    if (worker_id == -1) {
        worker = SwooleWG.worker;
    } else {
        worker = serv->get_worker(worker_id);
    }

    if (!worker) {
        RETURN_FALSE;
    } else {
        RETURN_LONG(worker->status);
    }
}

static PHP_METHOD(swoole_server, getWorkerPid) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    zend_long worker_id = -1;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &worker_id) == FAILURE) {
        RETURN_FALSE;
    }
    Worker *worker = worker_id < 0 ? SwooleWG.worker : serv->get_worker(worker_id);
    if (!worker) {
        RETURN_FALSE;
    }
    RETURN_LONG(worker->pid);
}

static PHP_METHOD(swoole_server, getManagerPid) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    RETURN_LONG(serv->gs->manager_pid);
}

static PHP_METHOD(swoole_server, getMasterPid) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    RETURN_LONG(serv->gs->master_pid);
}

static PHP_METHOD(swoole_server, shutdown) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (swoole_kill(serv->gs->master_pid, SIGTERM) < 0) {
        php_swoole_sys_error(E_WARNING, "failed to shutdown, kill(%d, SIGTERM) failed", serv->gs->master_pid);
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_server, stop) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_bool wait_reactor = 0;
    zend_long worker_id = SwooleG.process_id;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(worker_id)
    Z_PARAM_BOOL(wait_reactor)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (worker_id == SwooleG.process_id && wait_reactor == 0) {
        if (SwooleTG.reactor != nullptr) {
            SwooleTG.reactor->defer(
                [](void *data) {
                    Reactor *reactor = (Reactor *) data;
                    reactor->running = false;
                },
                SwooleTG.reactor);
        }
        serv->running = false;
    } else {
        Worker *worker = serv->get_worker(worker_id);
        if (worker == nullptr) {
            RETURN_FALSE;
        } else if (swoole_kill(worker->pid, SIGTERM) < 0) {
            php_swoole_sys_error(E_WARNING, "swKill(%d, SIGTERM) failed", worker->pid);
            RETURN_FALSE;
        }
    }
    RETURN_TRUE;
}

// swoole_connection_iterator

static PHP_METHOD(swoole_connection_iterator, __construct) {
    php_swoole_fatal_error(E_ERROR, "please use the Swoole\\Server->connections");
    return;
}

static PHP_METHOD(swoole_connection_iterator, rewind) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    iterator->index = 0;
    iterator->current_fd = iterator->serv->get_minfd();
}

static PHP_METHOD(swoole_connection_iterator, valid) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    int fd = iterator->current_fd;
    int max_fd = iterator->serv->get_maxfd();

    for (; fd <= max_fd; fd++) {
        Connection *conn = iterator->serv->get_connection_for_iterator(fd);
        if (!conn) {
            continue;
        }
        SessionId session_id = conn->session_id;
        if (session_id <= 0 ||
            (iterator->port && (iterator->port->get_fd() < 0 || conn->server_fd != iterator->port->get_fd()))) {
            continue;
        }
        iterator->session_id = session_id;
        iterator->current_fd = fd;
        iterator->index++;
        RETURN_TRUE;
    }

    RETURN_FALSE;
}

static PHP_METHOD(swoole_connection_iterator, current) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    RETURN_LONG(iterator->session_id);
}

static PHP_METHOD(swoole_connection_iterator, next) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    iterator->current_fd++;
}

static PHP_METHOD(swoole_connection_iterator, key) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    RETURN_LONG(iterator->index);
}

static PHP_METHOD(swoole_connection_iterator, count) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    if (iterator->port) {
        RETURN_LONG(iterator->port->gs->connection_num);
    } else {
        RETURN_LONG(iterator->serv->gs->connection_num);
    }
}

static PHP_METHOD(swoole_connection_iterator, offsetExists) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    zval *zserv = (zval *) iterator->serv->private_data_2;
    zval *zfd;
    zval retval;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE) {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(zserv, swoole_server_ce, nullptr, "exists", &retval, zfd);
    RETVAL_BOOL(Z_BVAL_P(&retval));
}

static PHP_METHOD(swoole_connection_iterator, offsetGet) {
    ConnectionIterator *iterator = php_swoole_connection_iterator_get_and_check_ptr(ZEND_THIS);
    zval *zserv = (zval *) iterator->serv->private_data_2;
    zval *zfd;
    zval retval;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE) {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(zserv, swoole_server_ce, nullptr, "getClientInfo", &retval, zfd);
    RETVAL_ZVAL(&retval, 0, 0);
}

static PHP_METHOD(swoole_connection_iterator, offsetSet) {}
static PHP_METHOD(swoole_connection_iterator, offsetUnset) {}
static PHP_METHOD(swoole_connection_iterator, __destruct) {}
