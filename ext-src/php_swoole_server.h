/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#pragma once

#include "php_swoole_cxx.h"
#include "swoole_server.h"

#include <unordered_map>
#include <list>
#include <vector>

//--------------------------------------------------------
enum php_swoole_server_callback_type {
    SW_SERVER_CB_onStart,           // master
    SW_SERVER_CB_onBeforeShutdown,  // master
    SW_SERVER_CB_onShutdown,        // master
    SW_SERVER_CB_onWorkerStart,     // worker(event & task)
    SW_SERVER_CB_onWorkerStop,      // worker(event & task)
    SW_SERVER_CB_onBeforeReload,    // manager
    SW_SERVER_CB_onAfterReload,     // manager
    SW_SERVER_CB_onTask,            // worker(task)
    SW_SERVER_CB_onFinish,          // worker(event & task)
    SW_SERVER_CB_onWorkerExit,      // worker(event)
    SW_SERVER_CB_onWorkerError,     // manager
    SW_SERVER_CB_onManagerStart,    // manager
    SW_SERVER_CB_onManagerStop,     // manager
    SW_SERVER_CB_onPipeMessage,     // worker(event & task)
};
//--------------------------------------------------------
enum php_swoole_server_port_callback_type {
    SW_SERVER_CB_onConnect,      // stream, worker(event)
    SW_SERVER_CB_onReceive,      // stream, worker(event)
    SW_SERVER_CB_onClose,        // stream, worker(event)
    SW_SERVER_CB_onPacket,       // dgram, worker(event)
    SW_SERVER_CB_onRequest,      // http, worker(event)
    SW_SERVER_CB_onHandshake,    // websocket, worker(event)
    SW_SERVER_CB_onOpen,         // websocket, worker(event)
    SW_SERVER_CB_onMessage,      // websocket, worker(event)
    SW_SERVER_CB_onDisconnect,   // websocket (non websocket connection), worker(event)
    SW_SERVER_CB_onBufferFull,   // worker(event)
    SW_SERVER_CB_onBufferEmpty,  // worker(event)
};

#define PHP_SWOOLE_SERVER_CALLBACK_NUM (SW_SERVER_CB_onPipeMessage + 1)
#define PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM (SW_SERVER_CB_onBufferEmpty + 1)

namespace swoole {
struct TaskCo;

struct ServerPortProperty {
    zval *callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zend_fcall_info_cache *caches[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zval _callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    Server *serv;
    ListenPort *port;
    zval *zsetting;
};

struct ServerProperty {
    std::vector<zval *> ports;
    std::vector<zval *> user_processes;
    ServerPortProperty *primary_port;
    zend_fcall_info_cache *callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];
    std::unordered_map<TaskId, zend_fcall_info_cache> task_callbacks;
    std::unordered_map<TaskId, TaskCo *> task_coroutine_map;
    std::unordered_map<SessionId, std::list<Coroutine *> *> send_coroutine_map;
    std::vector<zend_fcall_info_cache *> command_callbacks;
};

struct ServerObject {
    Server *serv;
    ServerProperty *property;
    zend_object std;

    zend_class_entry *get_ce() {
        return Z_OBJCE_P(get_object());
    }

    zval *get_object() {
        return (zval *) serv->private_data_2;
    }

    bool isset_callback(ListenPort *port, int event_type) {
        ServerPortProperty *port_property = (ServerPortProperty *) port->ptr;
        return (port_property->callbacks[event_type] || property->primary_port->callbacks[event_type]);
    }

    zend_bool is_websocket_server() {
        return instanceof_function(get_ce(), swoole_websocket_server_ce);
    }

    zend_bool is_http_server() {
        return instanceof_function(get_ce(), swoole_http_server_ce);
    }

    zend_bool is_redis_server() {
        return instanceof_function(get_ce(), swoole_redis_server_ce);
    }

    void register_callback();
    void on_before_start();
};

struct TaskCo {
    Coroutine *co;
    int *list;
    uint32_t count;
    zval *result;
};
void register_admin_server_commands(Server *serv);
}  // namespace swoole

void php_swoole_server_register_callbacks(swServer *serv);
zend_fcall_info_cache *php_swoole_server_get_fci_cache(swServer *serv, int server_fd, int event_type);
int php_swoole_create_dir(const char *path, size_t length);
void php_swoole_server_before_start(swServer *serv, zval *zobject);
bool php_swoole_server_isset_callback(swServer *serv, swListenPort *port, int event_type);
void php_swoole_http_server_init_global_variant();
void php_swoole_server_send_yield(swServer *serv, swoole::SessionId sesion_id, zval *zdata, zval *return_value);
void php_swoole_get_recv_data(swServer *serv, zval *zdata, swRecvData *req);
void php_swoole_server_onConnect(swServer *, swDataHead *);
int php_swoole_server_onReceive(swServer *, swRecvData *);
int php_swoole_http_server_onReceive(swServer *, swRecvData *);
int php_swoole_redis_server_onReceive(swServer *serv, swRecvData *req);
int php_swoole_server_onPacket(swServer *, swRecvData *);
void php_swoole_server_onClose(swServer *, swDataHead *);
void php_swoole_server_onBufferFull(swServer *, swDataHead *);
void php_swoole_server_onBufferEmpty(swServer *, swDataHead *);

swServer *php_swoole_server_get_and_check_server(zval *zobject);
void php_swoole_server_port_deref(zend_object *object);
swoole::ServerObject *php_swoole_server_get_zend_object(swoole::Server *serv);
zval *php_swoole_server_get_zval_object(swoole::Server *serv);
