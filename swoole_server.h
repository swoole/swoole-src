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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#pragma once

#include "php_swoole_cxx.h"
#include "server.h"

//--------------------------------------------------------
enum php_swoole_server_callback_type
{
    SW_SERVER_CB_onStart,          //master
    SW_SERVER_CB_onShutdown,       //master
    SW_SERVER_CB_onWorkerStart,    //worker(event & task)
    SW_SERVER_CB_onWorkerStop,     //worker(event & task)
    SW_SERVER_CB_onBeforeReload,     //manager
    SW_SERVER_CB_onAfterReload,     //manager
    SW_SERVER_CB_onTask,           //worker(task)
    SW_SERVER_CB_onFinish,         //worker(event & task)
    SW_SERVER_CB_onWorkerExit,     //worker(event)
    SW_SERVER_CB_onWorkerError,    //manager
    SW_SERVER_CB_onManagerStart,   //manager
    SW_SERVER_CB_onManagerStop,    //manager
    SW_SERVER_CB_onPipeMessage,    //worker(event & task)
};
//--------------------------------------------------------
enum php_swoole_server_port_callback_type
{
    SW_SERVER_CB_onConnect,        //worker(event)
    SW_SERVER_CB_onReceive,        //worker(event)
    SW_SERVER_CB_onClose,          //worker(event)
    SW_SERVER_CB_onPacket,         //worker(event)
    SW_SERVER_CB_onRequest,        //http server
    SW_SERVER_CB_onHandShake,      //worker(event)
    SW_SERVER_CB_onOpen,           //worker(event)
    SW_SERVER_CB_onMessage,        //worker(event)
    SW_SERVER_CB_onBufferFull,     //worker(event)
    SW_SERVER_CB_onBufferEmpty,    //worker(event)
};

#define PHP_SWOOLE_SERVER_CALLBACK_NUM         (SW_SERVER_CB_onPipeMessage + 1)
#define PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM    (SW_SERVER_CB_onBufferEmpty + 1)

typedef struct
{
    zval *callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zend_fcall_info_cache *caches[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zval _callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    swServer *serv;
    swListenPort *port;
    zval *zsetting;
} php_swoole_server_port_property;

void php_swoole_server_register_callbacks(swServer *serv);
zend_fcall_info_cache* php_swoole_server_get_fci_cache(swServer *serv, int server_fd, int event_type);
void php_swoole_server_before_start(swServer *serv, zval *zobject);
void php_swoole_http_server_init_global_variant();
void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value);
void php_swoole_get_recv_data(swServer *serv, zval *zdata, swEventData *req);
void php_swoole_onConnect(swServer *, swDataHead *);
int php_swoole_onReceive(swServer *, swEventData *);
int php_swoole_http_onReceive(swServer *, swEventData *);
void php_swoole_http_onClose(swServer *, swDataHead *);
int php_swoole_onPacket(swServer *, swEventData *);
void php_swoole_onClose(swServer *, swDataHead *);
void php_swoole_onBufferFull(swServer *, swDataHead *);
void php_swoole_onBufferEmpty(swServer *, swDataHead *);
