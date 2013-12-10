/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2012 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  tianfenghan                                                 |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"

extern zend_module_entry swoole_module_entry;
#define phpext_swoole_ptr &swoole_module_entry

#ifdef PHP_WIN32
#	define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_SWOOLE_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif
//#define SW_USE_PHP        1
#define SW_HANDLE_NUM
#define SW_CHECK_RETURN(s)  if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return

#define SW_RES_SERVER_NAME          "SwooleServer"
#define SW_RES_CLIENT_NAME          "SwooleClient"
#define SW_RES_LOCK_NAME            "SwooleLock"

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_server_create);
PHP_FUNCTION(swoole_server_set);
PHP_FUNCTION(swoole_server_start);
PHP_FUNCTION(swoole_server_stop);
PHP_FUNCTION(swoole_server_send);
PHP_FUNCTION(swoole_server_close);
PHP_FUNCTION(swoole_server_handler);
PHP_FUNCTION(swoole_server_addlisten);
PHP_FUNCTION(swoole_server_addtimer);
PHP_FUNCTION(swoole_server_deltimer);
PHP_FUNCTION(swoole_server_task);
PHP_FUNCTION(swoole_server_finish);
PHP_FUNCTION(swoole_server_reload);
PHP_FUNCTION(swoole_server_shutdown);
PHP_FUNCTION(swoole_connection_list);
PHP_FUNCTION(swoole_connection_info);

PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
#endif

PHP_FUNCTION(swoole_client_select);

PHP_METHOD(swoole_client, __construct);
PHP_METHOD(swoole_client, connect);
PHP_METHOD(swoole_client, recv);
PHP_METHOD(swoole_client, send);
PHP_METHOD(swoole_client, close);
PHP_METHOD(swoole_client, on);

PHP_METHOD(swoole_lock, __construct);
PHP_METHOD(swoole_lock, lock);
PHP_METHOD(swoole_lock, trylock);
PHP_METHOD(swoole_lock, lock_read);
PHP_METHOD(swoole_lock, trylock_read);
PHP_METHOD(swoole_lock, unlock);

void swoole_destory_lock(zend_rsrc_list_entry *rsrc TSRMLS_DC);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif	/* PHP_SWOOLE_H */
