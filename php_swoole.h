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

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "php_streams.h"
#include "php_network.h"

#include "zend_variables.h"
#include "zend_interfaces.h"
#include "zend_closures.h"
#include "zend_exceptions.h"
#if PHP_VERSION_ID >= 80200
#include "zend_attributes.h"
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern zend_module_entry swoole_module_entry;
#define phpext_swoole_ptr &swoole_module_entry

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

// clang-format off
ZEND_BEGIN_MODULE_GLOBALS(swoole)
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_shortname;
    zend_bool enable_coroutine;
    zend_bool enable_preemptive_scheduler;
    zend_bool enable_library;
    long socket_buffer_size;
    int req_status;
ZEND_END_MODULE_GLOBALS(swoole)
// clang-format on

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif /* PHP_SWOOLE_H */
