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

#ifdef __cplusplus
extern "C" {
#endif

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
#include "zend_attributes.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* PHP 8.6 removed several long-standing Zend API aliases; keep compatibility shims. */
#if PHP_VERSION_ID >= 80600
#ifndef ZVAL_IS_NULL
#define ZVAL_IS_NULL(z) Z_ISNULL_P(z)
#endif
#ifndef zval_dtor
#define zval_dtor(z) zval_ptr_dtor_nogc(z)
#endif
#ifndef zval_is_true
#define zval_is_true(z) zend_is_true(z)
#endif
#ifndef ZEND_PARSE_PARAMS_THROW
#define ZEND_PARSE_PARAMS_THROW 0
#endif
#ifndef XtOffsetOf
#define XtOffsetOf(s_type, field) offsetof(s_type, field)
#endif
#ifndef INI_STR
#define INI_STR(name) ((char *) zend_ini_string_literal(name))
#endif
#ifndef INI_INT
#define INI_INT(name) zend_ini_long_literal(name)
#endif
#ifndef INI_BOOL
#define INI_BOOL(name) zend_ini_bool_literal(name)
#endif
#ifndef INI_FLT
#define INI_FLT(name) zend_ini_double_literal(name)
#endif
#ifndef EMPTY_SWITCH_DEFAULT_CASE
#define EMPTY_SWITCH_DEFAULT_CASE()                                                                                    \
    default:                                                                                                           \
        ZEND_UNREACHABLE();
#endif
#define zend_parse_parameters_throw zend_parse_parameters
#define zend_parse_parameters_none_throw zend_parse_parameters_none
/* php_error_docref1/2 were removed; args are shown via error_include_args INI. */
#ifndef php_error_docref1
#define php_error_docref1(docref, arg1, type, ...) php_error_docref((docref), (type), __VA_ARGS__)
#endif
#ifndef php_error_docref2
#define php_error_docref2(docref, arg1, arg2, type, ...) php_error_docref((docref), (type), __VA_ARGS__)
#endif
/* Renamed in PHP 8.6 (main/php_odbc_utils.h). */
#ifndef php_odbc_connstr_estimate_quote_length
#define php_odbc_connstr_estimate_quote_length php_odbc_connstr_get_quoted_length
#endif
#endif

#ifdef __cplusplus
}
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
    zend_bool enable_preemptive_scheduler;
    zend_bool enable_library;
    zend_bool enable_fiber_mock;
    zend_bool blocking_detection;
    zend_long blocking_threshold;
    zend_bool profile;
    zend_bool leak_detection;
    zend_long socket_buffer_size;
    int req_status;
    HashTable *in_autoload;
ZEND_END_MODULE_GLOBALS(swoole)
// clang-format on

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif /* PHP_SWOOLE_H */
