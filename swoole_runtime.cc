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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */
#include "php_swoole.h"

#ifdef SW_USE_PHPX

#include <initializer_list>

extern "C"
{
static PHP_METHOD(swoole_runtime, enableStrictMode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

zend_class_entry *ce;

static const zend_function_entry swoole_runtime_methods[] =
{
    PHP_ME(swoole_runtime, enableStrictMode, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_runtime_init(int module_number TSRMLS_DC)
{
    static zend_class_entry _ce;
    INIT_CLASS_ENTRY(_ce, "Swoole\\Runtime", swoole_runtime_methods);
    ce = zend_register_internal_class(&_ce TSRMLS_CC);
}

static auto block_io_functions =
{ "sleep", "usleep", "time_nanosleep", "time_sleep_until", "file_get_contents", "curl_init", "stream_select",
        "socket_select", "gethostbyname", };

static auto block_io_classes =
{ "redis", "mysqli", };

static PHP_METHOD(swoole_runtime, enableStrictMode)
{
    for (auto f : block_io_functions)
    {
        zend_disable_function((char *) f, strlen((char *) f));
    }
    for (auto c : block_io_classes)
    {
        zend_disable_class((char *) c, strlen((char *) c));
    }
}

#endif
