/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | Copyright (c) 2012-2018 The Swoole Group                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
*/
#pragma once

#include "php_swoole_cxx.h"
#if defined(SW_USE_CURL) && PHP_VERSION_ID >= 80300 && PHP_VERSION_ID < 80400
SW_EXTERN_C_BEGIN

#include <curl/curl.h>
#include <curl/multi.h>

void swoole_native_curl_minit(int module_number);
void swoole_native_curl_mshutdown();

ZEND_FUNCTION(swoole_native_curl_close);
ZEND_FUNCTION(swoole_native_curl_copy_handle);
ZEND_FUNCTION(swoole_native_curl_errno);
ZEND_FUNCTION(swoole_native_curl_error);
ZEND_FUNCTION(swoole_native_curl_escape);
ZEND_FUNCTION(swoole_native_curl_unescape);
ZEND_FUNCTION(swoole_native_curl_multi_setopt);
ZEND_FUNCTION(swoole_native_curl_exec);
ZEND_FUNCTION(swoole_native_curl_getinfo);
ZEND_FUNCTION(swoole_native_curl_init);
#if LIBCURL_VERSION_NUM >= 0x073E00 /* Available since 7.62.0 */
ZEND_FUNCTION(swoole_native_curl_upkeep);
#endif
ZEND_FUNCTION(swoole_native_curl_multi_add_handle);
ZEND_FUNCTION(swoole_native_curl_multi_close);
ZEND_FUNCTION(swoole_native_curl_multi_errno);
ZEND_FUNCTION(swoole_native_curl_multi_exec);
ZEND_FUNCTION(swoole_native_curl_multi_getcontent);
ZEND_FUNCTION(swoole_native_curl_multi_info_read);
ZEND_FUNCTION(swoole_native_curl_multi_init);
ZEND_FUNCTION(swoole_native_curl_multi_remove_handle);
ZEND_FUNCTION(swoole_native_curl_multi_select);
ZEND_FUNCTION(swoole_native_curl_multi_strerror);
ZEND_FUNCTION(swoole_native_curl_pause);
ZEND_FUNCTION(swoole_native_curl_reset);
ZEND_FUNCTION(swoole_native_curl_setopt_array);
ZEND_FUNCTION(swoole_native_curl_setopt);
ZEND_FUNCTION(swoole_native_curl_strerror);
ZEND_FUNCTION(swoole_native_curl_version);
SW_EXTERN_C_END
#endif
