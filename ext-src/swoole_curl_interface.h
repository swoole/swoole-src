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
 */

#pragma once

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
SW_EXTERN_C_BEGIN

#include <curl/curl.h>
#include <curl/multi.h>

#define curl_easy_reset swoole_curl_easy_reset

void swoole_native_curl_minit(int module_number);
void swoole_native_curl_mshutdown();

PHP_FUNCTION(swoole_native_curl_close);
PHP_FUNCTION(swoole_native_curl_copy_handle);
PHP_FUNCTION(swoole_native_curl_errno);
PHP_FUNCTION(swoole_native_curl_error);
PHP_FUNCTION(swoole_native_curl_exec);
PHP_FUNCTION(swoole_native_curl_getinfo);
PHP_FUNCTION(swoole_native_curl_init);
PHP_FUNCTION(swoole_native_curl_setopt);
PHP_FUNCTION(swoole_native_curl_setopt_array);
PHP_FUNCTION(swoole_native_curl_reset);
PHP_FUNCTION(swoole_native_curl_escape);
PHP_FUNCTION(swoole_native_curl_unescape);
PHP_FUNCTION(swoole_native_curl_pause);
PHP_FUNCTION(swoole_native_curl_multi_add_handle);
PHP_FUNCTION(swoole_native_curl_multi_close);
PHP_FUNCTION(swoole_native_curl_multi_errno);
PHP_FUNCTION(swoole_native_curl_multi_exec);
PHP_FUNCTION(swoole_native_curl_multi_select);
PHP_FUNCTION(swoole_native_curl_multi_remove_handle);
PHP_FUNCTION(swoole_native_curl_multi_setopt);
PHP_FUNCTION(swoole_native_curl_multi_getcontent);
PHP_FUNCTION(swoole_native_curl_multi_info_read);
PHP_FUNCTION(swoole_native_curl_multi_init);
#if LIBCURL_VERSION_NUM >= 0x073E00
PHP_FUNCTION(swoole_native_curl_upkeep);
#endif

SW_EXTERN_C_END
#endif
