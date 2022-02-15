#pragma once

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
SW_EXTERN_C_BEGIN

#include <curl/curl.h>
#include <curl/multi.h>

void swoole_native_curl_minit(int module_number);
void swoole_native_curl_mshutdown();
void swoole_native_curl_rinit();

PHP_FUNCTION(swoole_native_curl_close);
PHP_FUNCTION(swoole_native_curl_copy_handle);
PHP_FUNCTION(swoole_native_curl_errno);
PHP_FUNCTION(swoole_native_curl_error);
PHP_FUNCTION(swoole_native_curl_exec);
PHP_FUNCTION(swoole_native_curl_getinfo);
PHP_FUNCTION(swoole_native_curl_init);
PHP_FUNCTION(swoole_native_curl_setopt);
PHP_FUNCTION(swoole_native_curl_setopt_array);

#if LIBCURL_VERSION_NUM >= 0x070c01 /* 7.12.1 */
PHP_FUNCTION(swoole_native_curl_reset);
#endif

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
PHP_FUNCTION(swoole_native_curl_escape);
PHP_FUNCTION(swoole_native_curl_unescape);
#endif

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
PHP_FUNCTION(swoole_native_curl_pause);
#endif
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
SW_EXTERN_C_END
#endif
