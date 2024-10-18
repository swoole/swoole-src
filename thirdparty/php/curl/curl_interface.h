#pragma once

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
SW_EXTERN_C_BEGIN

#include <curl/curl.h>
#include <curl/multi.h>

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
SW_EXTERN_C_END
#endif
