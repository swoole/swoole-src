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

SW_EXTERN_C_BEGIN
PHP_FUNCTION(swoole_call_array_method);
PHP_FUNCTION(swoole_call_string_method);
PHP_FUNCTION(swoole_call_stream_method);
PHP_FUNCTION(swoole_array_search);
PHP_FUNCTION(swoole_array_contains);
PHP_FUNCTION(swoole_array_join);
PHP_FUNCTION(swoole_array_key_exists);
PHP_FUNCTION(swoole_array_map);
PHP_FUNCTION(swoole_array_is_typed);
PHP_FUNCTION(swoole_array_is_empty);
PHP_FUNCTION(swoole_str_split);
PHP_FUNCTION(swoole_str_is_empty);
PHP_FUNCTION(swoole_str_match);
PHP_FUNCTION(swoole_str_match_all);
PHP_FUNCTION(swoole_parse_str);
PHP_FUNCTION(swoole_hash);
PHP_FUNCTION(swoole_typed_array);
SW_EXTERN_C_END