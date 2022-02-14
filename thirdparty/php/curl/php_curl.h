/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Sterling Hughes <sterling@php.net>                           |
   |         Wez Furlong <wez@thebrainroom.com>                           |
   +----------------------------------------------------------------------+
*/

/* Copied from PHP-7.4.11 */

#ifdef SW_USE_CURL

#ifndef _PHP_CURL_H
#define _PHP_CURL_H

#include "php.h"
#include "zend_smart_str.h"

#define PHP_CURL_DEBUG 0

#ifdef PHP_WIN32
# define PHP_CURL_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_CURL_API __attribute__ ((visibility("default")))
#else
# define PHP_CURL_API
#endif

#include "php_version.h"
#define PHP_CURL_VERSION PHP_VERSION

#include <curl/curl.h>
#include <curl/multi.h>

#define CURLOPT_RETURNTRANSFER 19913
#define CURLOPT_BINARYTRANSFER 19914 /* For Backward compatibility */
#define PHP_CURL_STDOUT 0
#define PHP_CURL_FILE   1
#define PHP_CURL_USER   2
#define PHP_CURL_DIRECT 3
#define PHP_CURL_RETURN 4
#define PHP_CURL_IGNORE 7

#if PHP_VERSION_ID < 80000
#define le_curl_name "Swoole-Coroutine-cURL-Handle"
#define le_curl_multi_handle_name "Swoole-Coroutine-cURL-Multi-Handle"
#endif

#if PHP_VERSION_ID >= 80000
PHP_CURL_API extern zend_class_entry *curl_ce;
PHP_CURL_API extern zend_class_entry *curl_share_ce;
PHP_CURL_API extern zend_class_entry *curl_multi_ce;
PHP_CURL_API extern zend_class_entry *swoole_coroutine_curl_handle_ce;
PHP_CURL_API extern zend_class_entry *swoole_coroutine_curl_multi_handle_ce;
#endif

PHP_CURL_API extern zend_class_entry *curl_CURLFile_class;

#else
#define curl_module_ptr NULL
#endif /* HAVE_CURL */
#define phpext_curl_ptr curl_module_ptr
#endif
