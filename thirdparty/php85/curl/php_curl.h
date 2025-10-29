/*
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Sterling Hughes <sterling@php.net>                           |
   |         Wez Furlong <wez@thebrainroom.com>                           |
   +----------------------------------------------------------------------+
*/

#if defined(SW_USE_CURL) && PHP_VERSION_ID >= 80400

#ifndef _PHP_CURL_H
#define _PHP_CURL_H

#include "php.h"
#include "zend_smart_str.h"

#define PHP_CURL_DEBUG 0

#ifdef PHP_WIN32
#ifdef PHP_CURL_EXPORTS
#define PHP_CURL_API __declspec(dllexport)
#else
#define PHP_CURL_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define PHP_CURL_API __attribute__((visibility("default")))
#else
#define PHP_CURL_API
#endif

PHP_CURL_API extern zend_class_entry *curl_ce;
PHP_CURL_API extern zend_class_entry *curl_share_ce;
PHP_CURL_API extern zend_class_entry *curl_multi_ce;
PHP_CURL_API extern zend_class_entry *swoole_coroutine_curl_handle_ce;
PHP_CURL_API extern zend_class_entry *swoole_coroutine_curl_multi_handle_ce;
PHP_CURL_API extern zend_class_entry *curl_CURLFile_class;
PHP_CURL_API extern zend_class_entry *curl_CURLStringFile_class;

#endif /* _PHP_CURL_H */
#endif
