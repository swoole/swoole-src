/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2017 The PHP Group                                |
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

/* $Id$ */

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

extern zend_module_entry curl_module_entry;
#define curl_module_ptr &curl_module_entry

#define CURLOPT_RETURNTRANSFER 19913
#define CURLOPT_BINARYTRANSFER 19914 /* For Backward compatibility */
#define PHP_CURL_STDOUT 0
#define PHP_CURL_FILE   1
#define PHP_CURL_USER   2
#define PHP_CURL_DIRECT 3
#define PHP_CURL_RETURN 4
#define PHP_CURL_IGNORE 7

#define le_curl_name "Swoole-Coroutine-cURL Handle"
#define le_curl_multi_handle_name "Swoole-Coroutine-cURL Multi Handle"
#define le_curl_share_handle_name "Swoole-Coroutine-cURL Share Handle"

void _php_curl_multi_close(zend_resource *);
void _php_curl_share_close(zend_resource *);

typedef struct {
	zval                  func_name;
	zend_fcall_info_cache fci_cache;
	FILE                 *fp;
	smart_str             buf;
	int                   method;
	zval					stream;
} php_curl_write;

typedef struct {
	zval                  func_name;
	zend_fcall_info_cache fci_cache;
	FILE                 *fp;
	zend_resource        *res;
	int                   method;
	zval                  stream;
} php_curl_read;

typedef struct {
	zval                  func_name;
	zend_fcall_info_cache fci_cache;
	int                   method;
} php_curl_progress, php_curl_fnmatch, php_curlm_server_push;

typedef struct {
	php_curl_write    *write;
	php_curl_write    *write_header;
	php_curl_read     *read;
#if CURLOPT_PASSWDFUNCTION != 0
	zval               passwd;
#endif
	zval               std_err;
	php_curl_progress *progress;
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
	php_curl_fnmatch  *fnmatch;
#endif
} php_curl_handlers;

struct _php_curl_error  {
	char str[CURL_ERROR_SIZE + 1];
	int  no;
};

struct _php_curl_send_headers {
	zend_string *str;
};

struct _php_curl_free {
	zend_llist str;
	zend_llist post;
	HashTable *slist;
};

typedef struct {
	CURL                         *cp;
	php_curl_handlers            *handlers;
	zend_resource                *res;
	struct _php_curl_free        *to_free;
	struct _php_curl_send_headers header;
	struct _php_curl_error        err;
	zend_bool                     in_callback;
	uint32_t*                     clone;
	swoole::Coroutine *co;
	swoole::FutureTask *context;
	std::function<bool(void)> *callback;
} php_curl;

#define CURLOPT_SAFE_UPLOAD -1

typedef struct {
	php_curlm_server_push	*server_push;
} php_curlm_handlers;

typedef struct {
	int         still_running;
	CURLM      *multi;
	zend_llist  easyh;
	php_curlm_handlers	*handlers;
	struct {
		int no;
	} err;
} php_curlm;

typedef struct {
	CURLSH                   *share;
	struct {
		int no;
	} err;
} php_curlsh;

php_curl *alloc_curl_handle();
void _php_curl_cleanup_handle(php_curl *);
void _php_curl_multi_cleanup_list(void *data);
void _php_curl_verify_handlers(php_curl *ch, int reporterror);
void _php_setup_easy_copy_handlers(php_curl *ch, php_curl *source);

void curlfile_register_class(void);
PHP_CURL_API extern zend_class_entry *curl_CURLFile_class;

#else
#define curl_module_ptr NULL
#endif /* HAVE_CURL */
#define phpext_curl_ptr curl_module_ptr
