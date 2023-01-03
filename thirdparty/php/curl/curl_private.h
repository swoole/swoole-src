/*
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

/* Copied from PHP-4f68662f5b61aecf90f6d8005976f5f91d4ce8d3 */

#ifdef SW_USE_CURL

#ifndef _PHP_CURL_PRIVATE_H
#define _PHP_CURL_PRIVATE_H

#include "php_curl.h"

#define PHP_CURL_DEBUG 0

#include "php_version.h"
#define PHP_CURL_VERSION PHP_VERSION

#include <curl/curl.h>
#include <curl/multi.h>

#define CURLOPT_RETURNTRANSFER 19913
#define CURLOPT_BINARYTRANSFER 19914 /* For Backward compatibility */
#define PHP_CURL_STDOUT 0
#define PHP_CURL_FILE 1
#define PHP_CURL_USER 2
#define PHP_CURL_DIRECT 3
#define PHP_CURL_RETURN 4
#define PHP_CURL_IGNORE 7

#define SAVE_CURL_ERROR(__handle, __err)                                                                               \
    do {                                                                                                               \
        (__handle)->err.no = (int) __err;                                                                              \
    } while (0)

typedef struct {
    zval func_name;
    zend_fcall_info_cache fci_cache;
    FILE *fp;
    smart_str buf;
    int method;
    zval stream;
} php_curl_write;

typedef struct {
    zval func_name;
    zend_fcall_info_cache fci_cache;
    FILE *fp;
    zend_resource *res;
    int method;
    zval stream;
} php_curl_read;

typedef struct {
    zval func_name;
    zend_fcall_info_cache fci_cache;
    int method;
} php_curl_progress, php_curl_fnmatch, php_curlm_server_push, php_curl_fnxferinfo;

typedef struct {
    php_curl_write *write;
    php_curl_write *write_header;
    php_curl_read *read;
    zval std_err;
    php_curl_progress *progress;
#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
    php_curl_fnxferinfo *xferinfo;
#endif
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    php_curl_fnmatch *fnmatch;
#endif
} php_curl_handlers;

struct _php_curl_error {
    char str[CURL_ERROR_SIZE + 1];
    int no;
};

struct _php_curl_send_headers {
    zend_string *str;
};

#if PHP_VERSION_ID >= 80100
struct _php_curl_free {
    zend_llist post;
    zend_llist stream;
#if LIBCURL_VERSION_NUM < 0x073800 /* 7.56.0 */
    zend_llist buffers;
#endif
    HashTable *slist;
};
#else
struct _php_curl_free {
    zend_llist str;
    zend_llist post;
    zend_llist stream;
    HashTable *slist;
};
#endif

typedef struct {
    CURL *cp;
#if PHP_VERSION_ID >= 80100
    php_curl_handlers handlers;
#else
    php_curl_handlers *handlers;
#endif
#if PHP_VERSION_ID < 80000
    zend_resource *res;
#endif
    struct _php_curl_free *to_free;
    struct _php_curl_send_headers header;
    struct _php_curl_error err;
    zend_bool in_callback;
    uint32_t *clone;
    zval postfields;
#if PHP_VERSION_ID >= 80100 || PHP_VERSION_ID < 80000
    zval private_data;
#endif
    /* CurlShareHandle object set using CURLOPT_SHARE. */
#if PHP_VERSION_ID >= 80000
    struct _php_curlsh *share;
    zend_object std;
#endif
} php_curl;

#define CURLOPT_SAFE_UPLOAD -1

typedef struct {
    php_curlm_server_push *server_push;
} php_curlm_handlers;

namespace swoole {
namespace curl {
class Multi;
}
}  // namespace swoole

using swoole::curl::Multi;

typedef struct {
#if PHP_VERSION_ID < 80100
    int still_running;
#endif
    Multi *multi;
    zend_llist easyh;
#if PHP_VERSION_ID >= 80100
    php_curlm_handlers handlers;
#else
    php_curlm_handlers *handlers;
#endif
    struct {
        int no;
    } err;
#if PHP_VERSION_ID < 80000
    bool in_coroutine;
#else
    zend_object std;
#endif
} php_curlm;

typedef struct _php_curlsh {
    CURLSH *share;
    struct {
        int no;
    } err;
    zend_object std;
} php_curlsh;

php_curl *swoole_curl_init_handle_into_zval(zval *curl);
void swoole_curl_init_handle(php_curl *ch);
void swoole_curl_cleanup_handle(php_curl *);
void swoole_curl_multi_cleanup_list(void *data);
void swoole_curl_verify_handlers(php_curl *ch, int reporterror);
void swoole_setup_easy_copy_handlers(php_curl *ch, php_curl *source);

#if PHP_VERSION_ID >= 80100
static inline php_curl_handlers *curl_handlers(php_curl *ch) {
    return &ch->handlers;
}
#else
static inline php_curl_handlers *curl_handlers(php_curl *ch) {
    return ch->handlers;
}
#endif

#if PHP_VERSION_ID >= 80200
typedef zend_result curl_result_t;
#else
typedef int curl_result_t;
#endif

#if PHP_VERSION_ID >= 80000
static inline php_curl *curl_from_obj(zend_object *obj) {
    return (php_curl *) ((char *) (obj) -XtOffsetOf(php_curl, std));
}

#define Z_CURL_P(zv) curl_from_obj(Z_OBJ_P(zv))

static inline php_curlsh *curl_share_from_obj(zend_object *obj) {
    return (php_curlsh *) ((char *) (obj) -XtOffsetOf(php_curlsh, std));
}

#define Z_CURL_SHARE_P(zv) curl_share_from_obj(Z_OBJ_P(zv))
void curl_multi_register_class(const zend_function_entry *method_entries);
curl_result_t swoole_curl_cast_object(zend_object *obj, zval *result, int type);
#else
#define Z_CURL_P(zv) swoole_curl_get_handle(zv)
#endif /* PHP8 end */

php_curl *swoole_curl_get_handle(zval *zid, bool exclusive = true, bool required = true);

SW_EXTERN_C_BEGIN
#if PHP_VERSION_ID < 80000
void swoole_curl_close_ex(php_curl *ch);
void swoole_curl_close(zend_resource *rsrc);
void swoole_curl_multi_close(zend_resource *rsrc);
php_curl *swoole_curl_alloc_handle();
int swoole_curl_get_le_curl();
int swoole_curl_get_le_curl_multi();
#endif
SW_EXTERN_C_END

#endif /* _PHP_CURL_PRIVATE_H */
#endif
