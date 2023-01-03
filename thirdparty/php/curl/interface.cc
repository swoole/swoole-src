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
   |         Tianfeng Han  <rango@swoole.com>                             |
   +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
#include "php_swoole_curl.h"

using namespace swoole;

SW_EXTERN_C_BEGIN
#include "curl_interface.h"
#include "curl_arginfo.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <curl/easy.h>

/* As of curl 7.11.1 this is no longer defined inside curl.h */
#ifndef HttpPost
#define HttpPost curl_httppost
#endif

#ifndef RETVAL_COPY
#define RETVAL_COPY(zv) ZVAL_COPY(return_value, zv)
#endif

#ifndef RETURN_COPY
#define RETURN_COPY(zv)                                                                                                \
    do {                                                                                                               \
        RETVAL_COPY(zv);                                                                                               \
        return;                                                                                                        \
    } while (0)
#endif

/* {{{ cruft for thread safe SSL crypto locks */
#if defined(ZTS) && defined(HAVE_CURL_SSL)
#ifdef PHP_WIN32
#define PHP_CURL_NEED_OPENSSL_TSL
#include <openssl/crypto.h>
#else /* !PHP_WIN32 */
#if defined(HAVE_CURL_OPENSSL)
#if defined(HAVE_OPENSSL_CRYPTO_H)
#define PHP_CURL_NEED_OPENSSL_TSL
#include <openssl/crypto.h>
#else
#warning "libcurl was compiled with OpenSSL support, but configure could not find " \
    "openssl/crypto.h; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#endif
#elif defined(HAVE_CURL_GNUTLS)
#if defined(HAVE_GCRYPT_H)
#define PHP_CURL_NEED_GNUTLS_TSL
#include <gcrypt.h>
#else
#warning "libcurl was compiled with GnuTLS support, but configure could not find " \
    "gcrypt.h; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#endif
#else
#warning "libcurl was compiled with SSL support, but configure could not determine which" \
    "library was used; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#endif /* HAVE_CURL_OPENSSL || HAVE_CURL_GNUTLS */
#endif /* PHP_WIN32 */
#endif /* ZTS && HAVE_CURL_SSL */
/* }}} */

#define SMART_STR_PREALLOC 4096

#include "zend_smart_str.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "ext/standard/url.h"
#include "curl_private.h"

static zend_class_entry *swoole_native_curl_exception_ce;
static zend_object_handlers swoole_native_curl_exception_handlers;

#if PHP_VERSION_ID < 80000
static int le_curl;
static int le_curl_multi_handle;
static int le_curl_share_handle;
#define le_curl_share_handle_name "cURL Share Handle"

int swoole_curl_get_le_curl() {
    return le_curl;
}

int swoole_curl_get_le_curl_multi() {
    return le_curl_multi_handle;
}

int swoole_curl_get_le_curl_share() {
    return le_curl_share_handle;
}

#endif

#define CAAL(s, v) add_assoc_long_ex(return_value, s, sizeof(s) - 1, (zend_long) v);
#define CAAD(s, v) add_assoc_double_ex(return_value, s, sizeof(s) - 1, (double) v);
#define CAAS(s, v) add_assoc_string_ex(return_value, s, sizeof(s) - 1, (char *) (v ? v : ""));
#define CAASTR(s, v) add_assoc_str_ex(return_value, s, sizeof(s) - 1, v ? zend_string_copy(v) : ZSTR_EMPTY_ALLOC());
#define CAAZ(s, v) add_assoc_zval_ex(return_value, s, sizeof(s) - 1, (zval *) v);

#if defined(PHP_WIN32) || defined(__GNUC__)
#define php_curl_ret(__ret)                                                                                            \
    RETVAL_FALSE;                                                                                                      \
    return __ret;
#else
#define php_curl_ret(__ret)                                                                                            \
    RETVAL_FALSE;                                                                                                      \
    return;
#endif

void swoole_curl_set_private_data(php_curl *ch, zval *zvalue) {
#if PHP_VERSION_ID >= 80100 || PHP_VERSION_ID < 80000
    zval_ptr_dtor(&ch->private_data);
    ZVAL_COPY(&ch->private_data, zvalue);
#else
    zend_update_property_ex(nullptr, &ch->std, SW_ZSTR_KNOWN(SW_ZEND_STR_PRIVATE_DATA), zvalue);
#endif
}

void swoole_curl_get_private_data(php_curl *ch, zval *return_value) {
#if PHP_VERSION_ID >= 80100 || PHP_VERSION_ID < 80000
    if (!Z_ISUNDEF(ch->private_data)) {
        RETURN_COPY(&ch->private_data);
    } else {
        RETURN_FALSE;
    }
#else
    zval rv;
    zval *zv = zend_read_property_ex(nullptr, &ch->std, SW_ZSTR_KNOWN(SW_ZEND_STR_PRIVATE_DATA), 1, &rv);
    RETURN_COPY(zv);
#endif
}

php_curl *swoole_curl_get_handle(zval *zid, bool exclusive, bool required) {
    php_curl *ch;
#if PHP_VERSION_ID >= 80000
    ch = Z_CURL_P(zid);
#else
    if ((ch = (php_curl *) zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        if (required) {
            swoole_fatal_error(SW_ERROR_INVALID_PARAMS, "supplied resource is not a valid " le_curl_name " resource");
        }
        return nullptr;
    }
#endif
    if (SWOOLE_G(req_status) == PHP_SWOOLE_RSHUTDOWN_END) {
        exclusive = false;
    }
    if (exclusive) {
        auto handle = swoole::curl::get_handle(ch->cp);
        if (handle && handle->multi && handle->multi->check_bound_co() == nullptr) {
            return nullptr;
        }
    }
    return ch;
}

static int php_curl_option_str(php_curl *ch, zend_long option, const char *str, const size_t len) {
    if (strlen(str) != len) {
#if PHP_VERSION_ID >= 80000
        zend_value_error("%s(): cURL option must not contain any null bytes", get_active_function_name());
#else
        php_error_docref(NULL, E_WARNING, "Curl option contains invalid characters (\\0)");
#endif
        return FAILURE;
    }

    CURLcode error = curl_easy_setopt(ch->cp, (CURLoption) option, str);
    SAVE_CURL_ERROR(ch, error);

    return error == CURLE_OK ? SUCCESS : FAILURE;
}

static int php_curl_option_url(php_curl *ch, const char *url, const size_t len) /* {{{ */
{
    /* Disable file:// if open_basedir are used */
    if (PG(open_basedir) && *PG(open_basedir)) {
#if LIBCURL_VERSION_NUM >= 0x071304
        curl_easy_setopt(ch->cp, CURLOPT_PROTOCOLS, CURLPROTO_ALL & ~CURLPROTO_FILE);
#else
        php_url *uri;

        if (!(uri = php_url_parse_ex(url, len))) {
            php_error_docref(NULL, E_WARNING, "Invalid URL '%s'", url);
            return FAILURE;
        }

        if (uri->scheme && zend_string_equals_literal_ci(uri->scheme, "file")) {
            php_error_docref(NULL, E_WARNING, "Protocol 'file' disabled in cURL");
            php_url_free(uri);
            return FAILURE;
        }
        php_url_free(uri);
#endif
    }

    return php_curl_option_str(ch, CURLOPT_URL, url, len);
}
/* }}} */

void swoole_curl_verify_handlers(php_curl *ch, int reporterror) /* {{{ */
{
    php_stream *stream;

    ZEND_ASSERT(ch && curl_handlers(ch));

    if (!Z_ISUNDEF(curl_handlers(ch)->std_err)) {
        stream = (php_stream *) zend_fetch_resource2_ex(
            &curl_handlers(ch)->std_err, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_STDERR resource has gone away, resetting to stderr");
            }
            zval_ptr_dtor(&curl_handlers(ch)->std_err);
            ZVAL_UNDEF(&curl_handlers(ch)->std_err);

            curl_easy_setopt(ch->cp, CURLOPT_STDERR, stderr);
        }
    }
    if (curl_handlers(ch)->read && !Z_ISUNDEF(curl_handlers(ch)->read->stream)) {
        stream = (php_stream *) zend_fetch_resource2_ex(
            &curl_handlers(ch)->read->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_INFILE resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&curl_handlers(ch)->read->stream);
            ZVAL_UNDEF(&curl_handlers(ch)->read->stream);
            curl_handlers(ch)->read->res = NULL;
            curl_handlers(ch)->read->fp = 0;

            curl_easy_setopt(ch->cp, CURLOPT_INFILE, (void *) ch);
        }
    }
    if (curl_handlers(ch)->write_header && !Z_ISUNDEF(curl_handlers(ch)->write_header->stream)) {
        stream = (php_stream *) zend_fetch_resource2_ex(
            &curl_handlers(ch)->write_header->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_WRITEHEADER resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&curl_handlers(ch)->write_header->stream);
            ZVAL_UNDEF(&curl_handlers(ch)->write_header->stream);
            curl_handlers(ch)->write_header->fp = 0;

            curl_handlers(ch)->write_header->method = PHP_CURL_IGNORE;
            curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER, (void *) ch);
        }
    }
    if (curl_handlers(ch)->write && !Z_ISUNDEF(curl_handlers(ch)->write->stream)) {
        stream = (php_stream *) zend_fetch_resource2_ex(
            &curl_handlers(ch)->write->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_FILE resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&curl_handlers(ch)->write->stream);
            ZVAL_UNDEF(&curl_handlers(ch)->write->stream);
            curl_handlers(ch)->write->fp = 0;

            curl_handlers(ch)->write->method = PHP_CURL_STDOUT;
            curl_easy_setopt(ch->cp, CURLOPT_FILE, (void *) ch);
        }
    }
    return;
}
/* }}} */

/* CurlHandle class */
static const zend_function_entry swoole_coroutine_curl_handle_methods[] = {ZEND_FE_END};

#if PHP_VERSION_ID >= 80000
zend_class_entry *swoole_coroutine_curl_handle_ce;
static zend_object_handlers swoole_coroutine_curl_handle_handlers;

static zend_object *swoole_curl_create_object(zend_class_entry *class_type);
static void swoole_curl_free_obj(zend_object *object);
static zend_function *swoole_curl_get_constructor(zend_object *object);
static zend_object *swoole_curl_clone_obj(zend_object *object);
static HashTable *swoole_curl_get_gc(zend_object *object, zval **table, int *n);
#endif

static inline int build_mime_structure_from_hash(php_curl *ch, zval *zpostfields);

SW_EXTERN_C_END

void swoole_native_curl_minit(int module_number) {
    if (!SWOOLE_G(cli)) {
        return;
    }
#if PHP_VERSION_ID >= 80000
    swoole_coroutine_curl_handle_ce = curl_ce;
    swoole_coroutine_curl_handle_ce->create_object = swoole_curl_create_object;
    memcpy(&swoole_coroutine_curl_handle_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    swoole_coroutine_curl_handle_handlers.offset = XtOffsetOf(php_curl, std);
    swoole_coroutine_curl_handle_handlers.free_obj = swoole_curl_free_obj;
    swoole_coroutine_curl_handle_handlers.get_gc = swoole_curl_get_gc;
    swoole_coroutine_curl_handle_handlers.get_constructor = swoole_curl_get_constructor;
    swoole_coroutine_curl_handle_handlers.clone_obj = swoole_curl_clone_obj;
    swoole_coroutine_curl_handle_handlers.cast_object = swoole_curl_cast_object;
    swoole_coroutine_curl_handle_handlers.compare = [](zval *o1, zval *o2) { return ZEND_UNCOMPARABLE; };

    swoole_coroutine_curl_handle_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    zend_declare_property_bool(swoole_coroutine_curl_handle_ce, ZEND_STRL("in_coroutine"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_coroutine_curl_handle_ce, ZEND_STRL("private_data"), ZEND_ACC_PUBLIC);

    curl_multi_register_class(nullptr);

    zend_unregister_functions(swoole_native_curl_functions, -1, CG(function_table));
    zend_register_functions(NULL, swoole_native_curl_functions, NULL, MODULE_PERSISTENT);

#else
    le_curl = zend_register_list_destructors_ex(swoole_curl_close, NULL, le_curl_name, module_number);
    le_curl_multi_handle =
        zend_register_list_destructors_ex(swoole_curl_multi_close, NULL, le_curl_multi_handle_name, module_number);
#endif

    SW_INIT_CLASS_ENTRY_EX(swoole_native_curl_exception,
                           "Swoole\\Coroutine\\Curl\\Exception",
                           nullptr,
                           "Co\\Coroutine\\Curl\\Exception",
                           nullptr,
                           swoole_exception);
}

void swoole_native_curl_rinit() {
#if PHP_VERSION_ID < 80000
    if (!SWOOLE_G(cli)) {
        return;
    }
    le_curl_share_handle = zend_fetch_list_dtor_id("curl_share");
#endif
}

/* CurlHandle class */

#if PHP_VERSION_ID >= 80000
static zend_object *swoole_curl_create_object(zend_class_entry *class_type) {
    php_curl *intern = (php_curl *) zend_object_alloc(sizeof(php_curl), class_type);

    zend_object_std_init(&intern->std, class_type);
    object_properties_init(&intern->std, class_type);
    intern->std.handlers = &swoole_coroutine_curl_handle_handlers;

    return &intern->std;
}

static zend_function *swoole_curl_get_constructor(zend_object *object) {
    zend_throw_error(NULL, "Cannot directly construct CurlHandle, use curl_init() instead");
    return NULL;
}

static zend_object *swoole_curl_clone_obj(zend_object *object) {
    php_curl *ch = curl_from_obj(object);
    CURL *cp = curl_easy_duphandle(ch->cp);
    if (!cp) {
        zend_throw_exception(NULL, "Failed to clone CurlHandle", 0);
        return nullptr;
    }

    zend_object *clone_object = swoole_curl_create_object(curl_ce);
    php_curl *clone_ch = curl_from_obj(clone_object);
    swoole_curl_init_handle(clone_ch);

    clone_ch->cp = cp;
    swoole_setup_easy_copy_handlers(clone_ch, ch);
    swoole::curl::create_handle(clone_ch->cp);

    zval *postfields = &ch->postfields;
    if (Z_TYPE_P(postfields) != IS_UNDEF) {
        if (build_mime_structure_from_hash(clone_ch, postfields) != SUCCESS) {
            zend_throw_exception(NULL, "Failed to clone CurlHandle", 0);
            return &clone_ch->std;
        }
    }

    return &clone_ch->std;
}

static HashTable *swoole_curl_get_gc(zend_object *object, zval **table, int *n) {
    php_curl *curl = curl_from_obj(object);

    zend_get_gc_buffer *gc_buffer = zend_get_gc_buffer_create();

    zend_get_gc_buffer_add_zval(gc_buffer, &curl->postfields);
    if (curl_handlers(curl)) {
        if (curl_handlers(curl)->read) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->read->func_name);
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->read->stream);
        }

        if (curl_handlers(curl)->write) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->write->func_name);
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->write->stream);
        }

        if (curl_handlers(curl)->write_header) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->write_header->func_name);
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->write_header->stream);
        }

        if (curl_handlers(curl)->progress) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->progress->func_name);
        }

#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
        if (curl_handlers(curl)->xferinfo) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->xferinfo->func_name);
        }
#endif

#if LIBCURL_VERSION_NUM >= 0x071500
        if (curl_handlers(curl)->fnmatch) {
            zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->fnmatch->func_name);
        }
#endif

        zend_get_gc_buffer_add_zval(gc_buffer, &curl_handlers(curl)->std_err);
    }

    zend_get_gc_buffer_use(gc_buffer, table, n);

    return zend_std_get_properties(object);
}

curl_result_t swoole_curl_cast_object(zend_object *obj, zval *result, int type) {
    if (type == IS_LONG) {
        /* For better backward compatibility, make (int) $curl_handle return the object ID,
         * similar to how it previously returned the resource ID. */
        ZVAL_LONG(result, obj->handle);
        return SUCCESS;
    }

    return zend_std_cast_object_tostring(obj, result, type);
}

#endif

void swoole_native_curl_mshutdown() {}

/* {{{ curl_write_nothing
 * Used as a work around. See _php_curl_close_ex
 */
static size_t fn_write_nothing(char *data, size_t size, size_t nmemb, void *ctx) {
    return size * nmemb;
}
/* }}} */

/* {{{ curl_write_nothing
 * Used as a work around. See _php_curl_close_ex
 */
static size_t curl_write_nothing(char *data, size_t size, size_t nmemb, void *ctx) {
    return size * nmemb;
}
/* }}} */

/* {{{ curl_write
 */
static size_t fn_write(char *data, size_t size, size_t nmemb, void *ctx) {
    php_curl *ch = (php_curl *) ctx;
    php_curl_write *t = curl_handlers(ch)->write;
    size_t length = size * nmemb;

#if PHP_CURL_DEBUG
    fprintf(stderr, "curl_write() called\n");
    fprintf(stderr, "data = %s, size = %d, nmemb = %d, ctx = %x\n", data, size, nmemb, ctx);
#endif

    switch (t->method) {
    case PHP_CURL_STDOUT:
        PHPWRITE(data, length);
        break;
    case PHP_CURL_FILE:
        return fwrite(data, size, nmemb, t->fp);
    case PHP_CURL_RETURN:
        if (length > 0) {
            smart_str_appendl(&t->buf, data, (int) length);
        }
        break;
    case PHP_CURL_USER: {
        zval argv[2];
        zval retval;
        int error;
        zend_fcall_info fci;

#if PHP_VERSION_ID >= 80000
        GC_ADDREF(&ch->std);
        ZVAL_OBJ(&argv[0], &ch->std);
#else
        GC_ADDREF(ch->res);
        ZVAL_RES(&argv[0], ch->res);
#endif
        ZVAL_STRINGL(&argv[1], data, length);

        fci.size = sizeof(fci);
        fci.object = NULL;
        ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
        fci.retval = &retval;
        fci.param_count = 2;
        fci.params = argv;
#if PHP_VERSION_ID >= 80000
        fci.named_params = NULL;
#else
        fci.no_separation = 0;
#endif
        ch->in_callback = 1;
        error = zend_call_function(&fci, &t->fci_cache);
        ch->in_callback = 0;
        if (error == FAILURE) {
            php_error_docref(NULL, E_WARNING, "Could not call the CURLOPT_WRITEFUNCTION");
            length = -1;
        } else if (!Z_ISUNDEF(retval)) {
            swoole_curl_verify_handlers(ch, 1);
            length = zval_get_long(&retval);
        }

        zval_ptr_dtor(&argv[0]);
        zval_ptr_dtor(&argv[1]);
        break;
    }
    }

    return length;
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
/* {{{ curl_fnmatch
 */
static int fn_fnmatch(void *ctx, const char *pattern, const char *string) {
    php_curl *ch = (php_curl *) ctx;
    php_curl_fnmatch *t = curl_handlers(ch)->fnmatch;
    int rval = CURL_FNMATCHFUNC_FAIL;
    switch (t->method) {
    case PHP_CURL_USER: {
        zval argv[3];
        zval retval;
        int error;
        zend_fcall_info fci;

#if PHP_VERSION_ID >= 80000
        GC_ADDREF(&ch->std);
        ZVAL_OBJ(&argv[0], &ch->std);
#else
        GC_ADDREF(ch->res);
        ZVAL_RES(&argv[0], ch->res);
#endif
        ZVAL_STRING(&argv[1], pattern);
        ZVAL_STRING(&argv[2], string);

        fci.size = sizeof(fci);
        ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
        fci.object = NULL;
        fci.retval = &retval;
        fci.param_count = 3;
        fci.params = argv;
#if PHP_VERSION_ID >= 80000
        fci.named_params = NULL;
#else
        fci.no_separation = 0;
#endif

        ch->in_callback = 1;
        error = zend_call_function(&fci, &t->fci_cache);
        ch->in_callback = 0;
        if (error == FAILURE) {
            php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_FNMATCH_FUNCTION");
        } else if (!Z_ISUNDEF(retval)) {
            swoole_curl_verify_handlers(ch, 1);
            rval = zval_get_long(&retval);
        }
        zval_ptr_dtor(&argv[0]);
        zval_ptr_dtor(&argv[1]);
        zval_ptr_dtor(&argv[2]);
        break;
    }
    }
    return rval;
}
/* }}} */
#endif

/* {{{ curl_progress
 */
static size_t fn_progress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow) {
    php_curl *ch = (php_curl *) clientp;
    php_curl_progress *t = curl_handlers(ch)->progress;
    size_t rval = 0;

#if PHP_CURL_DEBUG
    fprintf(stderr, "curl_progress() called\n");
    fprintf(stderr,
            "clientp = %x, dltotal = %f, dlnow = %f, ultotal = %f, ulnow = %f\n",
            clientp,
            dltotal,
            dlnow,
            ultotal,
            ulnow);
#endif

    switch (t->method) {
    case PHP_CURL_USER: {
        zval argv[5];
        zval retval;
        int error;
        zend_fcall_info fci;

#if PHP_VERSION_ID >= 80000
        GC_ADDREF(&ch->std);
        ZVAL_OBJ(&argv[0], &ch->std);
#else
        GC_ADDREF(ch->res);
        ZVAL_RES(&argv[0], ch->res);
#endif
        ZVAL_LONG(&argv[1], (zend_long) dltotal);
        ZVAL_LONG(&argv[2], (zend_long) dlnow);
        ZVAL_LONG(&argv[3], (zend_long) ultotal);
        ZVAL_LONG(&argv[4], (zend_long) ulnow);

        fci.size = sizeof(fci);
        ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
        fci.object = NULL;
        fci.retval = &retval;
        fci.param_count = 5;
        fci.params = argv;
#if PHP_VERSION_ID >= 80000
        fci.named_params = NULL;
#else
        fci.no_separation = 0;
#endif

        ch->in_callback = 1;
        error = zend_call_function(&fci, &t->fci_cache);
        ch->in_callback = 0;
        if (error == FAILURE) {
            php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_PROGRESSFUNCTION");
        } else if (!Z_ISUNDEF(retval)) {
            swoole_curl_verify_handlers(ch, 1);
            if (0 != zval_get_long(&retval)) {
                rval = 1;
            }
        }
        zval_ptr_dtor(&argv[0]);
    }
    }
    return rval;
}
/* }}} */

/* {{{ curl_read
 */
static size_t fn_read(char *data, size_t size, size_t nmemb, void *ctx) {
    php_curl *ch = (php_curl *) ctx;
    php_curl_read *t = curl_handlers(ch)->read;
    int length = 0;

    switch (t->method) {
    case PHP_CURL_DIRECT:
        if (t->fp) {
            length = fread(data, size, nmemb, t->fp);
        }
        break;
    case PHP_CURL_USER: {
        zval argv[3];
        zval retval;
        int error;
        zend_fcall_info fci;

#if PHP_VERSION_ID >= 80000
        GC_ADDREF(&ch->std);
        ZVAL_OBJ(&argv[0], &ch->std);
#else
        GC_ADDREF(ch->res);
        ZVAL_RES(&argv[0], ch->res);
#endif
        if (t->res) {
            GC_ADDREF(t->res);
            ZVAL_RES(&argv[1], t->res);
        } else {
            ZVAL_NULL(&argv[1]);
        }
        ZVAL_LONG(&argv[2], (int) size * nmemb);

        fci.size = sizeof(fci);
        ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
        fci.object = NULL;
        fci.retval = &retval;
        fci.param_count = 3;
        fci.params = argv;
#if PHP_VERSION_ID >= 80000
        fci.named_params = NULL;
#else
        fci.no_separation = 0;
#endif
        ch->in_callback = 1;
        error = zend_call_function(&fci, &t->fci_cache);
        ch->in_callback = 0;
        if (error == FAILURE) {
            php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_READFUNCTION");
            length = CURL_READFUNC_ABORT;
        } else if (!Z_ISUNDEF(retval)) {
            swoole_curl_verify_handlers(ch, 1);
            if (Z_TYPE(retval) == IS_STRING) {
                length = MIN((int) (size * nmemb), Z_STRLEN(retval));
                memcpy(data, Z_STRVAL(retval), length);
            }
            zval_ptr_dtor(&retval);
        }

        zval_ptr_dtor(&argv[0]);
        zval_ptr_dtor(&argv[1]);
        break;
    }
    default:
        break;
    }

    return length;
}
/* }}} */

/* {{{ curl_write_header
 */
static size_t fn_write_header(char *data, size_t size, size_t nmemb, void *ctx) {
    php_curl *ch = (php_curl *) ctx;
    php_curl_write *t = curl_handlers(ch)->write_header;
    size_t length = size * nmemb;

    switch (t->method) {
    case PHP_CURL_STDOUT:
        // Handle special case write when we're returning the entire transfer
        if (curl_handlers(ch)->write->method == PHP_CURL_RETURN && length > 0) {
            smart_str_appendl(&curl_handlers(ch)->write->buf, data, (int) length);
        } else {
            PHPWRITE(data, length);
        }
        break;
    case PHP_CURL_FILE:
        return fwrite(data, size, nmemb, t->fp);
    case PHP_CURL_USER: {
        zval argv[2];
        zval retval;
        int error;
        zend_fcall_info fci;

#if PHP_VERSION_ID >= 80000
        GC_ADDREF(&ch->std);
        ZVAL_OBJ(&argv[0], &ch->std);
#else
        ZVAL_RES(&argv[0], ch->res);
        Z_ADDREF(argv[0]);
#endif

        ZVAL_STRINGL(&argv[1], data, length);

        fci.size = sizeof(fci);
        ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
        fci.object = NULL;
        fci.retval = &retval;
        fci.param_count = 2;
        fci.params = argv;
#if PHP_VERSION_ID >= 80000
        fci.named_params = NULL;
#else
        fci.no_separation = 0;
#endif
        ch->in_callback = 1;
        error = zend_call_function(&fci, &t->fci_cache);
        ch->in_callback = 0;
        if (error == FAILURE) {
            php_error_docref(NULL, E_WARNING, "Could not call the CURLOPT_HEADERFUNCTION");
            length = -1;
        } else if (!Z_ISUNDEF(retval)) {
            swoole_curl_verify_handlers(ch, 1);
            length = zval_get_long(&retval);
        }
        zval_ptr_dtor(&argv[0]);
        zval_ptr_dtor(&argv[1]);
        break;
    }

    case PHP_CURL_IGNORE:
        return length;

    default:
        return -1;
    }

    return length;
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
/* {{{ curl_xferinfo */
static size_t fn_xferinfo(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    php_curl *ch = (php_curl *) clientp;
    php_curl_fnxferinfo *t = curl_handlers(ch)->xferinfo;
    size_t rval = 0;

#if PHP_CURL_DEBUG
    fprintf(stderr, "curl_xferinfo() called\n");
    fprintf(stderr,
            "clientp = %x, dltotal = %ld, dlnow = %ld, ultotal = %ld, ulnow = %ld\n",
            clientp,
            dltotal,
            dlnow,
            ultotal,
            ulnow);
#endif

    zval argv[5];
    zval retval;
    zend_result error;
    zend_fcall_info fci;

    GC_ADDREF(&ch->std);
    ZVAL_OBJ(&argv[0], &ch->std);
    ZVAL_LONG(&argv[1], dltotal);
    ZVAL_LONG(&argv[2], dlnow);
    ZVAL_LONG(&argv[3], ultotal);
    ZVAL_LONG(&argv[4], ulnow);

    fci.size = sizeof(fci);
    ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
    fci.object = NULL;
    fci.retval = &retval;
    fci.param_count = 5;
    fci.params = argv;
    fci.named_params = NULL;

    ch->in_callback = 1;
    error = zend_call_function(&fci, &t->fci_cache);
    ch->in_callback = 0;
    if (error == FAILURE) {
        php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_XFERINFOFUNCTION");
    } else if (!Z_ISUNDEF(retval)) {
        swoole_curl_verify_handlers(ch, 1);
        if (0 != zval_get_long(&retval)) {
            rval = 1;
        }
    }
    zval_ptr_dtor(&argv[0]);
    return rval;
}
/* }}} */
#endif

static int curl_debug(CURL *cp, curl_infotype type, char *buf, size_t buf_len, void *ctx) /* {{{ */
{
    php_curl *ch = (php_curl *) ctx;

    if (type == CURLINFO_HEADER_OUT) {
        if (ch->header.str) {
            zend_string_release(ch->header.str);
        }
        if (buf_len > 0) {
            ch->header.str = zend_string_init(buf, buf_len, 0);
        }
    }

    return 0;
}
/* }}} */

/* {{{ curl_free_string
 */
static void curl_free_string(void **string) {
    efree((char *) *string);
}
/* }}} */

/* {{{ curl_free_post
 */
static void curl_free_post(void **post) {
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    curl_mime_free((curl_mime *) *post);
#else
    curl_formfree((struct HttpPost *) *post);
#endif
}
/* }}} */

struct mime_data_cb_arg {
    zend_string *filename;
    php_stream *stream;
};

/* {{{ curl_free_cb_arg
 */
static void curl_free_cb_arg(void **cb_arg_p) {
    struct mime_data_cb_arg *cb_arg = (struct mime_data_cb_arg *) *cb_arg_p;

    ZEND_ASSERT(cb_arg->stream == NULL);
    zend_string_release(cb_arg->filename);
    efree(cb_arg);
}
/* }}} */

/* {{{ curl_free_slist
 */
static void curl_free_slist(zval *el) {
    curl_slist_free_all(((struct curl_slist *) Z_PTR_P(el)));
}
/* }}} */

#if PHP_VERSION_ID >= 80000
php_curl *swoole_curl_init_handle_into_zval(zval *curl) {
    php_curl *ch;

    object_init_ex(curl, swoole_coroutine_curl_handle_ce);
    ch = Z_CURL_P(curl);

    swoole_curl_init_handle(ch);

    return ch;
}
#endif

/* {{{ alloc_curl_handle
 */
#if PHP_VERSION_ID >= 80000
void swoole_curl_init_handle(php_curl *ch)
#else
php_curl *swoole_curl_alloc_handle()
#endif
{
#if PHP_VERSION_ID < 80000
    php_curl *ch = (php_curl *) ecalloc(1, sizeof(php_curl));
#endif

    ch->to_free = (struct _php_curl_free *) ecalloc(1, sizeof(struct _php_curl_free));
#if PHP_VERSION_ID < 80100
    ch->handlers = (php_curl_handlers *) ecalloc(1, sizeof(php_curl_handlers));
#endif
    curl_handlers(ch)->write = (php_curl_write *) ecalloc(1, sizeof(php_curl_write));
    curl_handlers(ch)->write_header = (php_curl_write *) ecalloc(1, sizeof(php_curl_write));
    curl_handlers(ch)->read = (php_curl_read *) ecalloc(1, sizeof(php_curl_read));
    curl_handlers(ch)->progress = NULL;
    curl_handlers(ch)->fnmatch = NULL;
#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
    curl_handlers(ch)->xferinfo = NULL;
#endif
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    curl_handlers(ch)->fnmatch = NULL;
#endif
    ch->clone = (uint32_t *) emalloc(sizeof(uint32_t));
    *ch->clone = 1;

    memset(&ch->err, 0, sizeof(struct _php_curl_error));

#if PHP_VERSION_ID < 80100
    zend_llist_init(&ch->to_free->str, sizeof(char *), (llist_dtor_func_t) curl_free_string, 0);
#else
#if LIBCURL_VERSION_NUM < 0x073800 /* 7.56.0 */
    zend_llist_init(&ch->to_free->buffers, sizeof(char *), (llist_dtor_func_t) curl_free_string, 0);
#endif
#endif
    zend_llist_init(&ch->to_free->post, sizeof(struct HttpPost *), (llist_dtor_func_t) curl_free_post, 0);
    zend_llist_init(&ch->to_free->stream, sizeof(struct mime_data_cb_arg *), (llist_dtor_func_t) curl_free_cb_arg, 0);

    ch->to_free->slist = (HashTable *) emalloc(sizeof(HashTable));
    zend_hash_init(ch->to_free->slist, 4, NULL, curl_free_slist, 0);
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    ZVAL_UNDEF(&ch->postfields);
#endif

#if PHP_VERSION_ID < 80000
    return ch;
#endif
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
/* {{{ create_certinfo
 */
static void create_certinfo(struct curl_certinfo *ci, zval *listcode) {
    int i;

    if (ci) {
        zval certhash;

        for (i = 0; i < ci->num_of_certs; i++) {
            struct curl_slist *slist;

            array_init(&certhash);
            for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                int len;
                char s[64];
                char *tmp;
                strncpy(s, slist->data, sizeof(s));
                s[sizeof(s) - 1] = '\0';
                tmp = (char *) memchr(s, ':', sizeof(s));
                if (tmp) {
                    *tmp = '\0';
                    len = strlen(s);
                    add_assoc_string(&certhash, s, &slist->data[len + 1]);
                } else {
                    php_error_docref(NULL, E_WARNING, "Could not extract hash key from certificate info");
                }
            }
            add_next_index_zval(listcode, &certhash);
        }
    }
}
/* }}} */
#endif

/* {{{ _php_curl_set_default_options()
   Set default options for a handle */
static void _php_curl_set_default_options(php_curl *ch) {
    const char *cainfo;

    curl_easy_setopt(ch->cp, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(ch->cp, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(ch->cp, CURLOPT_ERRORBUFFER, ch->err.str);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEFUNCTION, fn_write);
    curl_easy_setopt(ch->cp, CURLOPT_FILE, (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_READFUNCTION, fn_read);
    curl_easy_setopt(ch->cp, CURLOPT_INFILE, (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_HEADERFUNCTION, fn_write_header);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER, (void *) ch);
#ifndef ZTS
    curl_easy_setopt(ch->cp, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);
#endif
    curl_easy_setopt(ch->cp, CURLOPT_DNS_CACHE_TIMEOUT, 120);
    curl_easy_setopt(ch->cp, CURLOPT_MAXREDIRS, 20); /* prevent infinite redirects */

    cainfo = INI_STR("openssl.cafile");
    if (!(cainfo && cainfo[0] != '\0')) {
        cainfo = INI_STR("curl.cainfo");
    }
    if (cainfo && cainfo[0] != '\0') {
        curl_easy_setopt(ch->cp, CURLOPT_CAINFO, cainfo);
    }
    curl_easy_setopt(ch->cp, CURLOPT_NOSIGNAL, 1);
}
/* }}} */

/* {{{ proto resource curl_init([string url])
   Initialize a cURL session */
PHP_FUNCTION(swoole_native_curl_init) {
    php_curl *ch;
    CURL *cp;
    zend_string *url = NULL;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
#if PHP_VERSION_ID >= 80000
    Z_PARAM_STR_OR_NULL(url)
#else
    Z_PARAM_STR(url)
#endif
    ZEND_PARSE_PARAMETERS_END();

    cp = curl_easy_init();
    if (!cp) {
        php_error_docref(NULL, E_WARNING, "Could not initialize a new cURL handle");
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 80000
    ch = swoole_curl_init_handle_into_zval(return_value);
#else
    ch = swoole_curl_alloc_handle();
#endif

    ch->cp = cp;

    curl_handlers(ch)->write->method = PHP_CURL_STDOUT;
    curl_handlers(ch)->read->method = PHP_CURL_DIRECT;
    curl_handlers(ch)->write_header->method = PHP_CURL_IGNORE;

    _php_curl_set_default_options(ch);
    swoole::curl::create_handle(cp);

    if (url) {
        if (php_curl_option_url(ch, ZSTR_VAL(url), ZSTR_LEN(url)) == FAILURE) {
#if PHP_VERSION_ID >= 80000
            zval_ptr_dtor(return_value);
#else
            swoole_curl_close_ex(ch);
#endif
            RETURN_FALSE;
        }
    }

#if PHP_VERSION_ID < 80000
    ZVAL_RES(return_value, zend_register_resource(ch, le_curl));
    ch->res = Z_RES_P(return_value);
#endif
}
/* }}} */

void swoole_setup_easy_copy_handlers(php_curl *ch, php_curl *source) {
    if (!Z_ISUNDEF(curl_handlers(source)->write->stream)) {
        Z_ADDREF(curl_handlers(source)->write->stream);
    }
    curl_handlers(ch)->write->stream = curl_handlers(source)->write->stream;
    curl_handlers(ch)->write->method = curl_handlers(source)->write->method;
    if (!Z_ISUNDEF(curl_handlers(source)->read->stream)) {
        Z_ADDREF(curl_handlers(source)->read->stream);
    }
    curl_handlers(ch)->read->stream = curl_handlers(source)->read->stream;
    curl_handlers(ch)->read->method = curl_handlers(source)->read->method;
    curl_handlers(ch)->write_header->method = curl_handlers(source)->write_header->method;
    if (!Z_ISUNDEF(curl_handlers(source)->write_header->stream)) {
        Z_ADDREF(curl_handlers(source)->write_header->stream);
    }
    curl_handlers(ch)->write_header->stream = curl_handlers(source)->write_header->stream;

    curl_handlers(ch)->write->fp = curl_handlers(source)->write->fp;
    curl_handlers(ch)->write_header->fp = curl_handlers(source)->write_header->fp;
    curl_handlers(ch)->read->fp = curl_handlers(source)->read->fp;
    curl_handlers(ch)->read->res = curl_handlers(source)->read->res;
#if PHP_VERSION_ID < 80000
#if CURLOPT_PASSWDDATA != 0
    if (!Z_ISUNDEF(curl_handlers(source)->passwd)) {
        ZVAL_COPY(&curl_handlers(ch)->passwd, &curl_handlers(source)->passwd);
        curl_easy_setopt(source->cp, CURLOPT_PASSWDDATA, (void *) ch);
    }
#endif
#endif
    if (!Z_ISUNDEF(curl_handlers(source)->write->func_name)) {
        ZVAL_COPY(&curl_handlers(ch)->write->func_name, &curl_handlers(source)->write->func_name);
    }
    if (!Z_ISUNDEF(curl_handlers(source)->read->func_name)) {
        ZVAL_COPY(&curl_handlers(ch)->read->func_name, &curl_handlers(source)->read->func_name);
    }
    if (!Z_ISUNDEF(curl_handlers(source)->write_header->func_name)) {
        ZVAL_COPY(&curl_handlers(ch)->write_header->func_name, &curl_handlers(source)->write_header->func_name);
    }

    curl_easy_setopt(ch->cp, CURLOPT_ERRORBUFFER, ch->err.str);
    curl_easy_setopt(ch->cp, CURLOPT_FILE, (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_INFILE, (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER, (void *) ch);

    if (curl_handlers(source)->progress) {
        curl_handlers(ch)->progress = (php_curl_progress *) ecalloc(1, sizeof(php_curl_progress));
        if (!Z_ISUNDEF(curl_handlers(source)->progress->func_name)) {
            ZVAL_COPY(&curl_handlers(ch)->progress->func_name, &curl_handlers(source)->progress->func_name);
        }
        curl_handlers(ch)->progress->method = curl_handlers(source)->progress->method;
        curl_easy_setopt(ch->cp, CURLOPT_PROGRESSDATA, (void *) ch);
    }

#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
    if (curl_handlers(source)->xferinfo) {
        curl_handlers(ch)->xferinfo = (php_curl_fnxferinfo *) ecalloc(1, sizeof(php_curl_fnxferinfo));
        if (!Z_ISUNDEF(curl_handlers(source)->xferinfo->func_name)) {
            ZVAL_COPY(&curl_handlers(ch)->xferinfo->func_name, &curl_handlers(source)->xferinfo->func_name);
        }
        curl_easy_setopt(ch->cp, CURLOPT_XFERINFODATA, (void *) ch);
    }
#endif

#if LIBCURL_VERSION_NUM >= 0x071500
    if (curl_handlers(source)->fnmatch) {
        curl_handlers(ch)->fnmatch = (php_curl_fnmatch *) ecalloc(1, sizeof(php_curl_fnmatch));
        if (!Z_ISUNDEF(curl_handlers(source)->fnmatch->func_name)) {
            ZVAL_COPY(&curl_handlers(ch)->fnmatch->func_name, &curl_handlers(source)->fnmatch->func_name);
        }
        curl_handlers(ch)->fnmatch->method = curl_handlers(source)->fnmatch->method;
        curl_easy_setopt(ch->cp, CURLOPT_FNMATCH_DATA, (void *) ch);
    }
#endif

    efree(ch->to_free->slist);
    efree(ch->to_free);
    ch->to_free = source->to_free;
    efree(ch->clone);
    ch->clone = source->clone;

    /* Keep track of cloned copies to avoid invoking curl destructors for every clone */
    (*source->clone)++;
}

#if LIBCURL_VERSION_NUM >= 0x073800                                        /* 7.56.0 */
static size_t read_cb(char *buffer, size_t size, size_t nitems, void *arg) /* {{{ */
{
    struct mime_data_cb_arg *cb_arg = (struct mime_data_cb_arg *) arg;
    ssize_t numread;

    if (cb_arg->stream == NULL) {
        if (!(cb_arg->stream = php_stream_open_wrapper(ZSTR_VAL(cb_arg->filename), "rb", IGNORE_PATH, NULL))) {
            return CURL_READFUNC_ABORT;
        }
    }
    numread = php_stream_read(cb_arg->stream, buffer, nitems * size);
    if (numread < 0) {
        php_stream_close(cb_arg->stream);
        cb_arg->stream = NULL;
        return CURL_READFUNC_ABORT;
    }
    return numread;
}
/* }}} */

static int seek_cb(void *arg, curl_off_t offset, int origin) /* {{{ */
{
    struct mime_data_cb_arg *cb_arg = (struct mime_data_cb_arg *) arg;
    int res;

    if (cb_arg->stream == NULL) {
        return CURL_SEEKFUNC_CANTSEEK;
    }
    res = php_stream_seek(cb_arg->stream, offset, origin);
    return res == SUCCESS ? CURL_SEEKFUNC_OK : CURL_SEEKFUNC_CANTSEEK;
}
/* }}} */

static void free_cb(void *arg) /* {{{ */
{
    struct mime_data_cb_arg *cb_arg = (struct mime_data_cb_arg *) arg;

    if (cb_arg->stream != NULL) {
        php_stream_close(cb_arg->stream);
        cb_arg->stream = NULL;
    }
}
/* }}} */
#endif

static inline int build_mime_structure_from_hash(php_curl *ch, zval *zpostfields) /* {{{ */
{
    CURLcode error = CURLE_OK;
    zval *current;
    HashTable *postfields = HASH_OF(zpostfields);
    zend_string *string_key;
    zend_ulong num_key;
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    curl_mime *mime = NULL;
    curl_mimepart *part;
    CURLcode form_error;
#else
    struct HttpPost *first = NULL;
    struct HttpPost *last = NULL;
    CURLFORMcode form_error;
#endif

    if (!postfields) {
        php_error_docref(NULL, E_WARNING, "Couldn't get HashTable in CURLOPT_POSTFIELDS");
        return FAILURE;
    }

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    if (zend_hash_num_elements(postfields) > 0) {
        mime = curl_mime_init(ch->cp);
        if (mime == NULL) {
            return FAILURE;
        }
    }
#endif

#if PHP_VERSION_ID < 80000
    ZEND_HASH_FOREACH_KEY_VAL_IND(postfields, num_key, string_key, current) {
#else
    ZEND_HASH_FOREACH_KEY_VAL(postfields, num_key, string_key, current) {
#endif
        zend_string *postval;
        /* Pretend we have a string_key here */
        if (!string_key) {
            string_key = zend_long_to_str(num_key);
        } else {
            zend_string_addref(string_key);
        }

        ZVAL_DEREF(current);
        if (Z_TYPE_P(current) == IS_OBJECT && instanceof_function(Z_OBJCE_P(current), curl_CURLFile_class)) {
            /* new-style file upload */
            zval *prop, rv;
            char *type = NULL, *filename = NULL;
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
            struct mime_data_cb_arg *cb_arg;
            php_stream *stream;
            php_stream_statbuf ssb;
            size_t filesize = -1;
            curl_seek_callback seekfunc = seek_cb;
#endif

            prop = zend_read_property(curl_CURLFile_class, SW_Z8_OBJ_P(current), "name", sizeof("name") - 1, 0, &rv);
            if (Z_TYPE_P(prop) != IS_STRING) {
                php_error_docref(NULL, E_WARNING, "Invalid filename for key %s", ZSTR_VAL(string_key));
            } else {
                postval = Z_STR_P(prop);

                if (php_check_open_basedir(ZSTR_VAL(postval))) {
                    return 1;
                }

                prop =
                    zend_read_property(curl_CURLFile_class, SW_Z8_OBJ_P(current), "mime", sizeof("mime") - 1, 0, &rv);
                if (Z_TYPE_P(prop) == IS_STRING && Z_STRLEN_P(prop) > 0) {
                    type = Z_STRVAL_P(prop);
                }
                prop = zend_read_property(
                    curl_CURLFile_class, SW_Z8_OBJ_P(current), "postname", sizeof("postname") - 1, 0, &rv);
                if (Z_TYPE_P(prop) == IS_STRING && Z_STRLEN_P(prop) > 0) {
                    filename = Z_STRVAL_P(prop);
                }

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
                zval_ptr_dtor(&ch->postfields);
                ZVAL_COPY(&ch->postfields, zpostfields);

                if ((stream = php_stream_open_wrapper(ZSTR_VAL(postval), "rb", STREAM_MUST_SEEK, NULL))) {
                    if (!stream->readfilters.head && !php_stream_stat(stream, &ssb)) {
                        filesize = ssb.sb.st_size;
                    }
                } else {
                    seekfunc = NULL;
                }

                cb_arg = (struct mime_data_cb_arg *) emalloc(sizeof *cb_arg);
                cb_arg->filename = zend_string_copy(postval);
                cb_arg->stream = stream;

                part = curl_mime_addpart(mime);
                if (part == NULL) {
                    zend_string_release(string_key);
                    return FAILURE;
                }
                if ((form_error = curl_mime_name(part, ZSTR_VAL(string_key))) != CURLE_OK ||
                    (form_error = curl_mime_data_cb(part, filesize, read_cb, seekfunc, free_cb, cb_arg)) != CURLE_OK ||
                    (form_error = curl_mime_filename(part, filename ? filename : ZSTR_VAL(postval))) != CURLE_OK ||
                    (form_error = curl_mime_type(part, type ? type : "application/octet-stream")) != CURLE_OK) {
                    error = form_error;
                }
                zend_llist_add_element(&ch->to_free->stream, &cb_arg);
#else
                form_error = curl_formadd(&first,
                                          &last,
                                          CURLFORM_COPYNAME,
                                          ZSTR_VAL(string_key),
                                          CURLFORM_NAMELENGTH,
                                          ZSTR_LEN(string_key),
                                          CURLFORM_FILENAME,
                                          filename ? filename : ZSTR_VAL(postval),
                                          CURLFORM_CONTENTTYPE,
                                          type ? type : "application/octet-stream",
                                          CURLFORM_FILE,
                                          ZSTR_VAL(postval),
                                          CURLFORM_END);
                if (form_error != CURL_FORMADD_OK) {
                    /* Not nice to convert between enums but we only have place for one error type */
                    error = (CURLcode) form_error;
                }
#endif
            }

            zend_string_release(string_key);
            continue;
        }

        postval = zval_get_string(current);

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
        part = curl_mime_addpart(mime);
        if (part == NULL) {
            zend_string_release(postval);
            zend_string_release(string_key);
            return FAILURE;
        }
        if ((form_error = curl_mime_name(part, ZSTR_VAL(string_key))) != CURLE_OK ||
            (form_error = curl_mime_data(part, ZSTR_VAL(postval), ZSTR_LEN(postval))) != CURLE_OK) {
            error = form_error;
        }
#else
        /* The arguments after _NAMELENGTH and _CONTENTSLENGTH
         * must be explicitly cast to long in curl_formadd
         * use since curl needs a long not an int. */
        form_error = curl_formadd(&first,
                                  &last,
                                  CURLFORM_COPYNAME,
                                  ZSTR_VAL(string_key),
                                  CURLFORM_NAMELENGTH,
                                  ZSTR_LEN(string_key),
                                  CURLFORM_COPYCONTENTS,
                                  ZSTR_VAL(postval),
                                  CURLFORM_CONTENTSLENGTH,
                                  ZSTR_LEN(postval),
                                  CURLFORM_END);

        if (form_error != CURL_FORMADD_OK) {
            /* Not nice to convert between enums but we only have place for one error type */
            error = (CURLcode) form_error;
        }
#endif
        zend_string_release(postval);
        zend_string_release(string_key);
    }
    ZEND_HASH_FOREACH_END();

    SAVE_CURL_ERROR(ch, error);
    if (error != CURLE_OK) {
        return FAILURE;
    }

    if ((*ch->clone) == 1) {
        zend_llist_clean(&ch->to_free->post);
    }
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    zend_llist_add_element(&ch->to_free->post, &mime);
    error = curl_easy_setopt(ch->cp, CURLOPT_MIMEPOST, mime);
#else
    zend_llist_add_element(&ch->to_free->post, &first);
    error = curl_easy_setopt(ch->cp, CURLOPT_HTTPPOST, first);
#endif

    SAVE_CURL_ERROR(ch, error);
    return error == CURLE_OK ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ proto resource curl_copy_handle(resource ch)
   Copy a cURL handle along with all of it's preferences */
PHP_FUNCTION(swoole_native_curl_copy_handle) {
    CURL *cp;
    zval *zid;
    php_curl *ch, *dupch;
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    zval *postfields;
#endif

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    cp = curl_easy_duphandle(ch->cp);
    if (!cp) {
        php_error_docref(NULL, E_WARNING, "Cannot duplicate cURL handle");
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 80000
    dupch = swoole_curl_init_handle_into_zval(return_value);
#else
    dupch = swoole_curl_alloc_handle();
#endif
    dupch->cp = cp;

    swoole_setup_easy_copy_handlers(dupch, ch);
    swoole::curl::create_handle(dupch->cp);

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    postfields = &ch->postfields;
    if (Z_TYPE_P(postfields) != IS_UNDEF) {
        if (build_mime_structure_from_hash(dupch, postfields) != SUCCESS) {
#if PHP_VERSION_ID >= 80000
            zval_ptr_dtor(return_value);
#else
            swoole_curl_close_ex(dupch);
#endif
            php_error_docref(NULL, E_WARNING, "Cannot rebuild mime structure");
            RETURN_FALSE;
        }
    }
#endif

#if PHP_VERSION_ID < 80000
    ZVAL_RES(return_value, zend_register_resource(dupch, le_curl));
    dupch->res = Z_RES_P(return_value);
#endif
}
/* }}} */
#if PHP_VERSION_ID >= 80000
static int _php_curl_setopt(php_curl *ch, zend_long option, zval *zvalue, bool is_array_config) /* {{{ */
#else
static int _php_curl_setopt(php_curl *ch, zend_long option, zval *zvalue) /* {{{ */
#endif
{
    CURLcode error = CURLE_OK;
    zend_long lval;

    switch (option) {
    /* Long options */
    case CURLOPT_SSL_VERIFYHOST:
        lval = zval_get_long(zvalue);
        if (lval == 1) {
#if LIBCURL_VERSION_NUM <= 0x071c00 /* 7.28.0 */
            php_error_docref(NULL,
                             E_NOTICE,
                             "CURLOPT_SSL_VERIFYHOST with value 1 is deprecated and will be removed as of libcurl "
                             "7.28.1. It is recommended to use value 2 instead");
#else
            php_error_docref(
                NULL, E_NOTICE, "CURLOPT_SSL_VERIFYHOST no longer accepts the value 1, value 2 will be used instead");
            error = curl_easy_setopt(ch->cp, (CURLoption) option, 2);
            break;
#endif
        }
        /* no break */
    case CURLOPT_AUTOREFERER:
    case CURLOPT_BUFFERSIZE:
    case CURLOPT_CONNECTTIMEOUT:
    case CURLOPT_COOKIESESSION:
    case CURLOPT_CRLF:
    case CURLOPT_DNS_CACHE_TIMEOUT:
    case CURLOPT_DNS_USE_GLOBAL_CACHE:
    case CURLOPT_FAILONERROR:
    case CURLOPT_FILETIME:
    case CURLOPT_FORBID_REUSE:
    case CURLOPT_FRESH_CONNECT:
    case CURLOPT_FTP_USE_EPRT:
    case CURLOPT_FTP_USE_EPSV:
    case CURLOPT_HEADER:
    case CURLOPT_HTTPGET:
    case CURLOPT_HTTPPROXYTUNNEL:
    case CURLOPT_HTTP_VERSION:
    case CURLOPT_INFILESIZE:
    case CURLOPT_LOW_SPEED_LIMIT:
    case CURLOPT_LOW_SPEED_TIME:
    case CURLOPT_MAXCONNECTS:
    case CURLOPT_MAXREDIRS:
    case CURLOPT_NETRC:
    case CURLOPT_NOBODY:
    case CURLOPT_NOPROGRESS:
    case CURLOPT_NOSIGNAL:
    case CURLOPT_PORT:
    case CURLOPT_POST:
    case CURLOPT_PROXYPORT:
    case CURLOPT_PROXYTYPE:
    case CURLOPT_PUT:
    case CURLOPT_RESUME_FROM:
    case CURLOPT_SSLVERSION:
    case CURLOPT_SSL_VERIFYPEER:
    case CURLOPT_TIMECONDITION:
    case CURLOPT_TIMEOUT:
    case CURLOPT_TIMEVALUE:
    case CURLOPT_TRANSFERTEXT:
    case CURLOPT_UNRESTRICTED_AUTH:
    case CURLOPT_UPLOAD:
    case CURLOPT_VERBOSE:
    case CURLOPT_HTTPAUTH:
    case CURLOPT_FTP_CREATE_MISSING_DIRS:
    case CURLOPT_PROXYAUTH:
    case CURLOPT_FTP_RESPONSE_TIMEOUT:
    case CURLOPT_IPRESOLVE:
    case CURLOPT_MAXFILESIZE:
    case CURLOPT_TCP_NODELAY:
    case CURLOPT_FTPSSLAUTH:
    case CURLOPT_IGNORE_CONTENT_LENGTH:
    case CURLOPT_FTP_SKIP_PASV_IP:
    case CURLOPT_FTP_FILEMETHOD:
    case CURLOPT_CONNECT_ONLY:
    case CURLOPT_LOCALPORT:
    case CURLOPT_LOCALPORTRANGE:
#if LIBCURL_VERSION_NUM >= 0x071000 /* Available since 7.16.0 */
    case CURLOPT_SSL_SESSIONID_CACHE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071001 /* Available since 7.16.1 */
    case CURLOPT_FTP_SSL_CCC:
    case CURLOPT_SSH_AUTH_TYPES:
#endif
#if LIBCURL_VERSION_NUM >= 0x071002 /* Available since 7.16.2 */
    case CURLOPT_CONNECTTIMEOUT_MS:
    case CURLOPT_HTTP_CONTENT_DECODING:
    case CURLOPT_HTTP_TRANSFER_DECODING:
    case CURLOPT_TIMEOUT_MS:
#endif
#if LIBCURL_VERSION_NUM >= 0x071004 /* Available since 7.16.4 */
    case CURLOPT_NEW_DIRECTORY_PERMS:
    case CURLOPT_NEW_FILE_PERMS:
#endif
#if LIBCURL_VERSION_NUM >= 0x071100 /* Available since 7.17.0 */
    case CURLOPT_USE_SSL:
    case CURLOPT_APPEND:
    case CURLOPT_DIRLISTONLY:
#else
    case CURLOPT_FTP_SSL:
    case CURLOPT_FTPAPPEND:
    case CURLOPT_FTPLISTONLY:
#endif
#if LIBCURL_VERSION_NUM >= 0x071200 /* Available since 7.18.0 */
    case CURLOPT_PROXY_TRANSFER_MODE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071300 /* Available since 7.19.0 */
    case CURLOPT_ADDRESS_SCOPE:
#endif
#if LIBCURL_VERSION_NUM > 0x071301 /* Available since 7.19.1 */
    case CURLOPT_CERTINFO:
#endif
#if LIBCURL_VERSION_NUM >= 0x071304 /* Available since 7.19.4 */
    case CURLOPT_PROTOCOLS:
    case CURLOPT_REDIR_PROTOCOLS:
    case CURLOPT_SOCKS5_GSSAPI_NEC:
    case CURLOPT_TFTP_BLKSIZE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071400 /* Available since 7.20.0 */
    case CURLOPT_FTP_USE_PRET:
    case CURLOPT_RTSP_CLIENT_CSEQ:
    case CURLOPT_RTSP_REQUEST:
    case CURLOPT_RTSP_SERVER_CSEQ:
#endif
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    case CURLOPT_WILDCARDMATCH:
#endif
#if LIBCURL_VERSION_NUM >= 0x071504 /* Available since 7.21.4 */
    case CURLOPT_TLSAUTH_TYPE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071600 /* Available since 7.22.0 */
    case CURLOPT_GSSAPI_DELEGATION:
#endif
#if LIBCURL_VERSION_NUM >= 0x071800 /* Available since 7.24.0 */
    case CURLOPT_ACCEPTTIMEOUT_MS:
#endif
#if LIBCURL_VERSION_NUM >= 0x071900 /* Available since 7.25.0 */
    case CURLOPT_SSL_OPTIONS:
    case CURLOPT_TCP_KEEPALIVE:
    case CURLOPT_TCP_KEEPIDLE:
    case CURLOPT_TCP_KEEPINTVL:
#endif
#if LIBCURL_VERSION_NUM >= 0x071f00 /* Available since 7.31.0 */
    case CURLOPT_SASL_IR:
#endif
#if LIBCURL_VERSION_NUM >= 0x072400 /* Available since 7.36.0 */
    case CURLOPT_EXPECT_100_TIMEOUT_MS:
    case CURLOPT_SSL_ENABLE_ALPN:
    case CURLOPT_SSL_ENABLE_NPN:
#endif
#if LIBCURL_VERSION_NUM >= 0x072500 /* Available since 7.37.0 */
    case CURLOPT_HEADEROPT:
#endif
#if LIBCURL_VERSION_NUM >= 0x072900 /* Available since 7.41.0 */
    case CURLOPT_SSL_VERIFYSTATUS:
#endif
#if LIBCURL_VERSION_NUM >= 0x072a00 /* Available since 7.42.0 */
    case CURLOPT_PATH_AS_IS:
    case CURLOPT_SSL_FALSESTART:
#endif
#if LIBCURL_VERSION_NUM >= 0x072b00 /* Available since 7.43.0 */
    case CURLOPT_PIPEWAIT:
#endif
#if LIBCURL_VERSION_NUM >= 0x072e00 /* Available since 7.46.0 */
    case CURLOPT_STREAM_WEIGHT:
#endif
#if LIBCURL_VERSION_NUM >= 0x073000 /* Available since 7.48.0 */
    case CURLOPT_TFTP_NO_OPTIONS:
#endif
#if LIBCURL_VERSION_NUM >= 0x073100 /* Available since 7.49.0 */
    case CURLOPT_TCP_FASTOPEN:
#endif
#if LIBCURL_VERSION_NUM >= 0x073300 /* Available since 7.51.0 */
    case CURLOPT_KEEP_SENDING_ON_ERROR:
#endif
#if LIBCURL_VERSION_NUM >= 0x073400 /* Available since 7.52.0 */
    case CURLOPT_PROXY_SSL_OPTIONS:
    case CURLOPT_PROXY_SSL_VERIFYHOST:
    case CURLOPT_PROXY_SSL_VERIFYPEER:
    case CURLOPT_PROXY_SSLVERSION:
#endif
#if LIBCURL_VERSION_NUM >= 0x073600 /* Available since 7.54.0 */
    case CURLOPT_SUPPRESS_CONNECT_HEADERS:
#endif
#if LIBCURL_VERSION_NUM >= 0x073700 /* Available since 7.55.0 */
    case CURLOPT_SOCKS5_AUTH:
#endif
#if LIBCURL_VERSION_NUM >= 0x073800 /* Available since 7.56.0 */
    case CURLOPT_SSH_COMPRESSION:
#endif
#if LIBCURL_VERSION_NUM >= 0x073b00 /* Available since 7.59.0 */
    case CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS:
#endif
#if LIBCURL_VERSION_NUM >= 0x073c00 /* Available since 7.60.0 */
    case CURLOPT_DNS_SHUFFLE_ADDRESSES:
    case CURLOPT_HAPROXYPROTOCOL:
#endif
#if LIBCURL_VERSION_NUM >= 0x073d00 /* Available since 7.61.0 */
    case CURLOPT_DISALLOW_USERNAME_IN_URL:
#endif
#if LIBCURL_VERSION_NUM >= 0x074000 /* Available since 7.64.0 */
    case CURLOPT_HTTP09_ALLOWED:
#endif
        lval = zval_get_long(zvalue);
#if LIBCURL_VERSION_NUM >= 0x071304
        if ((option == CURLOPT_PROTOCOLS || option == CURLOPT_REDIR_PROTOCOLS) &&
            (PG(open_basedir) && *PG(open_basedir)) && (lval & CURLPROTO_FILE)) {
            php_error_docref(NULL, E_WARNING, "CURLPROTO_FILE cannot be activated when an open_basedir is set");
            return 1;
        }
#endif
#ifdef ZTS
        if (option == CURLOPT_DNS_USE_GLOBAL_CACHE && lval) {
            php_error_docref(
                NULL, E_WARNING, "CURLOPT_DNS_USE_GLOBAL_CACHE cannot be activated when thread safety is enabled");
            return 1;
        }
#endif
        error = curl_easy_setopt(ch->cp, (CURLoption) option, lval);
        break;
    case CURLOPT_SAFE_UPLOAD:
        if (!zend_is_true(zvalue)) {
            php_error_docref(NULL, E_WARNING, "Disabling safe uploads is no longer supported");
            return FAILURE;
        }
        break;

    /* String options */
    case CURLOPT_CAINFO:
    case CURLOPT_CAPATH:
    case CURLOPT_COOKIE:
    case CURLOPT_EGDSOCKET:
    case CURLOPT_INTERFACE:
    case CURLOPT_PROXY:
    case CURLOPT_PROXYUSERPWD:
    case CURLOPT_REFERER:
    case CURLOPT_SSLCERTTYPE:
    case CURLOPT_SSLENGINE:
    case CURLOPT_SSLENGINE_DEFAULT:
    case CURLOPT_SSLKEY:
    case CURLOPT_SSLKEYPASSWD:
    case CURLOPT_SSLKEYTYPE:
    case CURLOPT_SSL_CIPHER_LIST:
    case CURLOPT_USERAGENT:
    case CURLOPT_USERPWD:
    case CURLOPT_COOKIELIST:
    case CURLOPT_FTP_ALTERNATIVE_TO_USER:
#if LIBCURL_VERSION_NUM >= 0x071101 /* Available since 7.17.1 */
    case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
#endif
#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
    case CURLOPT_PASSWORD:
    case CURLOPT_PROXYPASSWORD:
    case CURLOPT_PROXYUSERNAME:
    case CURLOPT_USERNAME:
#endif
#if LIBCURL_VERSION_NUM >= 0x071304 /* Available since 7.19.4 */
    case CURLOPT_NOPROXY:
    case CURLOPT_SOCKS5_GSSAPI_SERVICE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071400 /* Available since 7.20.0 */
    case CURLOPT_MAIL_FROM:
    case CURLOPT_RTSP_STREAM_URI:
    case CURLOPT_RTSP_TRANSPORT:
#endif
#if LIBCURL_VERSION_NUM >= 0x071504 /* Available since 7.21.4 */
    case CURLOPT_TLSAUTH_PASSWORD:
    case CURLOPT_TLSAUTH_USERNAME:
#endif
#if LIBCURL_VERSION_NUM >= 0x071506 /* Available since 7.21.6 */
    case CURLOPT_ACCEPT_ENCODING:
    case CURLOPT_TRANSFER_ENCODING:
#else
    case CURLOPT_ENCODING:
#endif
#if LIBCURL_VERSION_NUM >= 0x071800 /* Available since 7.24.0 */
    case CURLOPT_DNS_SERVERS:
#endif
#if LIBCURL_VERSION_NUM >= 0x071900 /* Available since 7.25.0 */
    case CURLOPT_MAIL_AUTH:
#endif
#if LIBCURL_VERSION_NUM >= 0x072200 /* Available since 7.34.0 */
    case CURLOPT_LOGIN_OPTIONS:
#endif
#if LIBCURL_VERSION_NUM >= 0x072700 /* Available since 7.39.0 */
    case CURLOPT_PINNEDPUBLICKEY:
#endif
#if LIBCURL_VERSION_NUM >= 0x072b00 /* Available since 7.43.0 */
    case CURLOPT_PROXY_SERVICE_NAME:
    case CURLOPT_SERVICE_NAME:
#endif
#if LIBCURL_VERSION_NUM >= 0x072d00 /* Available since 7.45.0 */
    case CURLOPT_DEFAULT_PROTOCOL:
#endif
#if LIBCURL_VERSION_NUM >= 0x073400 /* Available since 7.52.0 */
    case CURLOPT_PRE_PROXY:
    case CURLOPT_PROXY_CAINFO:
    case CURLOPT_PROXY_CAPATH:
    case CURLOPT_PROXY_CRLFILE:
    case CURLOPT_PROXY_KEYPASSWD:
    case CURLOPT_PROXY_PINNEDPUBLICKEY:
    case CURLOPT_PROXY_SSL_CIPHER_LIST:
    case CURLOPT_PROXY_SSLCERT:
    case CURLOPT_PROXY_SSLCERTTYPE:
    case CURLOPT_PROXY_SSLKEY:
    case CURLOPT_PROXY_SSLKEYTYPE:
    case CURLOPT_PROXY_TLSAUTH_PASSWORD:
    case CURLOPT_PROXY_TLSAUTH_TYPE:
    case CURLOPT_PROXY_TLSAUTH_USERNAME:
#endif
#if LIBCURL_VERSION_NUM >= 0x073500 /* Available since 7.53.0 */
    case CURLOPT_ABSTRACT_UNIX_SOCKET:
#endif
#if LIBCURL_VERSION_NUM >= 0x073700 /* Available since 7.55.0 */
    case CURLOPT_REQUEST_TARGET:
#endif
#if LIBCURL_VERSION_NUM >= 0x073d00 /* Available since 7.61.0 */
    case CURLOPT_PROXY_TLS13_CIPHERS:
    case CURLOPT_TLS13_CIPHERS:
#endif
    {
        zend_string *str = zval_get_string(zvalue);
        int ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str));
        zend_string_release(str);
        return ret;
    }

    /* Curl nullable string options */
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_FTPPORT:
    case CURLOPT_RANGE:
    case CURLOPT_FTP_ACCOUNT:
#if LIBCURL_VERSION_NUM >= 0x071400 /* Available since 7.20.0 */
    case CURLOPT_RTSP_SESSION_ID:
#endif
#if LIBCURL_VERSION_NUM >= 0x072100 /* Available since 7.33.0 */
    case CURLOPT_DNS_INTERFACE:
    case CURLOPT_DNS_LOCAL_IP4:
    case CURLOPT_DNS_LOCAL_IP6:
    case CURLOPT_XOAUTH2_BEARER:
#endif
#if LIBCURL_VERSION_NUM >= 0x072800 /* Available since 7.40.0 */
    case CURLOPT_UNIX_SOCKET_PATH:
#endif
#if LIBCURL_VERSION_NUM >= 0x071004 /* Available since 7.16.4 */
    case CURLOPT_KRBLEVEL:
#else
    case CURLOPT_KRB4LEVEL:
#endif
    {
        if (Z_ISNULL_P(zvalue)) {
            error = curl_easy_setopt(ch->cp, (CURLoption) option, NULL);
        } else {
            zend_string *str = zval_get_string(zvalue);
            int ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str));
            zend_string_release(str);
            return ret;
        }
        break;
    }

    /* Curl private option */
    case CURLOPT_PRIVATE: {
        swoole_curl_set_private_data(ch, zvalue);
        return SUCCESS;
    }

    /* Curl url option */
    case CURLOPT_URL: {
        zend_string *str = zval_get_string(zvalue);
        int ret = php_curl_option_url(ch, ZSTR_VAL(str), ZSTR_LEN(str));
        zend_string_release(str);
        return ret;
    }

    /* Curl file handle options */
    case CURLOPT_FILE:
    case CURLOPT_INFILE:
    case CURLOPT_STDERR:
    case CURLOPT_WRITEHEADER: {
        FILE *fp = NULL;
        php_stream *what = NULL;

        if (Z_TYPE_P(zvalue) != IS_NULL) {
            what = (php_stream *) zend_fetch_resource2_ex(
                zvalue, "File-Handle", php_file_le_stream(), php_file_le_pstream());
            if (!what) {
                return FAILURE;
            }

            if (FAILURE == php_stream_cast(what, PHP_STREAM_AS_STDIO, (void **) &fp, REPORT_ERRORS)) {
                return FAILURE;
            }

            if (!fp) {
                return FAILURE;
            }
        }

        error = CURLE_OK;
        switch (option) {
        case CURLOPT_FILE:
            if (!what) {
                if (!Z_ISUNDEF(curl_handlers(ch)->write->stream)) {
                    zval_ptr_dtor(&curl_handlers(ch)->write->stream);
                    ZVAL_UNDEF(&curl_handlers(ch)->write->stream);
                }
                curl_handlers(ch)->write->fp = NULL;
                curl_handlers(ch)->write->method = PHP_CURL_STDOUT;
            } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                zval_ptr_dtor(&curl_handlers(ch)->write->stream);
                curl_handlers(ch)->write->fp = fp;
                curl_handlers(ch)->write->method = PHP_CURL_FILE;
                ZVAL_COPY(&curl_handlers(ch)->write->stream, zvalue);
            } else {
#if PHP_VERSION_ID >= 80000
                zend_value_error("%s(): The provided file handle must be writable", get_active_function_name());
#else
                php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
#endif
                return FAILURE;
            }
            break;
        case CURLOPT_WRITEHEADER:
            if (!what) {
                if (!Z_ISUNDEF(curl_handlers(ch)->write_header->stream)) {
                    zval_ptr_dtor(&curl_handlers(ch)->write_header->stream);
                    ZVAL_UNDEF(&curl_handlers(ch)->write_header->stream);
                }
                curl_handlers(ch)->write_header->fp = NULL;
                curl_handlers(ch)->write_header->method = PHP_CURL_IGNORE;
            } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                zval_ptr_dtor(&curl_handlers(ch)->write_header->stream);
                curl_handlers(ch)->write_header->fp = fp;
                curl_handlers(ch)->write_header->method = PHP_CURL_FILE;
                ZVAL_COPY(&curl_handlers(ch)->write_header->stream, zvalue);
            } else {
#if PHP_VERSION_ID >= 80000
                zend_value_error("%s(): The provided file handle must be writable", get_active_function_name());
#else
                php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
#endif
                return FAILURE;
            }
            break;
        case CURLOPT_INFILE:
            if (!what) {
                if (!Z_ISUNDEF(curl_handlers(ch)->read->stream)) {
                    zval_ptr_dtor(&curl_handlers(ch)->read->stream);
                    ZVAL_UNDEF(&curl_handlers(ch)->read->stream);
                }
                curl_handlers(ch)->read->fp = NULL;
                curl_handlers(ch)->read->res = NULL;
            } else {
                zval_ptr_dtor(&curl_handlers(ch)->read->stream);
                curl_handlers(ch)->read->fp = fp;
                curl_handlers(ch)->read->res = Z_RES_P(zvalue);
                ZVAL_COPY(&curl_handlers(ch)->read->stream, zvalue);
            }
            break;
        case CURLOPT_STDERR:
            if (!what) {
                if (!Z_ISUNDEF(curl_handlers(ch)->std_err)) {
                    zval_ptr_dtor(&curl_handlers(ch)->std_err);
                    ZVAL_UNDEF(&curl_handlers(ch)->std_err);
                }
            } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                zval_ptr_dtor(&curl_handlers(ch)->std_err);
                ZVAL_COPY(&curl_handlers(ch)->std_err, zvalue);
            } else {
#if PHP_VERSION_ID >= 80000
                zend_value_error("%s(): The provided file handle must be writable", get_active_function_name());
#else
                php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
#endif
                return FAILURE;
            }
            /* break omitted intentionally */
        default:
            error = curl_easy_setopt(ch->cp, (CURLoption) option, fp);
            break;
        }
        break;
    }

    /* Curl linked list options */
    case CURLOPT_HTTP200ALIASES:
    case CURLOPT_HTTPHEADER:
    case CURLOPT_POSTQUOTE:
    case CURLOPT_PREQUOTE:
    case CURLOPT_QUOTE:
    case CURLOPT_TELNETOPTIONS:
#if LIBCURL_VERSION_NUM >= 0x071400 /* Available since 7.20.0 */
    case CURLOPT_MAIL_RCPT:
#endif
#if LIBCURL_VERSION_NUM >= 0x071503 /* Available since 7.21.3 */
    case CURLOPT_RESOLVE:
#endif
#if LIBCURL_VERSION_NUM >= 0x072500 /* Available since 7.37.0 */
    case CURLOPT_PROXYHEADER:
#endif
#if LIBCURL_VERSION_NUM >= 0x073100 /* Available since 7.49.0 */
    case CURLOPT_CONNECT_TO:
#endif
    {
        zval *current;
        HashTable *ph = NULL;
        zend_string *val;
        struct curl_slist *slist = NULL;

        ph = HASH_OF(zvalue);
        if (!ph) {
            const char *name = NULL;
            switch (option) {
            case CURLOPT_HTTPHEADER:
                name = "CURLOPT_HTTPHEADER";
                break;
            case CURLOPT_QUOTE:
                name = "CURLOPT_QUOTE";
                break;
            case CURLOPT_HTTP200ALIASES:
                name = "CURLOPT_HTTP200ALIASES";
                break;
            case CURLOPT_POSTQUOTE:
                name = "CURLOPT_POSTQUOTE";
                break;
            case CURLOPT_PREQUOTE:
                name = "CURLOPT_PREQUOTE";
                break;
            case CURLOPT_TELNETOPTIONS:
                name = "CURLOPT_TELNETOPTIONS";
                break;
#if LIBCURL_VERSION_NUM >= 0x071400 /* Available since 7.20.0 */
            case CURLOPT_MAIL_RCPT:
                name = "CURLOPT_MAIL_RCPT";
                break;
#endif
#if LIBCURL_VERSION_NUM >= 0x071503 /* Available since 7.21.3 */
            case CURLOPT_RESOLVE:
                name = "CURLOPT_RESOLVE";
                break;
#endif
#if LIBCURL_VERSION_NUM >= 0x072500 /* Available since 7.37.0 */
            case CURLOPT_PROXYHEADER:
                name = "CURLOPT_PROXYHEADER";
                break;
#endif
#if LIBCURL_VERSION_NUM >= 0x073100 /* Available since 7.49.0 */
            case CURLOPT_CONNECT_TO:
                name = "CURLOPT_CONNECT_TO";
                break;
#endif
            }
#if PHP_VERSION_ID >= 80000
            zend_type_error("%s(): The %s option must have an array value", get_active_function_name(), name);
#else
            php_error_docref(NULL, E_WARNING, "You must pass either an object or an array with the %s argument", name);
#endif
            return FAILURE;
        }

        ZEND_HASH_FOREACH_VAL(ph, current) {
            ZVAL_DEREF(current);
            val = zval_get_string(current);
            slist = curl_slist_append(slist, ZSTR_VAL(val));
            zend_string_release(val);
            if (!slist) {
                php_error_docref(NULL, E_WARNING, "Could not build curl_slist");
                return 1;
            }
        }
        ZEND_HASH_FOREACH_END();

        if (slist) {
            if ((*ch->clone) == 1) {
                zend_hash_index_update_ptr(ch->to_free->slist, option, slist);
            } else {
                zend_hash_next_index_insert_ptr(ch->to_free->slist, slist);
            }
        }

        error = curl_easy_setopt(ch->cp, (CURLoption) option, slist);

        break;
    }

    case CURLOPT_BINARYTRANSFER:
        /* Do nothing, just backward compatibility */
        break;

    case CURLOPT_FOLLOWLOCATION:
        lval = zend_is_true(zvalue);
#if LIBCURL_VERSION_NUM < 0x071304
        if (lval && PG(open_basedir) && *PG(open_basedir)) {
            php_error_docref(NULL, E_WARNING, "CURLOPT_FOLLOWLOCATION cannot be activated when an open_basedir is set");
            return FAILURE;
        }
#endif
        error = curl_easy_setopt(ch->cp, (CURLoption) option, lval);
        break;

    case CURLOPT_HEADERFUNCTION:
        if (!Z_ISUNDEF(curl_handlers(ch)->write_header->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->write_header->func_name);
            curl_handlers(ch)->write_header->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->write_header->func_name, zvalue);
        curl_handlers(ch)->write_header->method = PHP_CURL_USER;
        break;

    case CURLOPT_POSTFIELDS:
#if PHP_VERSION_ID >= 80000
        if (Z_TYPE_P(zvalue) == IS_ARRAY) {
#else
        if (Z_TYPE_P(zvalue) == IS_ARRAY || Z_TYPE_P(zvalue) == IS_OBJECT) {
#endif
            return build_mime_structure_from_hash(ch, zvalue);
        } else {
#if LIBCURL_VERSION_NUM >= 0x071101
            zend_string *str = zval_get_string(zvalue);
            /* with curl 7.17.0 and later, we can use COPYPOSTFIELDS, but we have to provide size before */
            error = curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDSIZE, ZSTR_LEN(str));
            error = curl_easy_setopt(ch->cp, CURLOPT_COPYPOSTFIELDS, ZSTR_VAL(str));
            zend_string_release(str);
#else
            char *post = NULL;
            zend_string *str = zval_get_string(zvalue);

            post = estrndup(ZSTR_VAL(str), ZSTR_LEN(str));
            zend_llist_add_element(&ch->to_free->str, &post);

            curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDS, post);
            error = curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDSIZE, ZSTR_LEN(str));
            zend_string_release(str);
#endif
        }
        break;

    case CURLOPT_PROGRESSFUNCTION:
        curl_easy_setopt(ch->cp, CURLOPT_PROGRESSFUNCTION, fn_progress);
        curl_easy_setopt(ch->cp, CURLOPT_PROGRESSDATA, ch);
        if (curl_handlers(ch)->progress == NULL) {
            curl_handlers(ch)->progress = (php_curl_progress *) ecalloc(1, sizeof(php_curl_progress));
        } else if (!Z_ISUNDEF(curl_handlers(ch)->progress->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->progress->func_name);
            curl_handlers(ch)->progress->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->progress->func_name, zvalue);
        curl_handlers(ch)->progress->method = PHP_CURL_USER;
        break;

    case CURLOPT_READFUNCTION:
        if (!Z_ISUNDEF(curl_handlers(ch)->read->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->read->func_name);
            curl_handlers(ch)->read->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->read->func_name, zvalue);
        curl_handlers(ch)->read->method = PHP_CURL_USER;
        break;

    case CURLOPT_RETURNTRANSFER:
        if (zend_is_true(zvalue)) {
            curl_handlers(ch)->write->method = PHP_CURL_RETURN;
        } else {
            curl_handlers(ch)->write->method = PHP_CURL_STDOUT;
        }
        break;

    case CURLOPT_WRITEFUNCTION:
        if (!Z_ISUNDEF(curl_handlers(ch)->write->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->write->func_name);
            curl_handlers(ch)->write->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->write->func_name, zvalue);
        curl_handlers(ch)->write->method = PHP_CURL_USER;
        break;

#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
    case CURLOPT_XFERINFOFUNCTION:
        curl_easy_setopt(ch->cp, CURLOPT_XFERINFOFUNCTION, fn_xferinfo);
        curl_easy_setopt(ch->cp, CURLOPT_XFERINFODATA, ch);
        if (curl_handlers(ch)->xferinfo == NULL) {
            curl_handlers(ch)->xferinfo = (php_curl_fnxferinfo *) ecalloc(1, sizeof(php_curl_fnxferinfo));
        } else if (!Z_ISUNDEF(curl_handlers(ch)->xferinfo->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->xferinfo->func_name);
            curl_handlers(ch)->xferinfo->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->xferinfo->func_name, zvalue);
        break;
#endif

    /* Curl off_t options */
    case CURLOPT_MAX_RECV_SPEED_LARGE:
    case CURLOPT_MAX_SEND_SPEED_LARGE:
#if LIBCURL_VERSION_NUM >= 0x073b00 /* Available since 7.59.0 */
    case CURLOPT_TIMEVALUE_LARGE:
#endif
        lval = zval_get_long(zvalue);
        error = curl_easy_setopt(ch->cp, (CURLoption) option, (curl_off_t) lval);
        break;

#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
    case CURLOPT_POSTREDIR:
        lval = zval_get_long(zvalue);
        error = curl_easy_setopt(ch->cp, CURLOPT_POSTREDIR, lval & CURL_REDIR_POST_ALL);
        break;
#endif

    /* the following options deal with files, therefore the open_basedir check
     * is required.
     */
    case CURLOPT_COOKIEFILE:
    case CURLOPT_COOKIEJAR:
    case CURLOPT_RANDOM_FILE:
    case CURLOPT_SSLCERT:
    case CURLOPT_NETRC_FILE:
#if LIBCURL_VERSION_NUM >= 0x071001 /* Available since 7.16.1 */
    case CURLOPT_SSH_PRIVATE_KEYFILE:
    case CURLOPT_SSH_PUBLIC_KEYFILE:
#endif
#if LIBCURL_VERSION_NUM >= 0x071300 /* Available since 7.19.0 */
    case CURLOPT_CRLFILE:
    case CURLOPT_ISSUERCERT:
#endif
#if LIBCURL_VERSION_NUM >= 0x071306 /* Available since 7.19.6 */
    case CURLOPT_SSH_KNOWNHOSTS:
#endif
    {
        zend_string *str = zval_get_string(zvalue);
        int ret;

        if (ZSTR_LEN(str) && php_check_open_basedir(ZSTR_VAL(str))) {
            zend_string_release(str);
            return FAILURE;
        }

        ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str));
        zend_string_release(str);
        return ret;
    }

    case CURLINFO_HEADER_OUT:
        if (zend_is_true(zvalue)) {
            curl_easy_setopt(ch->cp, CURLOPT_DEBUGFUNCTION, curl_debug);
            curl_easy_setopt(ch->cp, CURLOPT_DEBUGDATA, (void *) ch);
            curl_easy_setopt(ch->cp, CURLOPT_VERBOSE, 1);
        } else {
            curl_easy_setopt(ch->cp, CURLOPT_DEBUGFUNCTION, NULL);
            curl_easy_setopt(ch->cp, CURLOPT_DEBUGDATA, NULL);
            curl_easy_setopt(ch->cp, CURLOPT_VERBOSE, 0);
        }
        break;

    case CURLOPT_SHARE: {
#if PHP_VERSION_ID >= 80000
        if (Z_TYPE_P(zvalue) == IS_OBJECT && Z_OBJCE_P(zvalue) == curl_share_ce) {
            php_curlsh *sh = Z_CURL_SHARE_P(zvalue);
            curl_easy_setopt(ch->cp, CURLOPT_SHARE, sh->share);

            if (ch->share) {
                OBJ_RELEASE(&ch->share->std);
            }
            GC_ADDREF(&sh->std);
            ch->share = sh;
        }
#else
        php_curlsh *sh;
        if ((sh = (php_curlsh *) zend_fetch_resource_ex(zvalue, le_curl_share_handle_name, le_curl_share_handle))) {
            curl_easy_setopt(ch->cp, CURLOPT_SHARE, sh->share);
        }
#endif
        break;
    }

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    case CURLOPT_FNMATCH_FUNCTION:
        curl_easy_setopt(ch->cp, CURLOPT_FNMATCH_FUNCTION, fn_fnmatch);
        curl_easy_setopt(ch->cp, CURLOPT_FNMATCH_DATA, ch);
        if (curl_handlers(ch)->fnmatch == NULL) {
            curl_handlers(ch)->fnmatch = (php_curl_fnmatch *) ecalloc(1, sizeof(php_curl_fnmatch));
        } else if (!Z_ISUNDEF(curl_handlers(ch)->fnmatch->func_name)) {
            zval_ptr_dtor(&curl_handlers(ch)->fnmatch->func_name);
            curl_handlers(ch)->fnmatch->fci_cache = empty_fcall_info_cache;
        }
        ZVAL_COPY(&curl_handlers(ch)->fnmatch->func_name, zvalue);
        curl_handlers(ch)->fnmatch->method = PHP_CURL_USER;
        break;
#endif

#if PHP_VERSION_ID >= 80000
    default:
        if (is_array_config) {
            zend_argument_value_error(2, "must contain only valid cURL options");
        } else {
            zend_argument_value_error(2, "is not a valid cURL option");
        }
        error = CURLE_UNKNOWN_OPTION;
        break;
#endif
    }

    SAVE_CURL_ERROR(ch, error);
    if (error != CURLE_OK) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}
/* }}} */

/* {{{ proto bool curl_setopt(resource ch, int option, mixed value)
   Set an option for a cURL transfer */
PHP_FUNCTION(swoole_native_curl_setopt) {
    zval *zid, *zvalue;
    zend_long options;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(3, 3)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_LONG(options)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid, false)) == NULL) {
        RETURN_FALSE;
    }

#if PHP_VERSION_ID < 80000
    if (options <= 0 && options != CURLOPT_SAFE_UPLOAD) {
        php_error_docref(NULL, E_WARNING, "Invalid curl configuration option");
        RETURN_FALSE;
    }
    RETURN_BOOL(_php_curl_setopt(ch, options, zvalue) == SUCCESS);
#else
    RETURN_BOOL(_php_curl_setopt(ch, options, zvalue, 0) == SUCCESS);
#endif
}
/* }}} */

/* {{{ proto bool curl_setopt_array(resource ch, array options)
   Set an array of option for a cURL transfer */
PHP_FUNCTION(swoole_native_curl_setopt_array) {
    zval *zid, *arr, *entry;
    php_curl *ch;
    zend_ulong option;
    zend_string *string_key;

    ZEND_PARSE_PARAMETERS_START(2, 2)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_ARRAY(arr)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid, false)) == NULL) {
        RETURN_FALSE;
    }

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(arr), option, string_key, entry) {
        if (string_key) {
            php_error_docref(NULL, E_WARNING, "Array keys must be CURLOPT constants or equivalent integer values");
            RETURN_FALSE;
        }
        ZVAL_DEREF(entry);
#if PHP_VERSION_ID >= 80000
        if (_php_curl_setopt(ch, (zend_long) option, entry, 1) == FAILURE) {
#else
        if (_php_curl_setopt(ch, (zend_long) option, entry) == FAILURE) {
#endif
            RETURN_FALSE;
        }
    }
    ZEND_HASH_FOREACH_END();

    RETURN_TRUE;
}
/* }}} */

/* {{{ _php_curl_cleanup_handle(ch)
   Cleanup an execution phase */
void swoole_curl_cleanup_handle(php_curl *ch) {
    smart_str_free(&curl_handlers(ch)->write->buf);
    if (ch->header.str) {
        zend_string_release(ch->header.str);
        ch->header.str = NULL;
    }

    memset(ch->err.str, 0, CURL_ERROR_SIZE + 1);
    ch->err.no = 0;
}
/* }}} */

/* {{{ proto bool curl_exec(resource ch)
   Perform a cURL session */
PHP_FUNCTION(swoole_native_curl_exec) {
    CURLcode error;
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    swoole_curl_verify_handlers(ch, 1);
    swoole_curl_cleanup_handle(ch);

    Multi multi{};
    error = multi.exec(swoole::curl::get_handle(ch->cp));
    SAVE_CURL_ERROR(ch, error);

    if (error != CURLE_OK) {
        smart_str_free(&curl_handlers(ch)->write->buf);
        RETURN_FALSE;
    }

    if (!Z_ISUNDEF(curl_handlers(ch)->std_err)) {
        php_stream *stream;
        stream = (php_stream *) zend_fetch_resource2_ex(
            &curl_handlers(ch)->std_err, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream) {
            php_stream_flush(stream);
        }
    }

    if (curl_handlers(ch)->write->method == PHP_CURL_RETURN && curl_handlers(ch)->write->buf.s) {
        smart_str_0(&curl_handlers(ch)->write->buf);
        RETURN_STR_COPY(curl_handlers(ch)->write->buf.s);
    }

    /* flush the file handle, so any remaining data is synched to disk */
    if (curl_handlers(ch)->write->method == PHP_CURL_FILE && curl_handlers(ch)->write->fp) {
        fflush(curl_handlers(ch)->write->fp);
    }
    if (curl_handlers(ch)->write_header->method == PHP_CURL_FILE && curl_handlers(ch)->write_header->fp) {
        fflush(curl_handlers(ch)->write_header->fp);
    }

    if (curl_handlers(ch)->write->method == PHP_CURL_RETURN) {
        RETURN_EMPTY_STRING();
    } else {
        RETURN_TRUE;
    }
}
/* }}} */

/* {{{ proto mixed curl_getinfo(resource ch [, int option])
   Get information regarding a specific transfer */
PHP_FUNCTION(swoole_native_curl_getinfo) {
    zval *zid;
    php_curl *ch;
#if PHP_VERSION_ID >= 80000
    zend_long option;
    zend_bool option_is_null = 1;
#else
    zend_long option = 0;
#endif

    ZEND_PARSE_PARAMETERS_START(1, 2)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_OPTIONAL
#if PHP_VERSION_ID >= 80000
    Z_PARAM_LONG_OR_NULL(option, option_is_null)
#else
    Z_PARAM_LONG(option)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid, false)) == NULL) {
        RETURN_FALSE;
    }

#if PHP_VERSION_ID >= 80000
    if (option_is_null) {
#else
    if (ZEND_NUM_ARGS() < 2) {
#endif
        char *s_code;
        /* libcurl expects long datatype. So far no cases are known where
           it would be an issue. Using zend_long would truncate a 64-bit
           var on Win64, so the exact long datatype fits everywhere, as
           long as there's no 32-bit int overflow. */
        long l_code;
        double d_code;
#if LIBCURL_VERSION_NUM > 0x071301 /* 7.19.1 */
        struct curl_certinfo *ci = NULL;
        zval listcode;
#endif
#if LIBCURL_VERSION_NUM >= 0x073d00 /* 7.61.0 */
        curl_off_t co;
#endif

        array_init(return_value);

        if (curl_easy_getinfo(ch->cp, CURLINFO_EFFECTIVE_URL, &s_code) == CURLE_OK) {
            CAAS("url", s_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_CONTENT_TYPE, &s_code) == CURLE_OK) {
            if (s_code != NULL) {
                CAAS("content_type", s_code);
            } else {
                zval retnull;
                ZVAL_NULL(&retnull);
                CAAZ("content_type", &retnull);
            }
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_HTTP_CODE, &l_code) == CURLE_OK) {
            CAAL("http_code", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_HEADER_SIZE, &l_code) == CURLE_OK) {
            CAAL("header_size", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_REQUEST_SIZE, &l_code) == CURLE_OK) {
            CAAL("request_size", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_FILETIME, &l_code) == CURLE_OK) {
            CAAL("filetime", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SSL_VERIFYRESULT, &l_code) == CURLE_OK) {
            CAAL("ssl_verify_result", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_REDIRECT_COUNT, &l_code) == CURLE_OK) {
            CAAL("redirect_count", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_TOTAL_TIME, &d_code) == CURLE_OK) {
            CAAD("total_time", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_NAMELOOKUP_TIME, &d_code) == CURLE_OK) {
            CAAD("namelookup_time", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_CONNECT_TIME, &d_code) == CURLE_OK) {
            CAAD("connect_time", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_PRETRANSFER_TIME, &d_code) == CURLE_OK) {
            CAAD("pretransfer_time", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SIZE_UPLOAD, &d_code) == CURLE_OK) {
            CAAD("size_upload", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SIZE_DOWNLOAD, &d_code) == CURLE_OK) {
            CAAD("size_download", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SPEED_DOWNLOAD, &d_code) == CURLE_OK) {
            CAAD("speed_download", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SPEED_UPLOAD, &d_code) == CURLE_OK) {
            CAAD("speed_upload", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d_code) == CURLE_OK) {
            CAAD("download_content_length", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_CONTENT_LENGTH_UPLOAD, &d_code) == CURLE_OK) {
            CAAD("upload_content_length", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_STARTTRANSFER_TIME, &d_code) == CURLE_OK) {
            CAAD("starttransfer_time", d_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_REDIRECT_TIME, &d_code) == CURLE_OK) {
            CAAD("redirect_time", d_code);
        }
#if LIBCURL_VERSION_NUM >= 0x071202 /* Available since 7.18.2 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_REDIRECT_URL, &s_code) == CURLE_OK) {
            CAAS("redirect_url", s_code);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x071300 /* Available since 7.19.0 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_PRIMARY_IP, &s_code) == CURLE_OK) {
            CAAS("primary_ip", s_code);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_CERTINFO, &ci) == CURLE_OK) {
            array_init(&listcode);
            create_certinfo(ci, &listcode);
            CAAZ("certinfo", &listcode);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_PRIMARY_PORT, &l_code) == CURLE_OK) {
            CAAL("primary_port", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_LOCAL_IP, &s_code) == CURLE_OK) {
            CAAS("local_ip", s_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_LOCAL_PORT, &l_code) == CURLE_OK) {
            CAAL("local_port", l_code);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x073200 /* Available since 7.50.0 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_HTTP_VERSION, &l_code) == CURLE_OK) {
            CAAL("http_version", l_code);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x073400 /* Available since 7.52.0 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_PROTOCOL, &l_code) == CURLE_OK) {
            CAAL("protocol", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_PROXY_SSL_VERIFYRESULT, &l_code) == CURLE_OK) {
            CAAL("ssl_verifyresult", l_code);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_SCHEME, &s_code) == CURLE_OK) {
            CAAS("scheme", s_code);
        }
#endif
#if LIBCURL_VERSION_NUM >= 0x073d00 /* Available since 7.61.0 */
        if (curl_easy_getinfo(ch->cp, CURLINFO_APPCONNECT_TIME_T, &co) == CURLE_OK) {
            CAAL("appconnect_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_CONNECT_TIME_T, &co) == CURLE_OK) {
            CAAL("connect_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_NAMELOOKUP_TIME_T, &co) == CURLE_OK) {
            CAAL("namelookup_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_PRETRANSFER_TIME_T, &co) == CURLE_OK) {
            CAAL("pretransfer_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_REDIRECT_TIME_T, &co) == CURLE_OK) {
            CAAL("redirect_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_STARTTRANSFER_TIME_T, &co) == CURLE_OK) {
            CAAL("starttransfer_time_us", co);
        }
        if (curl_easy_getinfo(ch->cp, CURLINFO_TOTAL_TIME_T, &co) == CURLE_OK) {
            CAAL("total_time_us", co);
        }
#endif
        if (ch->header.str) {
            CAASTR("request_header", ch->header.str);
        }
    } else {
        switch (option) {
        case CURLINFO_HEADER_OUT:
            if (ch->header.str) {
                RETURN_STR_COPY(ch->header.str);
            } else {
                RETURN_FALSE;
            }
            break;
#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
        case CURLINFO_CERTINFO: {
            struct curl_certinfo *ci = NULL;

            array_init(return_value);

            if (curl_easy_getinfo(ch->cp, CURLINFO_CERTINFO, &ci) == CURLE_OK) {
                create_certinfo(ci, return_value);
            } else {
                RETURN_FALSE;
            }
            break;
        }
#endif
        case CURLINFO_PRIVATE: {
            swoole_curl_get_private_data(ch, return_value);
            return;
        }
        default: {
            int type = CURLINFO_TYPEMASK & option;
            switch (type) {
            case CURLINFO_STRING: {
                char *s_code = NULL;

                if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &s_code) == CURLE_OK && s_code) {
                    RETURN_STRING(s_code);
                } else {
                    RETURN_FALSE;
                }
                break;
            }
            case CURLINFO_LONG: {
                zend_long code = 0;

                if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &code) == CURLE_OK) {
                    RETURN_LONG(code);
                } else {
                    RETURN_FALSE;
                }
                break;
            }
            case CURLINFO_DOUBLE: {
                double code = 0.0;

                if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &code) == CURLE_OK) {
                    RETURN_DOUBLE(code);
                } else {
                    RETURN_FALSE;
                }
                break;
            }
            case CURLINFO_SLIST: {
                struct curl_slist *slist;
                if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &slist) == CURLE_OK) {
                    struct curl_slist *current = slist;
                    array_init(return_value);
                    while (current) {
                        add_next_index_string(return_value, current->data);
                        current = current->next;
                    }
                    curl_slist_free_all(slist);
                } else {
                    RETURN_FALSE;
                }
                break;
            }
#if LIBCURL_VERSION_NUM >= 0x073700 /* Available since 7.55.0 */
            case CURLINFO_OFF_T: {
                curl_off_t c_off;
                if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &c_off) == CURLE_OK) {
                    RETURN_LONG((long) c_off);
                } else {
                    RETURN_FALSE;
                }
                break;
            }
#endif
            default:
                RETURN_FALSE;
            }
        }
        }
    }
}
/* }}} */

/* {{{ proto string curl_error(resource ch)
   Return a string contain the last error for the current session */
PHP_FUNCTION(swoole_native_curl_error) {
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid, false)) == NULL) {
        RETURN_FALSE;
    }

    if (ch->err.no) {
        ch->err.str[CURL_ERROR_SIZE] = 0;
        if (strlen(ch->err.str) == 0) {
            RETURN_STRING(curl_easy_strerror((CURLcode) ch->err.no));
        }
        RETURN_STRING(ch->err.str);
    } else {
        RETURN_EMPTY_STRING();
    }
}
/* }}} */

/* {{{ proto int curl_errno(resource ch)
   Return an integer containing the last error number */
PHP_FUNCTION(swoole_native_curl_errno) {
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid, false)) == NULL) {
        RETURN_FALSE;
    }

    RETURN_LONG(ch->err.no);
}
/* }}} */

/* {{{ proto void curl_close(resource ch)
   Close a cURL session */
PHP_FUNCTION(swoole_native_curl_close) {
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    if (ch->in_callback) {
        php_error_docref(NULL, E_WARNING, "Attempt to close cURL handle from a callback");
        return;
    }

#if PHP_VERSION_ID < 80000
    zend_list_close(Z_RES_P(zid));
#endif
}
/* }}} */

static void _php_curl_free(php_curl *ch) {
    /*
     * Libcurl is doing connection caching. When easy handle is cleaned up,
     * if the handle was previously used by the curl_multi_api, the connection
     * remains open un the curl multi handle is cleaned up. Some protocols are
     * sending content like the FTP one, and libcurl try to use the
     * WRITEFUNCTION or the HEADERFUNCTION. Since structures used in those
     * callback are freed, we need to use an other callback to which avoid
     * segfaults.
     *
     * Libcurl commit d021f2e8a00 fix this issue and should be part of 7.28.2
     */
    curl_easy_setopt(ch->cp, CURLOPT_HEADERFUNCTION, curl_write_nothing);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEFUNCTION, curl_write_nothing);

    swoole::curl::Handle *handle = swoole::curl::get_handle(ch->cp);
    if (handle && handle->multi) {
        handle->multi->remove_handle(handle);
    }

    /* cURL destructors should be invoked only by last curl handle */
    if (--(*ch->clone) == 0) {
#if PHP_VERSION_ID < 80100
        zend_llist_clean(&ch->to_free->str);
#else
#if LIBCURL_VERSION_NUM < 0x073800 /* 7.56.0 */
        zend_llist_clean(&ch->to_free->buffers);
#endif
#endif
        zend_llist_clean(&ch->to_free->post);
        zend_llist_clean(&ch->to_free->stream);
        zend_hash_destroy(ch->to_free->slist);
        efree(ch->to_free->slist);
        efree(ch->to_free);
        efree(ch->clone);

        swoole::curl::destroy_handle(ch->cp);
    }

    if (ch->cp != NULL) {
        curl_easy_cleanup(ch->cp);
    }

    smart_str_free(&curl_handlers(ch)->write->buf);
    zval_ptr_dtor(&curl_handlers(ch)->write->func_name);
    zval_ptr_dtor(&curl_handlers(ch)->read->func_name);
    zval_ptr_dtor(&curl_handlers(ch)->write_header->func_name);
    zval_ptr_dtor(&curl_handlers(ch)->std_err);
    if (ch->header.str) {
        zend_string_release(ch->header.str);
    }

    zval_ptr_dtor(&curl_handlers(ch)->write_header->stream);
    zval_ptr_dtor(&curl_handlers(ch)->write->stream);
    zval_ptr_dtor(&curl_handlers(ch)->read->stream);

    efree(curl_handlers(ch)->write);
    efree(curl_handlers(ch)->write_header);
    efree(curl_handlers(ch)->read);

    if (curl_handlers(ch)->progress) {
        zval_ptr_dtor(&curl_handlers(ch)->progress->func_name);
        efree(curl_handlers(ch)->progress);
    }

#if LIBCURL_VERSION_NUM >= 0x071500
    if (curl_handlers(ch)->fnmatch) {
        zval_ptr_dtor(&curl_handlers(ch)->fnmatch->func_name);
        efree(curl_handlers(ch)->fnmatch);
    }
#endif

#if PHP_VERSION_ID < 80100
    efree(ch->handlers);
#endif
    zval_ptr_dtor(&ch->postfields);
#if PHP_VERSION_ID >= 80100 || PHP_VERSION_ID < 80000
    zval_ptr_dtor(&ch->private_data);
#endif

#if PHP_VERSION_ID >= 80000
    if (ch->share) {
        OBJ_RELEASE(&ch->share->std);
    }
#endif
}

#if PHP_VERSION_ID >= 80000
static void swoole_curl_free_obj(zend_object *object) {
    php_curl *ch = curl_from_obj(object);

#if PHP_CURL_DEBUG
    fprintf(stderr, "DTOR CALLED, ch = %x\n", ch);
#endif

    if (!ch->cp) {
        /* Can happen if constructor throws. */
        zend_object_std_dtor(&ch->std);
        return;
    }

    swoole_curl_verify_handlers(ch, 0);
    _php_curl_free(ch);

    zend_object_std_dtor(&ch->std);
}
#endif

#if PHP_VERSION_ID < 80000
/* {{{ _php_curl_close_ex()
   List destructor for curl handles */
void swoole_curl_close_ex(php_curl *ch) {
#if PHP_CURL_DEBUG
    fprintf(stderr, "DTOR CALLED, ch = %x\n", ch);
#endif

    swoole_curl_verify_handlers(ch, 0);
    _php_curl_free(ch);
    efree(ch);
}
/* }}} */

/* {{{ _php_curl_close()
   List destructor for curl handles */
void swoole_curl_close(zend_resource *rsrc) {
    php_curl *ch = (php_curl *) rsrc->ptr;
    swoole_curl_close_ex(ch);
}
#endif
/* }}} */

/* {{{ _php_curl_reset_handlers()
   Reset all handlers of a given php_curl */
static void _php_curl_reset_handlers(php_curl *ch) {
    if (!Z_ISUNDEF(curl_handlers(ch)->write->stream)) {
        zval_ptr_dtor(&curl_handlers(ch)->write->stream);
        ZVAL_UNDEF(&curl_handlers(ch)->write->stream);
    }
    curl_handlers(ch)->write->fp = NULL;
    curl_handlers(ch)->write->method = PHP_CURL_STDOUT;

    if (!Z_ISUNDEF(curl_handlers(ch)->write_header->stream)) {
        zval_ptr_dtor(&curl_handlers(ch)->write_header->stream);
        ZVAL_UNDEF(&curl_handlers(ch)->write_header->stream);
    }
    curl_handlers(ch)->write_header->fp = NULL;
    curl_handlers(ch)->write_header->method = PHP_CURL_IGNORE;

    if (!Z_ISUNDEF(curl_handlers(ch)->read->stream)) {
        zval_ptr_dtor(&curl_handlers(ch)->read->stream);
        ZVAL_UNDEF(&curl_handlers(ch)->read->stream);
    }
    curl_handlers(ch)->read->fp = NULL;
    curl_handlers(ch)->read->res = NULL;
    curl_handlers(ch)->read->method = PHP_CURL_DIRECT;

    if (!Z_ISUNDEF(curl_handlers(ch)->std_err)) {
        zval_ptr_dtor(&curl_handlers(ch)->std_err);
        ZVAL_UNDEF(&curl_handlers(ch)->std_err);
    }

    if (curl_handlers(ch)->progress) {
        zval_ptr_dtor(&curl_handlers(ch)->progress->func_name);
        efree(curl_handlers(ch)->progress);
        curl_handlers(ch)->progress = NULL;
    }

#if LIBCURL_VERSION_NUM >= 0x072000 && PHP_VERSION_ID >= 80200
    if (curl_handlers(ch)->xferinfo) {
        zval_ptr_dtor(&curl_handlers(ch)->xferinfo->func_name);
        efree(curl_handlers(ch)->xferinfo);
        curl_handlers(ch)->xferinfo = NULL;
    }
#endif

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    if (curl_handlers(ch)->fnmatch) {
        zval_ptr_dtor(&curl_handlers(ch)->fnmatch->func_name);
        efree(curl_handlers(ch)->fnmatch);
        curl_handlers(ch)->fnmatch = NULL;
    }
#endif
}
/* }}} */

/* {{{ proto void curl_reset(resource ch)
   Reset all options of a libcurl session handle */
PHP_FUNCTION(swoole_native_curl_reset) {
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    if (ch->in_callback) {
        php_error_docref(NULL, E_WARNING, "Attempt to reset cURL handle from a callback");
        return;
    }

    curl_easy_reset(ch->cp);
    _php_curl_reset_handlers(ch);
    _php_curl_set_default_options(ch);
}
/* }}} */

/* {{{ proto void curl_escape(resource ch, string str)
   URL encodes the given string */
PHP_FUNCTION(swoole_native_curl_escape) {
    zend_string *str;
    char *res;
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(2, 2)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    if (ZEND_SIZE_T_INT_OVFL(ZSTR_LEN(str))) {
        RETURN_FALSE;
    }

    if ((res = curl_easy_escape(ch->cp, ZSTR_VAL(str), ZSTR_LEN(str)))) {
        RETVAL_STRING(res);
        curl_free(res);
    } else {
        RETURN_FALSE;
    }
}
/* }}} */

/* {{{ proto void curl_unescape(resource ch, string str)
   URL decodes the given string */
PHP_FUNCTION(swoole_native_curl_unescape) {
    char *out = NULL;
    int out_len;
    zval *zid;
    zend_string *str;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(2, 2)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

#if PHP_VERSION_ID >= 80000
    ch = Z_CURL_P(zid);
#else
    if ((ch = (php_curl *) zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }
#endif

    if (ZEND_SIZE_T_INT_OVFL(ZSTR_LEN(str))) {
        RETURN_FALSE;
    }

    if ((out = curl_easy_unescape(ch->cp, ZSTR_VAL(str), ZSTR_LEN(str), &out_len))) {
        RETVAL_STRINGL(out, out_len);
        curl_free(out);
    } else {
        RETURN_FALSE;
    }
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
/* {{{ proto void curl_pause(resource ch, int bitmask)
       pause and unpause a connection */
PHP_FUNCTION(swoole_native_curl_pause) {
    zend_long bitmask;
    zval *zid;
    php_curl *ch;

    ZEND_PARSE_PARAMETERS_START(2, 2)
#if PHP_VERSION_ID >= 80000
    Z_PARAM_OBJECT_OF_CLASS(zid, swoole_coroutine_curl_handle_ce)
#else
    Z_PARAM_RESOURCE(zid)
#endif
    Z_PARAM_LONG(bitmask)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = swoole_curl_get_handle(zid)) == NULL) {
        RETURN_FALSE;
    }

    RETURN_LONG(curl_easy_pause(ch->cp, bitmask));
}
/* }}} */
#endif
#endif
