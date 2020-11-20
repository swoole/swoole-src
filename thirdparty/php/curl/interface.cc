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
   +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
#include "swoole_util.h"

using swoole::network::Socket;
using namespace swoole;

SW_EXTERN_C_BEGIN

#include <stdio.h>
#include <string.h>

#ifdef PHP_WIN32
#include <winsock2.h>
#include <sys/types.h>
#endif

#include <curl/curl.h>
#include <curl/easy.h>

/* As of curl 7.11.1 this is no longer defined inside curl.h */
#ifndef HttpPost
#define HttpPost curl_httppost
#endif

/* {{{ cruft for thread safe SSL crypto locks */
#if defined(ZTS) && defined(HAVE_CURL_SSL)
# ifdef PHP_WIN32
#  define PHP_CURL_NEED_OPENSSL_TSL
#  include <openssl/crypto.h>
# else /* !PHP_WIN32 */
#  if defined(HAVE_CURL_OPENSSL)
#   if defined(HAVE_OPENSSL_CRYPTO_H)
#    define PHP_CURL_NEED_OPENSSL_TSL
#    include <openssl/crypto.h>
#   else
#    warning \
    "libcurl was compiled with OpenSSL support, but configure could not find " \
    "openssl/crypto.h; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#   endif
#  elif defined(HAVE_CURL_GNUTLS)
#   if defined(HAVE_GCRYPT_H)
#    define PHP_CURL_NEED_GNUTLS_TSL
#    include <gcrypt.h>
#   else
#    warning \
    "libcurl was compiled with GnuTLS support, but configure could not find " \
    "gcrypt.h; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#   endif
#  else
#   warning \
    "libcurl was compiled with SSL support, but configure could not determine which" \
    "library was used; thus no SSL crypto locking callbacks will be set, which may " \
    "cause random crashes on SSL requests"
#  endif /* HAVE_CURL_OPENSSL || HAVE_CURL_GNUTLS */
# endif /* PHP_WIN32 */
#endif /* ZTS && HAVE_CURL_SSL */
/* }}} */

#define SMART_STR_PREALLOC 4096

#include "zend_smart_str.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "ext/standard/url.h"
#include "php_curl.h"

static int le_curl;

static void _php_curl_close_ex(php_curl *ch);
static void _php_curl_close(zend_resource *rsrc);

#define SAVE_CURL_ERROR(__handle, __err) (__handle)->err.no = (int) __err;

#define CAAL(s, v) add_assoc_long_ex(return_value, s, sizeof(s) - 1, (zend_long) v);
#define CAAD(s, v) add_assoc_double_ex(return_value, s, sizeof(s) - 1, (double) v);
#define CAAS(s, v) add_assoc_string_ex(return_value, s, sizeof(s) - 1, (char *) (v ? v : ""));
#define CAASTR(s, v) add_assoc_str_ex(return_value, s, sizeof(s) - 1, \
        v ? zend_string_copy(v) : ZSTR_EMPTY_ALLOC());
#define CAAZ(s, v) add_assoc_zval_ex(return_value, s, sizeof(s) -1 , (zval *) v);

#if defined(PHP_WIN32) || defined(__GNUC__)
# define php_curl_ret(__ret) RETVAL_FALSE; return __ret;
#else
# define php_curl_ret(__ret) RETVAL_FALSE; return;
#endif

namespace swoole {
class cURLMulti {
    CURLM *handle;
    TimerNode *timer;

    void read_info();

    Socket *create_socket(curl_socket_t sockfd) {
        if (!swoole_event_isset_handler(PHP_SWOOLE_FD_CO_CURL)) {
            swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_READ, cb_readable);
            swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_WRITE, cb_writable);
        }
        Socket *socket = new Socket();
        socket->fd = sockfd;
        socket->fd_type = (enum swFd_type) PHP_SWOOLE_FD_CO_CURL;
        curl_multi_assign(handle, sockfd, (void*) socket);
        return socket;
    }

 public:
    cURLMulti() {
        handle = curl_multi_init();
        curl_multi_setopt(handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
        curl_multi_setopt(handle, CURLMOPT_TIMERFUNCTION, handle_timeout);
        timer = nullptr;
    }

    bool add(CURL *cp) {
        return curl_multi_add_handle(handle, cp) == CURLM_OK;
    }

    void add_timer(long timeout_ms) {
       timer = swoole_timer_add(timeout_ms, false, [this](Timer *timer, TimerNode *tnode) {
            socket_action(CURL_SOCKET_TIMEOUT, 0);
            read_info();
        });
    }

    void del_timer() {
        if (timer) {
            swoole_timer_del(timer);
        }
    }

    void set_event(void *socket_ptr, curl_socket_t sockfd, int action) {
        Socket *socket = socket_ptr ? (Socket*) socket_ptr : create_socket(sockfd);
        int events = 0;
        if (action != CURL_POLL_IN) {
            events |= SW_EVENT_WRITE;
        }
        if (action != CURL_POLL_OUT) {
            events |= SW_EVENT_READ;
        }
        if (socket->events) {
            swoole_event_set(socket, events);
        } else {
            swoole_event_add(socket, events);
        }
    }

    void del_event(void *socket_ptr, curl_socket_t sockfd) {
        Socket *socket = (Socket*) socket_ptr;
        swoole_event_del(socket);
        socket->fd = -1;
        socket->free();
        curl_multi_assign(handle, sockfd, NULL);
    }

    void socket_action(int fd, int type) {
        int running_handles;
        curl_multi_socket_action(handle, fd, CURL_CSELECT_IN, &running_handles);
        read_info();
    }

    static int cb_readable(Reactor *reactor, Event *event);
    static int cb_writable(Reactor *reactor, Event *event);
    static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp);
    static int handle_timeout(CURLM *multi, long timeout_ms, void *userp);
};
}

static int php_curl_option_str(php_curl *ch, zend_long option, const char *str, const size_t len, zend_bool make_copy)
{
    long error = CURLE_OK;

    if (strlen(str) != len) {
        php_error_docref(NULL, E_WARNING, "Curl option contains invalid characters (\\0)");
        return FAILURE;
    }

#if LIBCURL_VERSION_NUM >= 0x071100
    if (make_copy) {
#endif
        char *copystr;

        /* Strings passed to libcurl as 'char *' arguments, are copied by the library since 7.17.0 */
        copystr = estrndup(str, len);
        error = curl_easy_setopt(ch->cp, (CURLoption)option, copystr);
        zend_llist_add_element(&ch->to_free->str, &copystr);
#if LIBCURL_VERSION_NUM >= 0x071100
    } else {
        error = curl_easy_setopt(ch->cp, (CURLoption)option, str);
    }
#endif

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

#if LIBCURL_VERSION_NUM > 0x073800 && defined(PHP_WIN32)
    if (len > sizeof("file://") - 1 && '/' != url[sizeof("file://") - 1] && !strncmp("file://", url, sizeof("file://") - 1) && len < MAXPATHLEN - 2) {
        char _tmp[MAXPATHLEN] = {0};

        memmove(_tmp, "file:///", sizeof("file:///") - 1);
        memmove(_tmp + sizeof("file:///") - 1, url + sizeof("file://") - 1, len - sizeof("file://") + 1);

        return php_curl_option_str(ch, CURLOPT_URL, _tmp, len + 1, 0);
    }
#endif

    return php_curl_option_str(ch, CURLOPT_URL, url, len, 0);
}
/* }}} */

void _php_curl_verify_handlers(php_curl *ch, int reporterror) /* {{{ */
{
    php_stream *stream;

    ZEND_ASSERT(ch && ch->handlers);

    if (!Z_ISUNDEF(ch->handlers->std_err)) {
        stream = (php_stream *)zend_fetch_resource2_ex(&ch->handlers->std_err, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_STDERR resource has gone away, resetting to stderr");
            }
            zval_ptr_dtor(&ch->handlers->std_err);
            ZVAL_UNDEF(&ch->handlers->std_err);

            curl_easy_setopt(ch->cp, CURLOPT_STDERR, stderr);
        }
    }
    if (ch->handlers->read && !Z_ISUNDEF(ch->handlers->read->stream)) {
        stream = (php_stream *)zend_fetch_resource2_ex(&ch->handlers->read->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_INFILE resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&ch->handlers->read->stream);
            ZVAL_UNDEF(&ch->handlers->read->stream);
            ch->handlers->read->res = NULL;
            ch->handlers->read->fp = 0;

            curl_easy_setopt(ch->cp, CURLOPT_INFILE, (void *) ch);
        }
    }
    if (ch->handlers->write_header && !Z_ISUNDEF(ch->handlers->write_header->stream)) {
        stream = (php_stream *)zend_fetch_resource2_ex(&ch->handlers->write_header->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_WRITEHEADER resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&ch->handlers->write_header->stream);
            ZVAL_UNDEF(&ch->handlers->write_header->stream);
            ch->handlers->write_header->fp = 0;

            ch->handlers->write_header->method = PHP_CURL_IGNORE;
            curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER, (void *) ch);
        }
    }
    if (ch->handlers->write && !Z_ISUNDEF(ch->handlers->write->stream)) {
        stream = (php_stream *)zend_fetch_resource2_ex(&ch->handlers->write->stream, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream == NULL) {
            if (reporterror) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_FILE resource has gone away, resetting to default");
            }
            zval_ptr_dtor(&ch->handlers->write->stream);
            ZVAL_UNDEF(&ch->handlers->write->stream);
            ch->handlers->write->fp = 0;

            ch->handlers->write->method = PHP_CURL_STDOUT;
            curl_easy_setopt(ch->cp, CURLOPT_FILE, (void *) ch);
        }
    }
    return;
}
/* }}} */


static cURLMulti *g_curl_multi = nullptr;

static inline cURLMulti *sw_curl_multi() {
    return g_curl_multi;
}

int cURLMulti::cb_readable(Reactor *reactor, Event *event) {
    sw_curl_multi()->socket_action(event->fd, CURL_CSELECT_IN);
    return 0;
}

int cURLMulti::cb_writable(Reactor *reactor, Event *event) {
    sw_curl_multi()->socket_action(event->fd, CURL_CSELECT_OUT);
    return 0;
}

int cURLMulti::handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
    switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
        sw_curl_multi()->set_event(socketp, s, action);
        break;
    case CURL_POLL_REMOVE:
        if (socketp) {
            sw_curl_multi()->del_event(socketp, s);
        }
        break;
    default:
        abort();
    }
    return 0;
}

void cURLMulti::read_info() {
    CURLMsg *message;
    int pending;
    CURL *easy_handle;

    while ((message = curl_multi_info_read(handle, &pending))) {
        switch (message->msg) {
        case CURLMSG_DONE:
            /* Do not use message data after calling curl_multi_remove_handle() and
             curl_easy_cleanup(). As per curl_multi_info_read() docs:
             "WARNING: The data the returned pointer points to will not survive
             calling curl_multi_cleanup, curl_multi_remove_handle or
             curl_easy_cleanup." */
            easy_handle = message->easy_handle;
            curl_multi_remove_handle(handle, easy_handle);
            php_curl *ch;
            curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &ch);
            zval result;
            ZVAL_LONG(&result, message->data.result);
            ch->callback = nullptr;
            PHPCoroutine::resume_m(ch->context, &result);
            break;
        default:
            swWarn("CURLMSG default");
            break;
        }
    }
}

int cURLMulti::handle_timeout(CURLM *multi, long timeout_ms, void *userp) {
    if (timeout_ms < 0) {
        sw_curl_multi()->del_timer();
    } else {
        if (timeout_ms == 0) {
            timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it in a bit */
        }
        sw_curl_multi()->add_timer(timeout_ms);
    }
    return 0;
}

void swoole_native_curl_init(int module_number)
{
    swSSL_init();
    le_curl = zend_register_list_destructors_ex(_php_curl_close, NULL, le_curl_name, module_number);
    g_curl_multi = new cURLMulti();
}

void swoole_native_curl_rshutdown() {
    delete g_curl_multi;
    g_curl_multi = nullptr;
}


/* {{{ curl_write_nothing
 * Used as a work around. See _php_curl_close_ex
 */
static size_t fn_write_nothing(char *data, size_t size, size_t nmemb, void *ctx)
{
    return size * nmemb;
}
/* }}} */

/* {{{ curl_write
 */
static size_t fn_write(char *data, size_t size, size_t nmemb, void *ctx)
{
    php_curl *ch = (php_curl *) ctx;
    php_curl_write *t = ch->handlers->write;
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
            std::function<bool(void)> fn = [&]() -> bool {
                zval argv[2];
                zval retval;
                int  error;
                zend_fcall_info fci;

                GC_ADDREF(ch->res);
        ZVAL_RES(&argv[0], ch->res);
                ZVAL_STRINGL(&argv[1], data, length);

                fci.size = sizeof(fci);
                fci.object = NULL;
                ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
                fci.retval = &retval;
                fci.param_count = 2;
                fci.params = argv;
                fci.no_separation = 0;

                ch->in_callback = 1;
                error = zend_call_function(&fci, &t->fci_cache);
                ch->in_callback = 0;
                if (error == FAILURE) {
                    php_error_docref(NULL, E_WARNING, "Could not call the CURLOPT_WRITEFUNCTION");
                    length = -1;
                } else if (!Z_ISUNDEF(retval)) {
                    _php_curl_verify_handlers(ch, 1);
                    length = zval_get_long(&retval);
                }

                zval_ptr_dtor(&argv[0]);
                zval_ptr_dtor(&argv[1]);
                return true;
            };

            zval result;
            ZVAL_NULL(&result);
            ch->callback = &fn;
            PHPCoroutine::resume_m(ch->context, &result);
            break;
        }
    }

    return length;
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
/* {{{ curl_fnmatch
 */
static int fn_fnmatch(void *ctx, const char *pattern, const char *string)
{
    php_curl *ch = (php_curl *) ctx;
    php_curl_fnmatch *t = ch->handlers->fnmatch;
    int rval = CURL_FNMATCHFUNC_FAIL;
    switch (t->method) {
    case PHP_CURL_USER: {
        std::function<bool(void)> fn = [&]() -> bool {
            zval argv[3];
            zval retval;
            int error;
            zend_fcall_info fci;

            GC_ADDREF(ch->res);
            ZVAL_RES(&argv[0], ch->res);
            ZVAL_STRING(&argv[1], pattern);
            ZVAL_STRING(&argv[2], string);

            fci.size = sizeof(fci);
            ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
            fci.object = NULL;
            fci.retval = &retval;
            fci.param_count = 3;
            fci.params = argv;
            fci.no_separation = 0;

            ch->in_callback = 1;
            error = zend_call_function(&fci, &t->fci_cache);
            ch->in_callback = 0;
            if (error == FAILURE) {
                php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_FNMATCH_FUNCTION");
            } else if (!Z_ISUNDEF(retval)) {
                _php_curl_verify_handlers(ch, 1);
                rval = zval_get_long(&retval);
            }
            zval_ptr_dtor(&argv[0]);
            zval_ptr_dtor(&argv[1]);
            zval_ptr_dtor(&argv[2]);
            return true;
        };

        zval result;
        ZVAL_NULL(&result);
        ch->callback = &fn;
        PHPCoroutine::resume_m(ch->context, &result);
        break;
    }
    }
    return rval;
}
/* }}} */
#endif

/* {{{ curl_progress
 */
static size_t fn_progress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
    php_curl *ch = (php_curl *)clientp;
    php_curl_progress *t = ch->handlers->progress;
    size_t	rval = 0;

#if PHP_CURL_DEBUG
    fprintf(stderr, "curl_progress() called\n");
    fprintf(stderr, "clientp = %x, dltotal = %f, dlnow = %f, ultotal = %f, ulnow = %f\n", clientp, dltotal, dlnow, ultotal, ulnow);
#endif

    switch (t->method) {
    case PHP_CURL_USER: {
        std::function<bool(void)> fn = [&]() -> bool {
            zval argv[5];
            zval retval;
            int  error;
            zend_fcall_info fci;

            GC_ADDREF(ch->res);
            ZVAL_RES(&argv[0], ch->res);
            ZVAL_LONG(&argv[1], (zend_long)dltotal);
            ZVAL_LONG(&argv[2], (zend_long)dlnow);
            ZVAL_LONG(&argv[3], (zend_long)ultotal);
            ZVAL_LONG(&argv[4], (zend_long)ulnow);

            fci.size = sizeof(fci);
            ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
            fci.object = NULL;
            fci.retval = &retval;
            fci.param_count = 5;
            fci.params = argv;
            fci.no_separation = 0;

            ch->in_callback = 1;
            error = zend_call_function(&fci, &t->fci_cache);
            ch->in_callback = 0;
            if (error == FAILURE) {
                php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_PROGRESSFUNCTION");
            } else if (!Z_ISUNDEF(retval)) {
                _php_curl_verify_handlers(ch, 1);
                if (0 != zval_get_long(&retval)) {
                    rval = 1;
                }
            }
            zval_ptr_dtor(&argv[0]);

            return true;
        };

        zval result;
        ZVAL_NULL(&result);
        ch->callback = &fn;
        PHPCoroutine::resume_m(ch->context, &result);
        break;
    }
    }
    return rval;
}
/* }}} */

/* {{{ curl_read
 */
static size_t fn_read(char *data, size_t size, size_t nmemb, void *ctx)
{
    php_curl *ch = (php_curl *)ctx;
    php_curl_read *t = ch->handlers->read;
    int length = 0;

    switch (t->method) {
    case PHP_CURL_DIRECT:
        if (t->fp) {
            length = fread(data, size, nmemb, t->fp);
        }
        break;
    case PHP_CURL_USER: {
        std::function<bool(void)> fn = [&]() -> bool {
            zval argv[3];
            zval retval;
            int error;
            zend_fcall_info fci;

            GC_ADDREF(ch->res);
            ZVAL_RES(&argv[0], ch->res);
            if (t->res) {
                GC_ADDREF(t->res);
                ZVAL_RES(&argv[1], t->res);
            } else {
                ZVAL_NULL(&argv[1]);
            }
            ZVAL_LONG(&argv[2], (int )size * nmemb);

            fci.size = sizeof(fci);
            ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
            fci.object = NULL;
            fci.retval = &retval;
            fci.param_count = 3;
            fci.params = argv;
            fci.no_separation = 0;

            ch->in_callback = 1;
            error = zend_call_function(&fci, &t->fci_cache);
            ch->in_callback = 0;
            if (error == FAILURE) {
                php_error_docref(NULL, E_WARNING, "Cannot call the CURLOPT_READFUNCTION");
#if LIBCURL_VERSION_NUM >= 0x070c01 /* 7.12.1 */
                length = CURL_READFUNC_ABORT;
#endif
            } else if (!Z_ISUNDEF(retval)) {
                _php_curl_verify_handlers(ch, 1);
                if (Z_TYPE(retval) == IS_STRING) {
                    length = MIN((int ) (size * nmemb), Z_STRLEN(retval));
                    memcpy(data, Z_STRVAL(retval), length);
                }
                zval_ptr_dtor(&retval);
            }

            zval_ptr_dtor(&argv[0]);
            zval_ptr_dtor(&argv[1]);
            zval_ptr_dtor(&argv[2]);

            return true;
        };

        zval result;
        ZVAL_NULL(&result);
        ch->callback = &fn;
        PHPCoroutine::resume_m(ch->context, &result);
        break;
    }
    }

    return length;
}
/* }}} */

/* {{{ curl_write_header
 */
static size_t fn_write_header(char *data, size_t size, size_t nmemb, void *ctx)
{
    php_curl *ch = (php_curl *) ctx;
    php_curl_write *t = ch->handlers->write_header;
    size_t length = size * nmemb;

    switch (t->method) {
        case PHP_CURL_STDOUT:
            // Handle special case write when we're returning the entire transfer
            if (ch->handlers->write->method == PHP_CURL_RETURN && length > 0) {
                smart_str_appendl(&ch->handlers->write->buf, data, (int) length);
            } else {
                PHPWRITE(data, length);
            }
            break;
        case PHP_CURL_FILE:
            return fwrite(data, size, nmemb, t->fp);
        case PHP_CURL_USER: {
            std::function<bool(void)> fn = [&]() -> bool {
                zval argv[2];
                zval retval;
                int  error;
                zend_fcall_info fci;

                ZVAL_RES(&argv[0], ch->res);
                Z_ADDREF(argv[0]);
                ZVAL_STRINGL(&argv[1], data, length);

                fci.size = sizeof(fci);
                ZVAL_COPY_VALUE(&fci.function_name, &t->func_name);
                fci.object = NULL;
                fci.retval = &retval;
                fci.param_count = 2;
                fci.params = argv;
                fci.no_separation = 0;

                ch->in_callback = 1;
                error = zend_call_function(&fci, &t->fci_cache);
                ch->in_callback = 0;
                if (error == FAILURE) {
                    php_error_docref(NULL, E_WARNING, "Could not call the CURLOPT_HEADERFUNCTION");
                    length = -1;
                } else if (!Z_ISUNDEF(retval)) {
                    _php_curl_verify_handlers(ch, 1);
                    length = zval_get_long(&retval);
                }
                zval_ptr_dtor(&argv[0]);
                zval_ptr_dtor(&argv[1]);

                return true;
            };

            zval result;
            ZVAL_NULL(&result);
            ch->callback = &fn;
            PHPCoroutine::resume_m(ch->context, &result);
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

static int curl_debug(CURL *cp, curl_infotype type, char *buf, size_t buf_len, void *ctx) /* {{{ */
{
    php_curl *ch = (php_curl *)ctx;

    if (type == CURLINFO_HEADER_OUT) {
        if (ch->header.str) {
            zend_string_release_ex(ch->header.str, 0);
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
static void curl_free_string(void **string)
{
    efree((char *)*string);
}
/* }}} */

/* {{{ curl_free_post
 */
static void curl_free_post(void **post)
{
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    curl_mime_free((curl_mime *)*post);
#else
    curl_formfree((struct HttpPost *)*post);
#endif
}
/* }}} */

struct mime_data_cb_arg {
    zend_string *filename;
    php_stream *stream;
};

/* {{{ curl_free_cb_arg
 */
static void curl_free_cb_arg(void **cb_arg_p)
{
    struct mime_data_cb_arg *cb_arg = (struct mime_data_cb_arg *) *cb_arg_p;

    ZEND_ASSERT(cb_arg->stream == NULL);
    zend_string_release(cb_arg->filename);
    efree(cb_arg);
}
/* }}} */

/* {{{ curl_free_slist
 */
static void curl_free_slist(zval *el)
{
    curl_slist_free_all(((struct curl_slist *)Z_PTR_P(el)));
}
/* }}} */

php_curl *curl_alloc_handle()
{
    php_curl *ch               = (php_curl *)ecalloc(1, sizeof(php_curl));
    ch->to_free                = (struct _php_curl_free *)ecalloc(1, sizeof(struct _php_curl_free));
    ch->handlers               = (php_curl_handlers *)ecalloc(1, sizeof(php_curl_handlers));
    ch->handlers->write        = (php_curl_write *)ecalloc(1, sizeof(php_curl_write));
    ch->handlers->write_header = (php_curl_write *)ecalloc(1, sizeof(php_curl_write));
    ch->handlers->read         = (php_curl_read *)ecalloc(1, sizeof(php_curl_read));
    ch->handlers->progress     = NULL;
#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    ch->handlers->fnmatch      = NULL;
#endif
    ch->clone 				   = (uint32_t *)emalloc(sizeof(uint32_t));
    *ch->clone                 = 1;

    memset(&ch->err, 0, sizeof(struct _php_curl_error));

    zend_llist_init(&ch->to_free->str,   sizeof(char *),          (llist_dtor_func_t)curl_free_string, 0);
    zend_llist_init(&ch->to_free->post,  sizeof(struct HttpPost *), (llist_dtor_func_t)curl_free_post,   0);
    zend_llist_init(&ch->to_free->stream, sizeof(struct mime_data_cb_arg *), (llist_dtor_func_t)curl_free_cb_arg, 0);

    ch->to_free->slist = (HashTable *) emalloc(sizeof(HashTable));
    zend_hash_init(ch->to_free->slist, 4, NULL, curl_free_slist, 0);
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    ZVAL_UNDEF(&ch->postfields);
#endif
    return ch;
}
/* }}} */

#if LIBCURL_VERSION_NUM >= 0x071301 /* Available since 7.19.1 */
/* {{{ create_certinfo
 */
static void create_certinfo(struct curl_certinfo *ci, zval *listcode)
{
    int i;

    if (ci) {
        zval certhash;

        for (i=0; i<ci->num_of_certs; i++) {
            struct curl_slist *slist;

            array_init(&certhash);
            for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                int len;
                char s[64];
                char *tmp;
                strncpy(s, slist->data, sizeof(s));
                s[sizeof(s)-1] = '\0';
                tmp = (char *)memchr(s, ':', sizeof(s));
                if(tmp) {
                    *tmp = '\0';
                    len = strlen(s);
                    add_assoc_string(&certhash, s, &slist->data[len+1]);
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
static void _php_curl_set_default_options(php_curl *ch)
{
    const char *cainfo;

    curl_easy_setopt(ch->cp, CURLOPT_NOPROGRESS,        1);
    curl_easy_setopt(ch->cp, CURLOPT_VERBOSE,           0);
    curl_easy_setopt(ch->cp, CURLOPT_ERRORBUFFER,       ch->err.str);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEFUNCTION,     fn_write);
    curl_easy_setopt(ch->cp, CURLOPT_FILE,              (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_READFUNCTION,      fn_read);
    curl_easy_setopt(ch->cp, CURLOPT_INFILE,            (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_HEADERFUNCTION,    fn_write_header);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER,       (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_PRIVATE, ch);

#if !defined(ZTS)
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
PHP_FUNCTION(swoole_native_curl_init)
{
    php_curl *ch;
    CURL 	 *cp;
    zend_string *url = NULL;

    ZEND_PARSE_PARAMETERS_START(0,1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(url)
    ZEND_PARSE_PARAMETERS_END();

    cp = curl_easy_init();
    if (!cp) {
        php_error_docref(NULL, E_WARNING, "Could not initialize a new cURL handle");
        RETURN_FALSE;
    }

    ch = curl_alloc_handle();

    ch->cp = cp;

    ch->handlers->write->method = PHP_CURL_STDOUT;
    ch->handlers->read->method  = PHP_CURL_DIRECT;
    ch->handlers->write_header->method = PHP_CURL_IGNORE;

    _php_curl_set_default_options(ch);

    if (url) {
        if (php_curl_option_url(ch, ZSTR_VAL(url), ZSTR_LEN(url)) == FAILURE) {
            _php_curl_close_ex(ch);
            RETURN_FALSE;
        }
    }

    ZVAL_RES(return_value, zend_register_resource(ch, le_curl));
    ch->res = Z_RES_P(return_value);
}
/* }}} */

void _php_setup_easy_copy_handlers(php_curl *ch, php_curl *source)
{
    if (!Z_ISUNDEF(source->handlers->write->stream)) {
        Z_ADDREF(source->handlers->write->stream);
    }
    ch->handlers->write->stream = source->handlers->write->stream;
    ch->handlers->write->method = source->handlers->write->method;
    if (!Z_ISUNDEF(source->handlers->read->stream)) {
        Z_ADDREF(source->handlers->read->stream);
    }
    ch->handlers->read->stream  = source->handlers->read->stream;
    ch->handlers->read->method  = source->handlers->read->method;
    ch->handlers->write_header->method = source->handlers->write_header->method;
    if (!Z_ISUNDEF(source->handlers->write_header->stream)) {
        Z_ADDREF(source->handlers->write_header->stream);
    }
    ch->handlers->write_header->stream = source->handlers->write_header->stream;

    ch->handlers->write->fp = source->handlers->write->fp;
    ch->handlers->write_header->fp = source->handlers->write_header->fp;
    ch->handlers->read->fp = source->handlers->read->fp;
    ch->handlers->read->res = source->handlers->read->res;
#if CURLOPT_PASSWDDATA != 0
    if (!Z_ISUNDEF(source->handlers->passwd)) {
        ZVAL_COPY(&ch->handlers->passwd, &source->handlers->passwd);
        curl_easy_setopt(source->cp, CURLOPT_PASSWDDATA, (void *) ch);
    }
#endif
    if (!Z_ISUNDEF(source->handlers->write->func_name)) {
        ZVAL_COPY(&ch->handlers->write->func_name, &source->handlers->write->func_name);
    }
    if (!Z_ISUNDEF(source->handlers->read->func_name)) {
        ZVAL_COPY(&ch->handlers->read->func_name, &source->handlers->read->func_name);
    }
    if (!Z_ISUNDEF(source->handlers->write_header->func_name)) {
        ZVAL_COPY(&ch->handlers->write_header->func_name, &source->handlers->write_header->func_name);
    }

    curl_easy_setopt(ch->cp, CURLOPT_ERRORBUFFER,       ch->err.str);
    curl_easy_setopt(ch->cp, CURLOPT_FILE,              (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_INFILE,            (void *) ch);
    curl_easy_setopt(ch->cp, CURLOPT_WRITEHEADER,       (void *) ch);

    if (source->handlers->progress) {
        ch->handlers->progress = (php_curl_progress *)ecalloc(1, sizeof(php_curl_progress));
        if (!Z_ISUNDEF(source->handlers->progress->func_name)) {
            ZVAL_COPY(&ch->handlers->progress->func_name, &source->handlers->progress->func_name);
        }
        ch->handlers->progress->method = source->handlers->progress->method;
        curl_easy_setopt(ch->cp, CURLOPT_PROGRESSDATA, (void *) ch);
    }

#if LIBCURL_VERSION_NUM >= 0x071500
    if (source->handlers->fnmatch) {
        ch->handlers->fnmatch = (php_curl_fnmatch *)ecalloc(1, sizeof(php_curl_fnmatch));
        if (!Z_ISUNDEF(source->handlers->fnmatch->func_name)) {
            ZVAL_COPY(&ch->handlers->fnmatch->func_name, &source->handlers->fnmatch->func_name);
        }
        ch->handlers->fnmatch->method = source->handlers->fnmatch->method;
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


#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
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
    HashTable *postfields;
    zend_string *string_key;
    zend_ulong num_key;
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    curl_mime *mime = NULL;
    curl_mimepart *part;
    CURLcode form_error;
#else
    struct HttpPost *first = NULL;
    struct HttpPost *last  = NULL;
    CURLFORMcode form_error;
#endif

    postfields = HASH_OF(zpostfields);
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

    ZEND_HASH_FOREACH_KEY_VAL_IND(postfields, num_key, string_key, current) {
        zend_string *postval, *tmp_postval;
        /* Pretend we have a string_key here */
        if (!string_key) {
            string_key = zend_long_to_str(num_key);
        } else {
            zend_string_addref(string_key);
        }

        ZVAL_DEREF(current);
        if (Z_TYPE_P(current) == IS_OBJECT &&
                instanceof_function(Z_OBJCE_P(current), curl_CURLFile_class)) {
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

            prop = zend_read_property(curl_CURLFile_class, current, "name", sizeof("name")-1, 0, &rv);
            if (Z_TYPE_P(prop) != IS_STRING) {
                php_error_docref(NULL, E_WARNING, "Invalid filename for key %s", ZSTR_VAL(string_key));
            } else {
                postval = Z_STR_P(prop);

                if (php_check_open_basedir(ZSTR_VAL(postval))) {
                    return 1;
                }

                prop = zend_read_property(curl_CURLFile_class, current, "mime", sizeof("mime")-1, 0, &rv);
                if (Z_TYPE_P(prop) == IS_STRING && Z_STRLEN_P(prop) > 0) {
                    type = Z_STRVAL_P(prop);
                }
                prop = zend_read_property(curl_CURLFile_class, current, "postname", sizeof("postname")-1, 0, &rv);
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
                    zend_string_release_ex(string_key, 0);
                    return FAILURE;
                }
                if ((form_error = curl_mime_name(part, ZSTR_VAL(string_key))) != CURLE_OK
                    || (form_error = curl_mime_data_cb(part, filesize, read_cb, seekfunc, free_cb, cb_arg)) != CURLE_OK
                    || (form_error = curl_mime_filename(part, filename ? filename : ZSTR_VAL(postval))) != CURLE_OK
                    || (form_error = curl_mime_type(part, type ? type : "application/octet-stream")) != CURLE_OK) {
                    error = form_error;
                }
                zend_llist_add_element(&ch->to_free->stream, &cb_arg);
#else
                form_error = curl_formadd(&first, &last,
                                CURLFORM_COPYNAME, ZSTR_VAL(string_key),
                                CURLFORM_NAMELENGTH, ZSTR_LEN(string_key),
                                CURLFORM_FILENAME, filename ? filename : ZSTR_VAL(postval),
                                CURLFORM_CONTENTTYPE, type ? type : "application/octet-stream",
                                CURLFORM_FILE, ZSTR_VAL(postval),
                                CURLFORM_END);
                if (form_error != CURL_FORMADD_OK) {
                    /* Not nice to convert between enums but we only have place for one error type */
                    error = (CURLcode)form_error;
                }
#endif
            }

            zend_string_release_ex(string_key, 0);
            continue;
        }

        postval = zval_get_tmp_string(current, &tmp_postval);

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
        part = curl_mime_addpart(mime);
        if (part == NULL) {
            zend_tmp_string_release(tmp_postval);
            zend_string_release_ex(string_key, 0);
            return FAILURE;
        }
        if ((form_error = curl_mime_name(part, ZSTR_VAL(string_key))) != CURLE_OK
            || (form_error = curl_mime_data(part, ZSTR_VAL(postval), ZSTR_LEN(postval))) != CURLE_OK) {
            error = form_error;
        }
#else
        /* The arguments after _NAMELENGTH and _CONTENTSLENGTH
            * must be explicitly cast to long in curl_formadd
            * use since curl needs a long not an int. */
        form_error = curl_formadd(&first, &last,
                                CURLFORM_COPYNAME, ZSTR_VAL(string_key),
                                CURLFORM_NAMELENGTH, ZSTR_LEN(string_key),
                                CURLFORM_COPYCONTENTS, ZSTR_VAL(postval),
                                CURLFORM_CONTENTSLENGTH, ZSTR_LEN(postval),
                                CURLFORM_END);

        if (form_error != CURL_FORMADD_OK) {
            /* Not nice to convert between enums but we only have place for one error type */
            error = (CURLcode)form_error;
        }
#endif
        zend_tmp_string_release(tmp_postval);
        zend_string_release_ex(string_key, 0);
    } ZEND_HASH_FOREACH_END();

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
PHP_FUNCTION(swoole_native_curl_copy_handle)
{
    CURL		*cp;
    zval		*zid;
    php_curl	*ch, *dupch;
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    zval		*postfields;
#endif

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    cp = curl_easy_duphandle(ch->cp);
    if (!cp) {
        php_error_docref(NULL, E_WARNING, "Cannot duplicate cURL handle");
        RETURN_FALSE;
    }

    dupch = curl_alloc_handle();
    dupch->cp = cp;

    _php_setup_easy_copy_handlers(dupch, ch);

#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    postfields = &ch->postfields;
    if (Z_TYPE_P(postfields) != IS_UNDEF) {
        if (build_mime_structure_from_hash(dupch, postfields) != SUCCESS) {
            _php_curl_close_ex(dupch);
            php_error_docref(NULL, E_WARNING, "Cannot rebuild mime structure");
            RETURN_FALSE;
        }
    }
#endif

    ZVAL_RES(return_value, zend_register_resource(dupch, le_curl));
    dupch->res = Z_RES_P(return_value);
}
/* }}} */

static int _php_curl_setopt(php_curl *ch, zend_long option, zval *zvalue) /* {{{ */
{
    CURLcode error = CURLE_OK;
    zend_long lval;

    switch (option) {
        /* Long options */
        case CURLOPT_SSL_VERIFYHOST:
            lval = zval_get_long(zvalue);
            if (lval == 1) {
#if LIBCURL_VERSION_NUM <= 0x071c00 /* 7.28.0 */
                php_error_docref(NULL, E_NOTICE, "CURLOPT_SSL_VERIFYHOST with value 1 is deprecated and will be removed as of libcurl 7.28.1. It is recommended to use value 2 instead");
#else
                php_error_docref(NULL, E_NOTICE, "CURLOPT_SSL_VERIFYHOST no longer accepts the value 1, value 2 will be used instead");
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
#if LIBCURL_VERSION_NUM >  0x071301 /* Available since 7.19.1 */
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
# if defined(ZTS)
            if (option == CURLOPT_DNS_USE_GLOBAL_CACHE && lval) {
                php_error_docref(NULL, E_WARNING, "CURLOPT_DNS_USE_GLOBAL_CACHE cannot be activated when thread safety is enabled");
                return 1;
            }
# endif
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
            zend_string *tmp_str;
            zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
            int ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str), 0);
            zend_tmp_string_release(tmp_str);
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
                zend_string *tmp_str;
                zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
                int ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str), 0);
                zend_tmp_string_release(tmp_str);
                return ret;
            }
            break;
        }

        /* Curl private option */
        case CURLOPT_PRIVATE:
        {
            zend_string *tmp_str;
            zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
            int ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str), 1);
            zend_tmp_string_release(tmp_str);
            return ret;
        }

        /* Curl url option */
        case CURLOPT_URL:
        {
            zend_string *tmp_str;
            zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
            int ret = php_curl_option_url(ch, ZSTR_VAL(str), ZSTR_LEN(str));
            zend_tmp_string_release(tmp_str);
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
                what = (php_stream *)zend_fetch_resource2_ex(zvalue, "File-Handle", php_file_le_stream(), php_file_le_pstream());
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
                        if (!Z_ISUNDEF(ch->handlers->write->stream)) {
                            zval_ptr_dtor(&ch->handlers->write->stream);
                            ZVAL_UNDEF(&ch->handlers->write->stream);
                        }
                        ch->handlers->write->fp = NULL;
                        ch->handlers->write->method = PHP_CURL_STDOUT;
                    } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                        zval_ptr_dtor(&ch->handlers->write->stream);
                        ch->handlers->write->fp = fp;
                        ch->handlers->write->method = PHP_CURL_FILE;
                        ZVAL_COPY(&ch->handlers->write->stream, zvalue);
                    } else {
                        php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
                        return FAILURE;
                    }
                    break;
                case CURLOPT_WRITEHEADER:
                    if (!what) {
                        if (!Z_ISUNDEF(ch->handlers->write_header->stream)) {
                            zval_ptr_dtor(&ch->handlers->write_header->stream);
                            ZVAL_UNDEF(&ch->handlers->write_header->stream);
                        }
                        ch->handlers->write_header->fp = NULL;
                        ch->handlers->write_header->method = PHP_CURL_IGNORE;
                    } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                        zval_ptr_dtor(&ch->handlers->write_header->stream);
                        ch->handlers->write_header->fp = fp;
                        ch->handlers->write_header->method = PHP_CURL_FILE;
                        ZVAL_COPY(&ch->handlers->write_header->stream, zvalue);;
                    } else {
                        php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
                        return FAILURE;
                    }
                    break;
                case CURLOPT_INFILE:
                    if (!what) {
                        if (!Z_ISUNDEF(ch->handlers->read->stream)) {
                            zval_ptr_dtor(&ch->handlers->read->stream);
                            ZVAL_UNDEF(&ch->handlers->read->stream);
                        }
                        ch->handlers->read->fp = NULL;
                        ch->handlers->read->res = NULL;
                    } else {
                        zval_ptr_dtor(&ch->handlers->read->stream);
                        ch->handlers->read->fp = fp;
                        ch->handlers->read->res = Z_RES_P(zvalue);
                        ZVAL_COPY(&ch->handlers->read->stream, zvalue);
                    }
                    break;
                case CURLOPT_STDERR:
                    if (!what) {
                        if (!Z_ISUNDEF(ch->handlers->std_err)) {
                            zval_ptr_dtor(&ch->handlers->std_err);
                            ZVAL_UNDEF(&ch->handlers->std_err);
                        }
                    } else if (what->mode[0] != 'r' || what->mode[1] == '+') {
                        zval_ptr_dtor(&ch->handlers->std_err);
                        ZVAL_COPY(&ch->handlers->std_err, zvalue);
                    } else {
                        php_error_docref(NULL, E_WARNING, "the provided file handle is not writable");
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
            HashTable *ph;
            zend_string *val, *tmp_val;
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
                php_error_docref(NULL, E_WARNING, "You must pass either an object or an array with the %s argument", name);
                return FAILURE;
            }

            ZEND_HASH_FOREACH_VAL_IND(ph, current) {
                ZVAL_DEREF(current);
                val = zval_get_tmp_string(current, &tmp_val);
                slist = curl_slist_append(slist, ZSTR_VAL(val));
                zend_tmp_string_release(tmp_val);
                if (!slist) {
                    php_error_docref(NULL, E_WARNING, "Could not build curl_slist");
                    return 1;
                }
            } ZEND_HASH_FOREACH_END();

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
            if (!Z_ISUNDEF(ch->handlers->write_header->func_name)) {
                zval_ptr_dtor(&ch->handlers->write_header->func_name);
                ch->handlers->write_header->fci_cache = empty_fcall_info_cache;
            }
            ZVAL_COPY(&ch->handlers->write_header->func_name, zvalue);
            ch->handlers->write_header->method = PHP_CURL_USER;
            break;

        case CURLOPT_POSTFIELDS:
            if (Z_TYPE_P(zvalue) == IS_ARRAY || Z_TYPE_P(zvalue) == IS_OBJECT) {
                return build_mime_structure_from_hash(ch, zvalue);
            } else {
#if LIBCURL_VERSION_NUM >= 0x071101
                zend_string *tmp_str;
                zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
                /* with curl 7.17.0 and later, we can use COPYPOSTFIELDS, but we have to provide size before */
                error = curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDSIZE, ZSTR_LEN(str));
                error = curl_easy_setopt(ch->cp, CURLOPT_COPYPOSTFIELDS, ZSTR_VAL(str));
                zend_tmp_string_release(tmp_str);
#else
                char *post = NULL;
                zend_string *tmp_str;
                zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);

                post = estrndup(ZSTR_VAL(str), ZSTR_LEN(str));
                zend_llist_add_element(&ch->to_free->str, &post);

                curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDS, post);
                error = curl_easy_setopt(ch->cp, CURLOPT_POSTFIELDSIZE, ZSTR_LEN(str));
                zend_tmp_string_release(tmp_str);
#endif
            }
            break;

        case CURLOPT_PROGRESSFUNCTION:
            curl_easy_setopt(ch->cp, CURLOPT_PROGRESSFUNCTION,	fn_progress);
            curl_easy_setopt(ch->cp, CURLOPT_PROGRESSDATA, ch);
            if (ch->handlers->progress == NULL) {
                ch->handlers->progress = (php_curl_progress *)ecalloc(1, sizeof(php_curl_progress));
            } else if (!Z_ISUNDEF(ch->handlers->progress->func_name)) {
                zval_ptr_dtor(&ch->handlers->progress->func_name);
                ch->handlers->progress->fci_cache = empty_fcall_info_cache;
            }
            ZVAL_COPY(&ch->handlers->progress->func_name, zvalue);
            ch->handlers->progress->method = PHP_CURL_USER;
            break;

        case CURLOPT_READFUNCTION:
            if (!Z_ISUNDEF(ch->handlers->read->func_name)) {
                zval_ptr_dtor(&ch->handlers->read->func_name);
                ch->handlers->read->fci_cache = empty_fcall_info_cache;
            }
            ZVAL_COPY(&ch->handlers->read->func_name, zvalue);
            ch->handlers->read->method = PHP_CURL_USER;
            break;

        case CURLOPT_RETURNTRANSFER:
            if (zend_is_true(zvalue)) {
                ch->handlers->write->method = PHP_CURL_RETURN;
            } else {
                ch->handlers->write->method = PHP_CURL_STDOUT;
            }
            break;

        case CURLOPT_WRITEFUNCTION:
            if (!Z_ISUNDEF(ch->handlers->write->func_name)) {
                zval_ptr_dtor(&ch->handlers->write->func_name);
                ch->handlers->write->fci_cache = empty_fcall_info_cache;
            }
            ZVAL_COPY(&ch->handlers->write->func_name, zvalue);
            ch->handlers->write->method = PHP_CURL_USER;
            break;

        /* Curl off_t options */
        case CURLOPT_MAX_RECV_SPEED_LARGE:
        case CURLOPT_MAX_SEND_SPEED_LARGE:
#if LIBCURL_VERSION_NUM >= 0x073b00 /* Available since 7.59.0 */
        case CURLOPT_TIMEVALUE_LARGE:
#endif
            lval = zval_get_long(zvalue);
            error = curl_easy_setopt(ch->cp, (CURLoption) option, (curl_off_t)lval);
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
            zend_string *tmp_str;
            zend_string *str = zval_get_tmp_string(zvalue, &tmp_str);
            int ret;

            if (ZSTR_LEN(str) && php_check_open_basedir(ZSTR_VAL(str))) {
                zend_tmp_string_release(tmp_str);
                return FAILURE;
            }

            ret = php_curl_option_str(ch, option, ZSTR_VAL(str), ZSTR_LEN(str), 0);
            zend_tmp_string_release(tmp_str);
            return ret;
        }

        case CURLINFO_HEADER_OUT:
            if (zend_is_true(zvalue)) {
                curl_easy_setopt(ch->cp, CURLOPT_DEBUGFUNCTION, curl_debug);
                curl_easy_setopt(ch->cp, CURLOPT_DEBUGDATA, (void *)ch);
                curl_easy_setopt(ch->cp, CURLOPT_VERBOSE, 1);
            } else {
                curl_easy_setopt(ch->cp, CURLOPT_DEBUGFUNCTION, NULL);
                curl_easy_setopt(ch->cp, CURLOPT_DEBUGDATA, NULL);
                curl_easy_setopt(ch->cp, CURLOPT_VERBOSE, 0);
            }
            break;

        case CURLOPT_SHARE:
            {
                php_error_docref(NULL, E_WARNING, "CURLOPT_SHARE option is not supported");
                return FAILURE;
            }
            break;

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
        case CURLOPT_FNMATCH_FUNCTION:
            curl_easy_setopt(ch->cp, CURLOPT_FNMATCH_FUNCTION, fn_fnmatch);
            curl_easy_setopt(ch->cp, CURLOPT_FNMATCH_DATA, ch);
            if (ch->handlers->fnmatch == NULL) {
                ch->handlers->fnmatch = (php_curl_fnmatch*)ecalloc(1, sizeof(php_curl_fnmatch));
            } else if (!Z_ISUNDEF(ch->handlers->fnmatch->func_name)) {
                zval_ptr_dtor(&ch->handlers->fnmatch->func_name);
                ch->handlers->fnmatch->fci_cache = empty_fcall_info_cache;
            }
            ZVAL_COPY(&ch->handlers->fnmatch->func_name, zvalue);
            ch->handlers->fnmatch->method = PHP_CURL_USER;
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
PHP_FUNCTION(swoole_native_curl_setopt)
{
    zval       *zid, *zvalue;
    zend_long        options;
    php_curl   *ch;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_LONG(options)
        Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    if (options <= 0 && options != CURLOPT_SAFE_UPLOAD) {
        php_error_docref(NULL, E_WARNING, "Invalid curl configuration option");
        RETURN_FALSE;
    }

    if (_php_curl_setopt(ch, options, zvalue) == SUCCESS) {
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}
/* }}} */

/* {{{ proto bool curl_setopt_array(resource ch, array options)
   Set an array of option for a cURL transfer */
PHP_FUNCTION(swoole_native_curl_setopt_array)
{
    zval		*zid, *arr, *entry;
    php_curl	*ch;
    zend_ulong	option;
    zend_string	*string_key;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_ARRAY(arr)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(arr), option, string_key, entry) {
        if (string_key) {
            php_error_docref(NULL, E_WARNING,
                    "Array keys must be CURLOPT constants or equivalent integer values");
            RETURN_FALSE;
        }
        ZVAL_DEREF(entry);
        if (_php_curl_setopt(ch, (zend_long) option, entry) == FAILURE) {
            RETURN_FALSE;
        }
    } ZEND_HASH_FOREACH_END();

    RETURN_TRUE;
}
/* }}} */

/* {{{ _php_curl_cleanup_handle(ch)
   Cleanup an execution phase */
void _php_curl_cleanup_handle(php_curl *ch)
{
    smart_str_free(&ch->handlers->write->buf);
    if (ch->header.str) {
        zend_string_release_ex(ch->header.str, 0);
        ch->header.str = NULL;
    }

    memset(ch->err.str, 0, CURL_ERROR_SIZE + 1);
    ch->err.no = 0;
}
/* }}} */

/* {{{ proto bool curl_exec(resource ch)
   Perform a cURL session */
PHP_FUNCTION(swoole_native_curl_exec)
{
    CURLcode	error;
    zval		*zid;
    php_curl	*ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    _php_curl_verify_handlers(ch, 1);
    _php_curl_cleanup_handle(ch);

    sw_curl_multi()->add(ch->cp);

    FutureTask *context = (FutureTask*) emalloc(sizeof(FutureTask));
    ON_SCOPE_EXIT {
        efree(context);
    };
    ch->context = context;

    do {
        PHPCoroutine::yield_m(return_value, context);
    } while(ZVAL_IS_NULL(return_value) && ch->callback && (*ch->callback)());

    error = (CURLcode) Z_LVAL_P(return_value);
    SAVE_CURL_ERROR(ch, error);

    if (error != CURLE_OK) {
        smart_str_free(&ch->handlers->write->buf);
        RETURN_FALSE;
    }

    if (!Z_ISUNDEF(ch->handlers->std_err)) {
        php_stream  *stream;
        stream = (php_stream*)zend_fetch_resource2_ex(&ch->handlers->std_err, NULL, php_file_le_stream(), php_file_le_pstream());
        if (stream) {
            php_stream_flush(stream);
        }
    }

    if (ch->handlers->write->method == PHP_CURL_RETURN && ch->handlers->write->buf.s) {
        smart_str_0(&ch->handlers->write->buf);
        RETURN_STR_COPY(ch->handlers->write->buf.s);
    }

    /* flush the file handle, so any remaining data is synched to disk */
    if (ch->handlers->write->method == PHP_CURL_FILE && ch->handlers->write->fp) {
        fflush(ch->handlers->write->fp);
    }
    if (ch->handlers->write_header->method == PHP_CURL_FILE && ch->handlers->write_header->fp) {
        fflush(ch->handlers->write_header->fp);
    }

    if (ch->handlers->write->method == PHP_CURL_RETURN) {
        RETURN_EMPTY_STRING();
    } else {
        RETURN_TRUE;
    }
}
/* }}} */

/* {{{ proto mixed curl_getinfo(resource ch [, int option])
   Get information regarding a specific transfer */
PHP_FUNCTION(swoole_native_curl_getinfo)
{
    zval		*zid;
    php_curl	*ch;
    zend_long	option = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(option)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    if (ZEND_NUM_ARGS() < 2) {
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
            default: {
                int type = CURLINFO_TYPEMASK & option;
                switch (type) {
                    case CURLINFO_STRING:
                    {
                        char *s_code = NULL;

                        if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &s_code) == CURLE_OK && s_code) {
                            RETURN_STRING(s_code);
                        } else {
                            RETURN_FALSE;
                        }
                        break;
                    }
                    case CURLINFO_LONG:
                    {
                        zend_long code = 0;

                        if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &code) == CURLE_OK) {
                            RETURN_LONG(code);
                        } else {
                            RETURN_FALSE;
                        }
                        break;
                    }
                    case CURLINFO_DOUBLE:
                    {
                        double code = 0.0;

                        if (curl_easy_getinfo(ch->cp, (CURLINFO) option, &code) == CURLE_OK) {
                            RETURN_DOUBLE(code);
                        } else {
                            RETURN_FALSE;
                        }
                        break;
                    }
                    case CURLINFO_SLIST:
                    {
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
                    case CURLINFO_OFF_T:
                    {
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
PHP_FUNCTION(swoole_native_curl_error)
{
    zval		*zid;
    php_curl	*ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    if (ch->err.no) {
        ch->err.str[CURL_ERROR_SIZE] = 0;
        RETURN_STRING(ch->err.str);
    } else {
        RETURN_EMPTY_STRING();
    }
}
/* }}} */

/* {{{ proto int curl_errno(resource ch)
   Return an integer containing the last error number */
PHP_FUNCTION(swoole_native_curl_errno)
{
    zval		*zid;
    php_curl	*ch;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    RETURN_LONG(ch->err.no);
}
/* }}} */

/* {{{ proto void curl_close(resource ch)
   Close a cURL session */
PHP_FUNCTION(swoole_native_curl_close)
{
    zval		*zid;
    php_curl	*ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    if (ch->in_callback) {
        php_error_docref(NULL, E_WARNING, "Attempt to close cURL handle from a callback");
        return;
    }

    zend_list_close(Z_RES_P(zid));
}
/* }}} */

/* {{{ _php_curl_close_ex()
   List destructor for curl handles */
static void _php_curl_close_ex(php_curl *ch)
{
#if PHP_CURL_DEBUG
    fprintf(stderr, "DTOR CALLED, ch = %x\n", ch);
#endif

    _php_curl_verify_handlers(ch, 0);

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
    if (ch->cp != NULL) {
        curl_easy_setopt(ch->cp, CURLOPT_HEADERFUNCTION, fn_write_nothing);
        curl_easy_setopt(ch->cp, CURLOPT_WRITEFUNCTION, fn_write_nothing);

        curl_easy_cleanup(ch->cp);
    }

    /* cURL destructors should be invoked only by last curl handle */
    if (--(*ch->clone) == 0) {
        zend_llist_clean(&ch->to_free->str);
        zend_llist_clean(&ch->to_free->post);
        zend_llist_clean(&ch->to_free->stream);
        zend_hash_destroy(ch->to_free->slist);
        efree(ch->to_free->slist);
        efree(ch->to_free);
        efree(ch->clone);
    }

    smart_str_free(&ch->handlers->write->buf);
    zval_ptr_dtor(&ch->handlers->write->func_name);
    zval_ptr_dtor(&ch->handlers->read->func_name);
    zval_ptr_dtor(&ch->handlers->write_header->func_name);
    zval_ptr_dtor(&ch->handlers->std_err);
    if (ch->header.str) {
        zend_string_release_ex(ch->header.str, 0);
    }

    zval_ptr_dtor(&ch->handlers->write_header->stream);
    zval_ptr_dtor(&ch->handlers->write->stream);
    zval_ptr_dtor(&ch->handlers->read->stream);

    efree(ch->handlers->write);
    efree(ch->handlers->write_header);
    efree(ch->handlers->read);

    if (ch->handlers->progress) {
        zval_ptr_dtor(&ch->handlers->progress->func_name);
        efree(ch->handlers->progress);
    }

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    if (ch->handlers->fnmatch) {
        zval_ptr_dtor(&ch->handlers->fnmatch->func_name);
        efree(ch->handlers->fnmatch);
    }
#endif

    efree(ch->handlers);
#if LIBCURL_VERSION_NUM >= 0x073800 /* 7.56.0 */
    zval_ptr_dtor(&ch->postfields);
#endif
    efree(ch);
}
/* }}} */

/* {{{ _php_curl_close()
   List destructor for curl handles */
static void _php_curl_close(zend_resource *rsrc)
{
    php_curl *ch = (php_curl *) rsrc->ptr;
    _php_curl_close_ex(ch);
}
/* }}} */

/* {{{ _php_curl_reset_handlers()
   Reset all handlers of a given php_curl */
static void _php_curl_reset_handlers(php_curl *ch)
{
    if (!Z_ISUNDEF(ch->handlers->write->stream)) {
        zval_ptr_dtor(&ch->handlers->write->stream);
        ZVAL_UNDEF(&ch->handlers->write->stream);
    }
    ch->handlers->write->fp = NULL;
    ch->handlers->write->method = PHP_CURL_STDOUT;

    if (!Z_ISUNDEF(ch->handlers->write_header->stream)) {
        zval_ptr_dtor(&ch->handlers->write_header->stream);
        ZVAL_UNDEF(&ch->handlers->write_header->stream);
    }
    ch->handlers->write_header->fp = NULL;
    ch->handlers->write_header->method = PHP_CURL_IGNORE;

    if (!Z_ISUNDEF(ch->handlers->read->stream)) {
        zval_ptr_dtor(&ch->handlers->read->stream);
        ZVAL_UNDEF(&ch->handlers->read->stream);
    }
    ch->handlers->read->fp = NULL;
    ch->handlers->read->res = NULL;
    ch->handlers->read->method  = PHP_CURL_DIRECT;

    if (!Z_ISUNDEF(ch->handlers->std_err)) {
        zval_ptr_dtor(&ch->handlers->std_err);
        ZVAL_UNDEF(&ch->handlers->std_err);
    }

    if (ch->handlers->progress) {
        zval_ptr_dtor(&ch->handlers->progress->func_name);
        efree(ch->handlers->progress);
        ch->handlers->progress = NULL;
    }

#if LIBCURL_VERSION_NUM >= 0x071500 /* Available since 7.21.0 */
    if (ch->handlers->fnmatch) {
        zval_ptr_dtor(&ch->handlers->fnmatch->func_name);
        efree(ch->handlers->fnmatch);
        ch->handlers->fnmatch = NULL;
    }
#endif

}
/* }}} */

/* {{{ proto void curl_reset(resource ch)
   Reset all options of a libcurl session handle */
PHP_FUNCTION(swoole_native_curl_reset)
{
    zval       *zid;
    php_curl   *ch;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(zid)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
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
PHP_FUNCTION(swoole_native_curl_escape)
{
    zend_string *str;
    char        *res;
    zval        *zid;
    php_curl    *ch;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
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
PHP_FUNCTION(swoole_native_curl_unescape)
{
    char        *out = NULL;
    int          out_len;
    zval        *zid;
    zend_string *str;
    php_curl    *ch;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

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
PHP_FUNCTION(swoole_native_curl_pause)
{
    zend_long       bitmask;
    zval       *zid;
    php_curl   *ch;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_LONG(bitmask)
    ZEND_PARSE_PARAMETERS_END();

    if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
        RETURN_FALSE;
    }

    RETURN_LONG(curl_easy_pause(ch->cp, bitmask));
}
/* }}} */
#endif

SW_EXTERN_C_END
#endif
