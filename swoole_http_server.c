/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "swoole_http.h"

#include <ext/standard/url.h>
#include <ext/standard/sha1.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_string.h>
#include <ext/standard/php_math.h>
#include <ext/standard/php_array.h>
#include <ext/date/php_date.h>
#include <ext/standard/md5.h>

#include <main/rfc1867.h>
#include <main/php_variables.h>

#include "websocket.h"
#include "Connection.h"
#include "base64.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_USE_HTTP2
#include "http2.h"
#endif

static swArray *http_client_array;

swString *swoole_http_buffer;
#ifdef SW_HAVE_ZLIB
swString *swoole_zlib_buffer;
#endif
swString *swoole_http_form_data_buffer;

enum http_global_flag
{
    HTTP_GLOBAL_GET       = 1u << 1,
    HTTP_GLOBAL_POST      = 1u << 2,
    HTTP_GLOBAL_COOKIE    = 1u << 3,
    HTTP_GLOBAL_REQUEST   = 1u << 4,
    HTTP_GLOBAL_SERVER    = 1u << 5,
    HTTP_GLOBAL_FILES     = 1u << 6,
};

enum http_upload_errno
{
    HTTP_UPLOAD_ERR_OK = 0,
    HTTP_UPLOAD_ERR_INI_SIZE,
    HTTP_UPLOAD_ERR_FORM_SIZE,
    HTTP_UPLOAD_ERR_PARTIAL,
    HTTP_UPLOAD_ERR_NO_FILE,
    HTTP_UPLOAD_ERR_NO_TMP_DIR = 6,
    HTTP_UPLOAD_ERR_CANT_WRITE,
};

zend_class_entry swoole_http_server_ce;
zend_class_entry *swoole_http_server_class_entry_ptr;

zend_class_entry swoole_http_response_ce;
zend_class_entry *swoole_http_response_class_entry_ptr;

zend_class_entry swoole_http_request_ce;
zend_class_entry *swoole_http_request_class_entry_ptr;

static int http_onReceive(swServer *serv, swEventData *req);
static void http_onClose(swServer *serv, swDataHead *ev);

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(php_http_parser *parser);
static int http_request_message_complete(php_http_parser *parser);

static int multipart_body_on_header_field(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_header_value(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_data(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_header_complete(multipart_parser* p);
static int multipart_body_on_data_end(multipart_parser* p);
static int multipart_body_end(multipart_parser* p);

static http_context* http_get_context(zval *object, int check_end TSRMLS_DC);

static void http_parse_cookie(zval *array, const char *at, size_t length);
static void http_build_header(http_context *, zval *object, swString *response, int body_length TSRMLS_DC);
static int http_trim_double_quote(zval **value, char **ptr);

static inline void http_header_key_format(char *key, int length)
{
    int i, state = 0;
    for (i = 0; i < length; i++)
    {
        if (state == 0)
        {
            if (key[i] >= 97 && key[i] <= 122)
            {
                key[i] -= 32;
            }
            state = 1;
        }
        else if (key[i] == '-')
        {
            state = 0;
        }
        else
        {
            if (key[i] >= 65 && key[i] <= 90)
            {
                key[i] += 32;
            }
        }
    }
}

#ifdef SW_HAVE_ZLIB
static int http_response_compress(swString *body, int level);
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size);
void php_zlib_free(voidpf opaque, voidpf address);
#endif

static PHP_METHOD(swoole_http_server, on);
static PHP_METHOD(swoole_http_server, start);

static PHP_METHOD(swoole_http_request, rawcontent);
static PHP_METHOD(swoole_http_request, __destruct);

static PHP_METHOD(swoole_http_response, write);
static PHP_METHOD(swoole_http_response, end);
static PHP_METHOD(swoole_http_response, sendfile);
static PHP_METHOD(swoole_http_response, cookie);
static PHP_METHOD(swoole_http_response, rawcookie);
static PHP_METHOD(swoole_http_response, header);
#ifdef SW_HAVE_ZLIB
static PHP_METHOD(swoole_http_response, gzip);
#endif
static PHP_METHOD(swoole_http_response, status);
static PHP_METHOD(swoole_http_response, __destruct);

static sw_inline char* http_get_method_name(int method)
{
    switch (method)
    {
    case PHP_HTTP_GET:
        return "GET";
    case PHP_HTTP_POST:
        return "POST";
    case PHP_HTTP_HEAD:
        return "HEAD";
    case PHP_HTTP_PUT:
        return "PUT";
    case PHP_HTTP_DELETE:
        return "DELETE";
    case PHP_HTTP_PATCH:
        return "PATCH";
    case PHP_HTTP_CONNECT:
        return "CONNECT";
    case PHP_HTTP_OPTIONS:
        return "OPTIONS";
    case PHP_HTTP_TRACE:
        return "TRACE";
    case PHP_HTTP_COPY:
        return "COPY";
    case PHP_HTTP_LOCK:
        return "LOCK";
    case PHP_HTTP_MKCOL:
        return "MKCOL";
    case PHP_HTTP_MOVE:
        return "MOVE";
    case PHP_HTTP_PROPFIND:
        return "PROPFIND";
    case PHP_HTTP_PROPPATCH:
        return "PROPPATCH";
    case PHP_HTTP_UNLOCK:
        return "UNLOCK";
        /* subversion */
    case PHP_HTTP_REPORT:
        return "REPORT";
    case PHP_HTTP_MKACTIVITY:
        return "MKACTIVITY";
    case PHP_HTTP_CHECKOUT:
        return "CHECKOUT";
    case PHP_HTTP_MERGE:
        return "MERGE";
        /* upnp */
    case PHP_HTTP_MSEARCH:
        return "MSEARCH";
    case PHP_HTTP_NOTIFY:
        return "NOTIFY";
    case PHP_HTTP_SUBSCRIBE:
        return "SUBSCRIBE";
    case PHP_HTTP_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case PHP_HTTP_NOT_IMPLEMENTED:
        return "IMPLEMENTED";
    default:
        return NULL;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

#ifdef SW_HAVE_ZLIB
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_gzip, 0, 0, 0)
    ZEND_ARG_INFO(0, compress_level)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_status, 0, 0, 1)
    ZEND_ARG_INFO(0, http_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_header, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, ucwords)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_cookie, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, expires)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, secure)
    ZEND_ARG_INFO(0, httponly)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_write, 0, 0, 1)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_end, 0, 0, 0)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    http_request_on_path,
    http_request_on_query_string,
    NULL,
    NULL,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
    http_request_on_body,
    http_request_message_complete
};

static const multipart_parser_settings mt_parser_settings =
{
    multipart_body_on_header_field,
    multipart_body_on_header_value,
    multipart_body_on_data,
    NULL,
    multipart_body_on_header_complete,
    multipart_body_on_data_end,
    multipart_body_end
};

const zend_function_entry swoole_http_server_methods[] =
{
    PHP_ME(swoole_http_server, on,         arginfo_swoole_http_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server, start,      arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_request_methods[] =
{
    PHP_ME(swoole_http_request, rawcontent, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

const zend_function_entry swoole_http_response_methods[] =
{
    PHP_ME(swoole_http_response, cookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, rawcookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, status, arginfo_swoole_http_response_status, ZEND_ACC_PUBLIC)
#ifdef SW_HAVE_ZLIB
    PHP_ME(swoole_http_response, gzip, arginfo_swoole_http_response_gzip, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_http_response, header, arginfo_swoole_http_response_header, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, write, arginfo_swoole_http_response_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, end, arginfo_swoole_http_response_end, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, sendfile, arginfo_swoole_http_response_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = parser->data;
    ctx->request.path = estrndup(at, length);
    ctx->request.path_len = length;
    return 0;
}

static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    http_context *ctx = parser->data;

    //no need free, will free by treat_data
    char *query = estrndup(at, length);
    sw_add_assoc_stringl_ex(ctx->request.zserver, ZEND_STRS("query_string"), query, length, 1);

    zval *zrequest_object = ctx->request.zobject;
    zval *zget;
    swoole_http_server_array_init(get, request);

    //parse url params
    sapi_module.treat_data(PARSE_STRING, query, zget TSRMLS_CC);

    return 0;
}

static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = parser->data;
    if (ctx->current_header_name_allocated)
    {
        efree(ctx->current_header_name);
        ctx->current_header_name_allocated = 0;
    }
    ctx->current_header_name = (char *) at;
    ctx->current_header_name_len = length;
    return 0;
}

int swoole_http_parse_form_data(http_context *ctx, const char *boundary_str, int boundary_len TSRMLS_DC)
{
    multipart_parser *mt_parser = multipart_parser_init(boundary_str, boundary_len, &mt_parser_settings);
    if (!mt_parser)
    {
        swoole_php_fatal_error(E_WARNING, "multipart_parser_init() failed.");
        return SW_ERR;
    }

    ctx->mt_parser = mt_parser;
    mt_parser->data = ctx;

    return SW_OK;
}

static void http_parse_cookie(zval *array, const char *at, size_t length)
{
    char keybuf[SW_HTTP_COOKIE_KEYLEN];
    char valbuf[SW_HTTP_COOKIE_VALLEN];
    char *_c = (char *) at;

    int klen = 0;
    int vlen = 0;
    int state = -1;

    int i = 0, j = 0;
    while (_c < at + length)
    {
        if (state <= 0 && *_c == '=')
        {
            klen = i - j + 1;
            if (klen >= SW_HTTP_COOKIE_KEYLEN)
            {
                swWarn("cookie key is too large.");
                return;
            }
            memcpy(keybuf, at + j, klen - 1);
            keybuf[klen - 1] = 0;

            j = i + 1;
            state = 1;
        }
        else if (state == 1 && *_c == ';')
        {
            vlen = i - j;
            strncpy(valbuf, (char * ) at + j, SW_HTTP_COOKIE_VALLEN);
            vlen = php_url_decode(valbuf, vlen);
            if (klen > 1)
            {
                sw_add_assoc_stringl_ex(array, keybuf, klen, valbuf, vlen, 1);
            }
            j = i + 1;
            state = -1;
        }
        else if (state < 0)
        {
            if (isspace(*_c))
            {
                //Remove leading spaces from cookie names
                ++j;
            }
            else
            {
                state = 0;
            }
        }
        _c++;
        i++;
    }
    if (j < length)
    {
        vlen = i - j;
        keybuf[klen - 1] = 0;
        strncpy(valbuf, (char * ) at + j, SW_HTTP_COOKIE_VALLEN);
        vlen = php_url_decode(valbuf, vlen);
        if (klen > 1)
        {
            sw_add_assoc_stringl_ex(array, keybuf, klen, valbuf, vlen, 1);
        }
    }
}

static int http_trim_double_quote(zval **value, char **ptr)
{
    int len = Z_STRLEN_PP(value);
    *ptr = Z_STRVAL_PP(value);

    //ltrim('"')
    if ((*ptr)[0] == '"')
    {
        (*ptr)++;
        len--;
    }
    //rtrim('"')
    if ((*ptr)[len - 1] == '"')
    {
        len--;
    }
    return len;
}

static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = parser->data;
    zval *zrequest_object = ctx->request.zobject;
    size_t header_len = ctx->current_header_name_len;
    char *header_name = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (strncmp(header_name, "cookie", header_len) == 0)
    {
        zval *zcookie;
        if (length >= SW_HTTP_COOKIE_VALLEN)
        {
            swWarn("cookie is too large.");
        }
        else
        {
            swoole_http_server_array_init(cookie, request);
            http_parse_cookie(zcookie, at, length);
        }
        goto free_memory;
    }
    else if (SwooleG.serv->listen_list->open_websocket_protocol && strncmp(header_name, "upgrade", header_len) == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        swConnection *conn = swWorker_get_connection(SwooleG.serv, ctx->fd);
        if (!conn)
        {
            swWarn("connection[%d] is closed.", ctx->fd);
            return SW_ERR;
        }
        conn->websocket_status = WEBSOCKET_STATUS_CONNECTION;
    }
    else if (parser->method == PHP_HTTP_POST || parser->method == PHP_HTTP_PUT || parser->method == PHP_HTTP_DELETE || parser->method == PHP_HTTP_PATCH)
    {
        if (strncmp(header_name, "content-type", header_len) == 0)
        {
            if (http_strncasecmp("application/x-www-form-urlencoded", at, length))
            {
                ctx->request.post_form_urlencoded = 1;
            }
            else if (http_strncasecmp("multipart/form-data", at, length))
            {
                int boundary_len = length - (sizeof("multipart/form-data; boundary=") - 1);
                if (boundary_len <= 0)
                {
                    swWarn("invalid multipart/form-data body.", ctx->fd);
                    return 0;
                }
                swoole_http_parse_form_data(ctx, at + length - boundary_len, boundary_len TSRMLS_CC);
            }
        }
    }

    zval *header = ctx->request.zheader;
    sw_add_assoc_stringl_ex(header, header_name, ctx->current_header_name_len + 1, (char *) at, length, 1);

    free_memory:
    if (ctx->current_header_name_allocated)
    {
        efree(ctx->current_header_name);
        ctx->current_header_name_allocated = 0;
    }
    efree(header_name);

    return 0;
}

static int http_request_on_headers_complete(php_http_parser *parser)
{
    http_context *ctx = parser->data;
    if (ctx->current_header_name_allocated)
    {
        efree(ctx->current_header_name);
        ctx->current_header_name_allocated = 0;
    }
    ctx->current_header_name = NULL;

    return 0;
}

static int multipart_body_on_header_field(multipart_parser* p, const char *at, size_t length)
{
    http_context *ctx = p->data;
    return http_request_on_header_field(&ctx->parser, at, length);
}

static int multipart_body_on_header_value(multipart_parser* p, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = p->data;
    zval *zrequest_object = ctx->request.zobject;
    zval *zfiles = ctx->request.zfiles;
    if (!zfiles)
    {
        swoole_http_server_array_init(files, request);
    }

    size_t header_len = ctx->current_header_name_len;
    char *headername = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (strncasecmp(headername, "content-disposition", header_len) == 0)
    {
        //not form data
        if (swoole_strnpos((char *) at, length, ZEND_STRL("form-data;")) < 0)
        {
            return SW_OK;
        }

        zval *tmp_array;
        SW_MAKE_STD_ZVAL(tmp_array);
        array_init(tmp_array);
        http_parse_cookie(tmp_array, (char *) at + sizeof("form-data;"), length - sizeof("form-data;"));

        zval *form_name;
        if (sw_zend_hash_find(Z_ARRVAL_P(tmp_array), ZEND_STRS("name"), (void **) &form_name) == FAILURE)
        {
            return SW_OK;
        }

        char *str;
        int len = http_trim_double_quote(&form_name, &str);

        zval *filename;
        //POST form data
        if (sw_zend_hash_find(Z_ARRVAL_P(tmp_array), ZEND_STRS("filename"), (void **) &filename) == FAILURE)
        {
            ctx->current_form_data_name = estrndup(str, len);
            ctx->current_form_data_name_len = len;
        }
        //upload file
        else
        {
            ctx->current_input_name = estrndup(str, len);

            zval *multipart_header;
            SW_MAKE_STD_ZVAL(multipart_header);
            array_init(multipart_header);
            add_assoc_zval(zfiles, ctx->current_input_name, multipart_header);

            sw_add_assoc_string(multipart_header, "name", "", 1);
            sw_add_assoc_string(multipart_header, "type", "", 1);
            sw_add_assoc_string(multipart_header, "tmp_name", "", 1);
            add_assoc_long(multipart_header, "error", HTTP_UPLOAD_ERR_OK);
            add_assoc_long(multipart_header, "size", 0);

            len = http_trim_double_quote(&filename, &str);
            sw_add_assoc_stringl(multipart_header, "name", str, len, 1);
        }
        sw_zval_ptr_dtor(&tmp_array);
    }

    if (strncasecmp(headername, "content-type", header_len) == 0)
    {
        zval *multipart_header = NULL;
        sw_zend_hash_find(Z_ARRVAL_P(zfiles), ctx->current_input_name, strlen(ctx->current_input_name) + 1, (void **) &multipart_header);
        sw_add_assoc_stringl(multipart_header, "type", (char * ) at, length, 1);
    }

    if (ctx->current_header_name_allocated)
    {
        efree(ctx->current_header_name);
        ctx->current_header_name_allocated = 0;
    }
    efree(headername);

    return 0;
}

static int multipart_body_on_data(multipart_parser* p, const char *at, size_t length)
{
    http_context *ctx = p->data;
    if (ctx->current_form_data_name)
    {
        swString_append_ptr(swoole_http_form_data_buffer, (char*) at, length);
        return 0;
    }
    if (p->fp == NULL)
    {
        return 0;
    }
    int n = fwrite(at, sizeof(char), length, (FILE *) p->fp);
    if (n != length)
    {
        zval *files = ctx->request.zfiles;
        zval *multipart_header = NULL;
        sw_zend_hash_find(Z_ARRVAL_P(files), ctx->current_input_name, strlen(ctx->current_input_name) + 1, (void **) &multipart_header);
        add_assoc_long(multipart_header, "error", HTTP_UPLOAD_ERR_CANT_WRITE);

        fclose((FILE *) p->fp);
        p->fp = NULL;

        swWarn("write upload file failed. Error %s[%d]", strerror(errno), errno);
    }
    return 0;
}

#if 0
static void get_random_file_name(char *des, const char *src)
{
    unsigned char digest[16] = {0};
    char buf[19] = {0};
    int n = sprintf(buf, "%s%d", src, swoole_system_random(0, 9999));

    PHP_MD5_CTX ctx;
    PHP_MD5Init(&ctx);
    PHP_MD5Update(&ctx, buf, n);
    PHP_MD5Final(digest, &ctx);
    make_digest_ex(des, digest, 16);
}
#endif

static int multipart_body_on_header_complete(multipart_parser* p)
{
    http_context *ctx = p->data;
    if (!ctx->current_input_name)
    {
        return 0;
    }

    zval *files = ctx->request.zfiles;
    zval *multipart_header;

    if (sw_zend_hash_find(Z_ARRVAL_P(files), ctx->current_input_name, strlen(ctx->current_input_name) + 1, (void **) &multipart_header) == FAILURE)
    {
        return 0;
    }

    zval *zerr = NULL;
    sw_zend_hash_find(Z_ARRVAL_P(multipart_header), ZEND_STRS("error"), (void **) &zerr);
    if (Z_LVAL_P(zerr) != HTTP_UPLOAD_ERR_OK)
    {
        return 0;
    }

    char file_path[SW_HTTP_UPLOAD_TMPDIR_SIZE];
    snprintf(file_path, SW_HTTP_UPLOAD_TMPDIR_SIZE, "%s/swoole.upfile.XXXXXX", SwooleG.serv->upload_tmp_dir);
    int tmpfile = swoole_tmpfile(file_path);

    FILE *fp = fdopen(tmpfile, "wb+");
    if (fp == NULL)
    {
        add_assoc_long(multipart_header, "error", HTTP_UPLOAD_ERR_NO_TMP_DIR);
        swWarn("fopen(%s) failed. Error %s[%d]", file_path, strerror(errno), errno);
        return 0;
    }

    p->fp = fp;
    sw_add_assoc_string(multipart_header, "tmp_name", file_path, 1);

    return 0;
}

static int multipart_body_on_data_end(multipart_parser* p)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = p->data;
    zval *zrequest_object = ctx->request.zobject;
    if (ctx->current_form_data_name)
    {
        zval *zpost = sw_zend_read_property(swoole_http_request_class_entry_ptr, zrequest_object, ZEND_STRL("post"), 1 TSRMLS_CC);
        if (ZVAL_IS_NULL(zpost))
        {
            swoole_http_server_array_init(post, request);
        }

        char *name = ctx->current_form_data_name;
        int len = ctx->current_form_data_name_len;

        if ((name[len-1] == ']') && (name[len-2] == '['))
        {
            zval *array_value;
            if (sw_zend_hash_find(Z_ARRVAL_P(zpost), name, len + 1, (void **) &array_value) == FAILURE)
            {
                SW_MAKE_STD_ZVAL(array_value);
                array_init(array_value);
                add_assoc_zval(zpost, name, array_value);
            }
            sw_add_next_index_stringl(array_value, swoole_http_form_data_buffer->str, swoole_http_form_data_buffer->length, 1);
        }
        else
        {
            sw_add_assoc_stringl_ex(zpost, ctx->current_form_data_name, ctx->current_form_data_name_len + 1,
                    swoole_http_form_data_buffer->str, swoole_http_form_data_buffer->length, 1);
        }

        efree(ctx->current_form_data_name);
        ctx->current_form_data_name = NULL;
        ctx->current_form_data_name_len = 0;
        swString_clear(swoole_http_form_data_buffer);
        return 0;
    }

    if (!ctx->current_input_name)
    {
        return 0;
    }

    zval *files = ctx->request.zfiles;
    if (ZVAL_IS_NULL(files))
    {
        return 0;
    }

    zval *multipart_header = NULL;
    sw_zend_hash_find(Z_ARRVAL_P(files), ctx->current_input_name, strlen(ctx->current_input_name) + 1, (void **) &multipart_header);

    if (p->fp != NULL)
    {
        long size = swoole_file_get_size((FILE*) p->fp);
        add_assoc_long(multipart_header, "size", size);

        fclose((FILE *)p->fp);
        p->fp = NULL;
    }

    efree(ctx->current_input_name);

    return 0;
}

static int multipart_body_end(multipart_parser* p)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = p->data;
    zval *files = ctx->request.zfiles;
    zval *value;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(files), value)
    {
        zval *file_path;
        if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("tmp_name"), (void **) &file_path) == SUCCESS)
        {
#if PHP_MAJOR_VERSION >= 7
            zend_string *tmp_name = zval_get_string(file_path);
            zend_hash_add_ptr(SG(rfc1867_uploaded_files), tmp_name, tmp_name);
#else
            char *temp_filename = Z_STRVAL_P(file_path);
            sw_zend_hash_add(SG(rfc1867_uploaded_files), temp_filename, Z_STRLEN_P(file_path) + 1, &temp_filename, sizeof(char *), NULL);
#endif
        }
    }
    SW_HASHTABLE_FOREACH_END();

    return 0;
}

static int http_request_on_body(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = parser->data;
    zval *zrequest_object = ctx->request.zobject;
    char *body;

    ctx->request.post_length = length;
    if (SwooleG.serv->http_parse_post && ctx->request.post_form_urlencoded)
    {
        zval *zpost;
        swoole_http_server_array_init(post, request);
        body = estrndup(at, length);

        sapi_module.treat_data(PARSE_STRING, body, zpost TSRMLS_CC);
    }
    else if (ctx->mt_parser != NULL)
    {
        multipart_parser *multipart_parser = ctx->mt_parser;
        size_t n = multipart_parser_execute(multipart_parser, at, length);
        if (n != length)
        {
            swoole_php_fatal_error(E_WARNING, "parse multipart body failed.");
        }
    }

    return 0;
}

static int http_request_message_complete(php_http_parser *parser)
{
    http_context *ctx = parser->data;
    ctx->request.version = parser->http_major * 100 + parser->http_minor;

    const char *vpath = ctx->request.path, *end = vpath + ctx->request.path_len, *p = end;
    ctx->request.ext = end;
    ctx->request.ext_len = 0;
    while (p > vpath)
    {
        --p;
        if (*p == '.')
        {
            ++p;
            ctx->request.ext = p;
            ctx->request.ext_len = end - p;
            break;
        }
    }
    ctx->request_read = 1;

    if (ctx->mt_parser)
    {
        multipart_parser_free(ctx->mt_parser);
        ctx->mt_parser = NULL;
    }

    return 0;
}

static int http_onReceive(swServer *serv, swEventData *req)
{
    if (swEventData_is_dgram(req->info.type))
    {
        return php_swoole_onReceive(serv, req);
    }

    int fd = req->info.fd;
    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        swWarn("connection[%d] is closed.", fd);
        return SW_ERR;
    }
    swListenPort *port = serv->connection_list[req->info.from_fd].object;
    //other server port
    if (!port->open_http_protocol)
    {
        return php_swoole_onReceive(serv, req);
    }
    //websocket client
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swoole_websocket_onMessage(req);
    }

    swoole_http_client *client = swArray_alloc(http_client_array, conn->fd);
    if (!client)
    {
        return SW_OK;
    }
    client->fd = fd;

#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        client->http2 = 1;
        return swoole_http2_onFrame(client, req);
    }
#endif

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_context *ctx = swoole_http_context_new(client TSRMLS_CC);
    php_http_parser *parser = &ctx->parser;
    zval *zserver = ctx->request.zserver;

    parser->data = ctx;

    php_http_parser_init(parser, PHP_HTTP_REQUEST);

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    php_swoole_get_recv_data(zdata, req, NULL, 0);

    swTrace("httpRequest %d bytes:\n---------------------------------------\n%s\n", (int)Z_STRLEN_P(zdata), Z_STRVAL_P(zdata));

    long n = php_http_parser_execute(parser, &http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    if (n < 0)
    {
        sw_zval_ptr_dtor(&zdata);
        bzero(client, sizeof(swoole_http_client));
        swWarn("php_http_parser_execute failed.");
        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            return SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
        }
    }
    else
    {
        zval *retval;
        zval **args[2];

        zval *zrequest_object = ctx->request.zobject;
        zval *zresponse_object = ctx->response.zobject;

        ctx->keepalive = php_http_should_keep_alive(parser);
        char *method_name = http_get_method_name(parser->method);

        sw_add_assoc_string(zserver, "request_method", method_name, 1);
        sw_add_assoc_stringl(zserver, "request_uri", ctx->request.path, ctx->request.path_len, 1);
        sw_add_assoc_stringl(zserver, "path_info", ctx->request.path, ctx->request.path_len, 1);
        sw_add_assoc_long_ex(zserver, ZEND_STRS("request_time"), SwooleGS->now);

        // Add REQUEST_TIME_FLOAT
        double now_float = swoole_microtime();
        sw_add_assoc_double_ex(zserver, ZEND_STRS("request_time_float"), now_float);

        swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
        if (!conn)
        {
            sw_zval_ptr_dtor(&zdata);
            swWarn("connection[%d] is closed.", fd);
            return SW_ERR;
        }

        zend_update_property(swoole_http_request_class_entry_ptr, zrequest_object, ZEND_STRL("data"), zdata TSRMLS_CC);
        ctx->request.zdata = sw_zend_read_property(swoole_http_request_class_entry_ptr, zrequest_object, ZEND_STRL("data"), 0 TSRMLS_CC);
        sw_copy_to_stack(ctx->request.zdata, ctx->request._zdata);

        add_assoc_long(ctx->request.zserver, "server_port", swConnection_get_port(&SwooleG.serv->connection_list[conn->from_fd]));
        add_assoc_long(ctx->request.zserver, "remote_port", swConnection_get_port(conn));
        sw_add_assoc_string(zserver, "remote_addr", swConnection_get_ip(conn), 1);

        if (ctx->request.version == 101)
        {
            sw_add_assoc_string(zserver, "server_protocol", "HTTP/1.1", 1);
        }
        else
        {
            sw_add_assoc_string(zserver, "server_protocol", "HTTP/1.0", 1);
        }

        sw_add_assoc_string(zserver, "server_software", SW_HTTP_SERVER_SOFTWARE, 1);

        zval *zcallback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onHandShake);
        //websocket handshake
        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION && zcallback == NULL)
        {
            return swoole_websocket_onHandshake(port, ctx);
        }

        args[0] = &zrequest_object;
        args[1] = &zresponse_object;

        int callback_type = 0;
        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            callback_type = SW_SERVER_CB_onHandShake;
            conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
        }
        else
        {
            callback_type = SW_SERVER_CB_onRequest;
            zcallback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onRequest);
            //no have onRequest callback
            if (zcallback == NULL)
            {
                swoole_websocket_onRequest(ctx);
                sw_zval_ptr_dtor(&zrequest_object);
                sw_zval_ptr_dtor(&zresponse_object);
                sw_zval_ptr_dtor(&zdata);
                bzero(client, sizeof(swoole_http_client));
                return SW_OK;
            }
        }

        zcallback = php_swoole_server_get_callback(serv, req->info.from_fd, callback_type);
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_error(E_WARNING, "onRequest handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        //websocket user handshake
        if (conn->websocket_status == WEBSOCKET_STATUS_HANDSHAKE)
        {
            //handshake success
            if (retval && Z_BVAL_P(retval))
            {
                conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
            }
        }
        bzero(client, sizeof(swoole_http_client));
        sw_zval_ptr_dtor(&zrequest_object);
        sw_zval_ptr_dtor(&zresponse_object);
        sw_zval_ptr_dtor(&zdata);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    return SW_OK;
}

static void http_onClose(swServer *serv, swDataHead *ev)
{
    int fd = ev->fd;

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        return;
    }
    swoole_http_client *client = swArray_fetch(http_client_array, conn->fd);
    if (!client)
    {
        return;
    }
#ifdef SW_USE_HTTP2
    if (client->http2)
    {
        swoole_http2_free(client);
    }
#endif
    zval *zcallback = php_swoole_server_get_callback(serv, ev->from_fd, SW_SERVER_CB_onClose);
    if (!zcallback)
    {
        return;
    }
    php_swoole_onClose(serv, ev);
}

void swoole_http_server_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_server_ce, "swoole_http_server", "Swoole\\Http\\Server", swoole_http_server_methods);
    swoole_http_server_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_http_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_http_server, "Swoole\\Http\\Server");

    zend_declare_property_long(swoole_http_server_class_entry_ptr, ZEND_STRL("global"), 0, ZEND_ACC_PRIVATE TSRMLS_CC);

    SWOOLE_INIT_CLASS_ENTRY(swoole_http_response_ce, "swoole_http_response", "Swoole\\Http\\Response", swoole_http_response_methods);
    swoole_http_response_class_entry_ptr = zend_register_internal_class(&swoole_http_response_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_http_response, "Swoole\\Http\\Response");

    SWOOLE_INIT_CLASS_ENTRY(swoole_http_request_ce, "swoole_http_request", "Swoole\\Http\\Request", swoole_http_request_methods);
    swoole_http_request_class_entry_ptr = zend_register_internal_class(&swoole_http_request_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_http_request, "Swoole\\Http\\Request");
}

static PHP_METHOD(swoole_http_server, on)
{
    zval *callback;
    zval *event_name;

    if (SwooleGS->start > 0)
    {
        swoole_php_error(E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &event_name, &callback) == FAILURE)
    {
        return;
    }

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);
#endif

    if (strncasecmp("request", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zend_update_property(swoole_http_server_class_entry_ptr, getThis(), ZEND_STRL("onRequest"), callback TSRMLS_CC);
        php_sw_server_callbacks[SW_SERVER_CB_onRequest] = sw_zend_read_property(swoole_http_server_class_entry_ptr, getThis(), ZEND_STRL("onRequest"), 0 TSRMLS_CC);
        sw_copy_to_stack(php_sw_server_callbacks[SW_SERVER_CB_onRequest], _php_sw_server_callbacks[SW_SERVER_CB_onRequest]);
    }
    else if (strncasecmp("handshake", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zend_update_property(swoole_http_server_class_entry_ptr, getThis(), ZEND_STRL("onHandshake"), callback TSRMLS_CC);
        php_sw_server_callbacks[SW_SERVER_CB_onHandShake] = sw_zend_read_property(swoole_http_server_class_entry_ptr, getThis(), ZEND_STRL("onHandshake"), 0 TSRMLS_CC);
        sw_copy_to_stack(php_sw_server_callbacks[SW_SERVER_CB_onHandShake], _php_sw_server_callbacks[SW_SERVER_CB_onHandShake]);
    }
    else
    {
        zval *obj = getThis();
        sw_zend_call_method_with_2_params(&obj, swoole_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}

http_context* swoole_http_context_new(swoole_http_client* client TSRMLS_DC)
{
    http_context *ctx = emalloc(sizeof(http_context));
    if (!ctx)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_MALLOC_FAIL, "emalloc(%ld) failed.", sizeof(http_context));
        return NULL;
    }
    bzero(ctx, sizeof(http_context));

    zval *zrequest_object;
#if PHP_MAJOR_VERSION >= 7
    zrequest_object = &ctx->request._zobject;
#else
    SW_ALLOC_INIT_ZVAL(zrequest_object);
#endif
    ctx->request.zobject = zrequest_object;
    object_init_ex(zrequest_object, swoole_http_request_class_entry_ptr);
    swoole_set_object(zrequest_object, ctx);

    zval *zresponse_object;
#if PHP_MAJOR_VERSION >= 7
    zresponse_object = &ctx->response._zobject;
#else
    SW_ALLOC_INIT_ZVAL(zresponse_object);
#endif
    ctx->response.zobject = zresponse_object;
    object_init_ex(zresponse_object, swoole_http_response_class_entry_ptr);
    swoole_set_object(zresponse_object, ctx);

    //socket fd
    zend_update_property_long(swoole_http_response_class_entry_ptr, zresponse_object, ZEND_STRL("fd"), client->fd TSRMLS_CC);
    zend_update_property_long(swoole_http_request_class_entry_ptr, zrequest_object, ZEND_STRL("fd"), client->fd TSRMLS_CC);

#if PHP_MEMORY_DEBUG
    php_vmstat.new_http_request ++;
#endif

    zval *zheader;
    swoole_http_server_array_init(header, request);

    zval *zserver;
    swoole_http_server_array_init(server, request);

    ctx->fd = client->fd;
    ctx->client = client;

    return ctx;
}

void swoole_http_context_free(http_context *ctx TSRMLS_DC)
{
    swoole_set_object(ctx->response.zobject, NULL);
    http_request *req = &ctx->request;
    if (req->path)
    {
        efree(req->path);
    }
#ifdef SW_USE_HTTP2
    if (req->post_buffer)
    {
        swString_free(req->post_buffer);
    }
#endif
    efree(ctx);
}

static char *http_status_message(int code)
{
    switch (code)
    {
    case 100:
        return "100 Continue";
    case 101:
        return "101 Switching Protocols";
    case 201:
        return "201 Created";
    case 202:
        return "202 Accepted";
    case 203:
        return "203 Non-Authoritative Information";
    case 204:
        return "204 No Content";
    case 205:
        return "205 Reset Content";
    case 206:
        return "206 Partial Content";
    case 207:
        return "207 Multi-Status";
    case 208:
        return "208 Already Reported";
    case 226:
        return "226 IM Used";
    case 300:
        return "300 Multiple Choices";
    case 301:
        return "301 Moved Permanently";
    case 302:
        return "302 Found";
    case 303:
        return "303 See Other";
    case 304:
        return "304 Not Modified";
    case 305:
        return "305 Use Proxy";
    case 307:
        return "307 Temporary Redirect";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 402:
        return "402 Payment Required";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 405:
        return "405 Method Not Allowed";
    case 406:
        return "406 Not Acceptable";
    case 407:
        return "407 Proxy Authentication Required";
    case 408:
        return "408 Request Timeout";
    case 409:
        return "409 Conflict";
    case 410:
        return "410 Gone";
    case 411:
        return "411 Length Required";
    case 412:
        return "412 Precondition Failed";
    case 413:
        return "413 Request Entity Too Large";
    case 414:
        return "414 Request URI Too Long";
    case 415:
        return "415 Unsupported Media Type";
    case 416:
        return "416 Requested Range Not Satisfiable";
    case 417:
        return "417 Expectation Failed";
    case 418:
        return "418 I'm a teapot";
    case 421:
        return "421 Misdirected Request";
    case 422:
        return "422 Unprocessable Entity";
    case 423:
        return "423 Locked";
    case 424:
        return "424 Failed Dependency";
    case 426:
        return "426 Upgrade Required";
    case 428:
        return "428 Precondition Required";
    case 429:
        return "429 Too Many Requests";
    case 431:
        return "431 Request Header Fields Too Large";
    case 500:
        return "500 Internal Server Error";
    case 501:
        return "501 Method Not Implemented";
    case 502:
        return "502 Bad Gateway";
    case 503:
        return "503 Service Unavailable";
    case 505:
        return "505 HTTP Version Not Supported";
    case 506:
        return "506 Variant Also Negotiates";
    case 507:
        return "507 Insufficient Storage";
    case 508:
        return "508 Loop Detected";
    case 510:
        return "510 Not Extended";
    case 511:
        return "511 Network Authentication Required";
    case 200:
    default:
        return "200 OK";
    }
}

static PHP_METHOD(swoole_http_server, start)
{
    int ret;

    if (SwooleGS->start > 0)
    {
        swoole_php_error(E_WARNING, "Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(getThis());
    php_swoole_register_callback(serv);

    if (serv->listen_list->open_websocket_protocol)
    {
        if (php_sw_server_callbacks[SW_SERVER_CB_onMessage] == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "require onMessage callback");
            RETURN_FALSE;
        }
        if (serv->listen_list->open_http2_protocol == 1)
        {
            swoole_php_fatal_error(E_ERROR, "cannot use http2 protocol in websocket server");
            RETURN_FALSE;
        }
    }
    else if (php_sw_server_callbacks[SW_SERVER_CB_onRequest] == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "require onRequest callback");
        RETURN_FALSE;
    }

    http_client_array = swArray_new(1024, sizeof(swoole_http_client));
    if (!http_client_array)
    {
        swoole_php_fatal_error(E_ERROR, "swArray_new(1024, %ld) failed.", sizeof(swoole_http_client));
        RETURN_FALSE;
    }

    swoole_http_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
        RETURN_FALSE;
    }

    swoole_http_form_data_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_form_data_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
        RETURN_FALSE;
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[3] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
        RETURN_FALSE;
    }
#endif

    serv->onReceive = http_onReceive;

    if (serv->listen_list->open_http2_protocol)
    {
        serv->onClose = http_onClose;
    }

    zval *zsetting = sw_zend_read_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
    {
        SW_MAKE_STD_ZVAL(zsetting);
        array_init(zsetting);
        zend_update_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("setting"), zsetting TSRMLS_CC);
    }

    add_assoc_bool(zsetting, "open_http_protocol", 1);
    add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
    add_assoc_bool(zsetting, "open_eof_check", 0);
    add_assoc_bool(zsetting, "open_length_check", 0);

    if (serv->listen_list->open_websocket_protocol)
    {
        add_assoc_bool(zsetting, "open_websocket_protocol", 1);
    }

    serv->listen_list->open_http_protocol = 1;
    serv->listen_list->open_mqtt_protocol = 0;
    serv->listen_list->open_eof_check = 0;
    serv->listen_list->open_length_check = 0;

    serv->ptr2 = getThis();

    //for is_uploaded_file and move_uploaded_file
    ALLOC_HASHTABLE(SG(rfc1867_uploaded_files));
    zend_hash_init(SG(rfc1867_uploaded_files), 8, NULL, NULL, 0);

    php_swoole_server_before_start(serv, getThis() TSRMLS_CC);

    ret = swServer_start(serv);
    if (ret < 0)
    {
        swoole_php_fatal_error(E_ERROR, "start server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_request, rawcontent)
{
    zval *zfd = sw_zend_read_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    if (ZVAL_IS_NULL(zfd))
    {
        swoole_php_error(E_WARNING, "http client not exists.");
        RETURN_FALSE;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

    http_request *req = &ctx->request;
    if (req->post_length > 0)
    {
        SW_RETVAL_STRINGL(Z_STRVAL_P(req->zdata) + Z_STRLEN_P(req->zdata) - req->post_length, req->post_length, 1);
    }
#ifdef SW_USE_HTTP2
    else if (req->post_buffer)
    {
        SW_RETVAL_STRINGL(req->post_buffer->str, req->post_buffer->length, 1);
    }
#endif
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_http_request, __destruct)
{
    zval *zfiles = sw_zend_read_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("files"), 1 TSRMLS_CC);
    //upload files
    if (zfiles && Z_TYPE_P(zfiles) == IS_ARRAY)
    {
        zval *value;
        char *key;
        int keytype;
        uint32_t keylen;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zfiles), key, keylen, keytype, value)
        {
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            zval *file_path;
            if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("tmp_name"), (void **) &file_path) == SUCCESS)
            {
                unlink(Z_STRVAL_P(file_path));
                sw_zend_hash_del(SG(rfc1867_uploaded_files), Z_STRVAL_P(file_path), Z_STRLEN_P(file_path) + 1);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void)key;
        (void)keylen;
    }
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_http_response, write)
{
    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        return;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        return;
    }

    if (!ctx->send_header)
    {
        ctx->chunk = 1;
        swString_clear(swoole_http_buffer);
        http_build_header(ctx, getThis(), swoole_http_buffer, -1 TSRMLS_CC);
        if (swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length) < 0)
        {
            ctx->chunk = 0;
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }

    swString http_body;
    int length = php_swoole_get_send_data(zdata, &http_body.str TSRMLS_CC);

    if (length < 0)
    {
        RETURN_FALSE;
    }
    else if (length == 0)
    {
       swoole_php_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }
    else
    {
        http_body.length = length;
    }

    swString_clear(swoole_http_buffer);

    char *hex_string;
    int hex_len;

#ifdef SW_HAVE_ZLIB
    if (ctx->gzip_enable)
    {
        http_response_compress(&http_body, ctx->gzip_level);

        hex_string = swoole_dec2hex(swoole_zlib_buffer->length, 16);
        hex_len = strlen(hex_string);

        //"%*s\r\n%*s\r\n", hex_len, hex_string, body.length, body.str
        swString_append_ptr(swoole_http_buffer, hex_string, hex_len);
        swString_append_ptr(swoole_http_buffer, SW_STRL("\r\n") - 1);
        swString_append(swoole_http_buffer, swoole_zlib_buffer);
        swString_append_ptr(swoole_http_buffer, SW_STRL("\r\n") - 1);
    }
    else
#endif
    {
        hex_string = swoole_dec2hex(http_body.length, 16);
        hex_len = strlen(hex_string);

        //"%*s\r\n%*s\r\n", hex_len, hex_string, body.length, body.str
        swString_append_ptr(swoole_http_buffer, hex_string, hex_len);
        swString_append_ptr(swoole_http_buffer, SW_STRL("\r\n") - 1);
        swString_append_ptr(swoole_http_buffer, http_body.str, http_body.length);
        swString_append_ptr(swoole_http_buffer, SW_STRL("\r\n") - 1);
    }

    int ret = swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
    sw_strdup_free(hex_string);
    SW_CHECK_RETURN(ret);
}

static http_context* http_get_context(zval *object, int check_end TSRMLS_DC)
{
    http_context *ctx = swoole_get_object(object);
    if (!ctx)
    {
        swoole_php_fatal_error(E_WARNING, "Http request is end.");
        return NULL;
    }
    if (check_end && ctx->end)
    {
        swoole_php_fatal_error(E_WARNING, "Http request is end.");
        return NULL;
    }
    return ctx;
}

static void http_build_header(http_context *ctx, zval *object, swString *response, int body_length TSRMLS_DC)
{
    assert(ctx->send_header == 0);

    char buf[SW_HTTP_HEADER_MAX_SIZE];
    int n;
    char *date_str;

    /**
     * http status line
     */
    n = snprintf(buf, sizeof(buf), "HTTP/1.1 %s\r\n", http_status_message(ctx->response.status));
    swString_append_ptr(response, buf, n);

    /**
     * http header
     */
    zval *header = ctx->response.zheader;
    if (header)
    {
        int flag = 0x0;
        HashTable *ht = Z_ARRVAL_P(header);
        zval *value = NULL;
        char *key = NULL;
        uint32_t keylen = 0;
        int type;

        SW_HASHTABLE_FOREACH_START2(ht, key, keylen, type, value)
        {
            if (!key)
            {
                break;
            }
            if (strncasecmp(key, "Server", keylen) == 0)
            {
                flag |= HTTP_RESPONSE_SERVER;
            }
            else if (strncasecmp(key, "Connection", keylen) == 0)
            {
                flag |= HTTP_RESPONSE_CONNECTION;
            }
            else if (strncasecmp(key, "Content-Length", keylen) == 0)
            {
                flag |= HTTP_RESPONSE_CONTENT_LENGTH;
            }
            else if (strncasecmp(key, "Date", keylen) == 0)
            {
                flag |= HTTP_RESPONSE_DATE;
            }
            else if (strncasecmp(key, "Content-Type", keylen) == 0)
            {
                flag |= HTTP_RESPONSE_CONTENT_TYPE;
            }
            n = snprintf(buf, sizeof(buf), "%*s: %*s\r\n", keylen - 1, key, Z_STRLEN_P(value), Z_STRVAL_P(value));
            swString_append_ptr(response, buf, n);
        }
        SW_HASHTABLE_FOREACH_END();
        (void)type;

        if (!(flag & HTTP_RESPONSE_SERVER))
        {
            swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\n"));
        }
        if (!(flag & HTTP_RESPONSE_CONNECTION))
        {
            if (ctx->keepalive)
            {
                swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
            }
            else
            {
                swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
            }
        }
        if (ctx->request.method == PHP_HTTP_OPTIONS)
        {
            swString_append_ptr(response, ZEND_STRL("Allow: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS\r\nContent-Length: 0\r\n"));
        }
        else if (body_length > 0)
        {

#ifdef SW_HAVE_ZLIB
            if (ctx->gzip_enable)
            {
                body_length = swoole_zlib_buffer->length;
            }
#endif
            n = snprintf(buf, sizeof(buf), "Content-Length: %d\r\n", body_length);
            swString_append_ptr(response, buf, n);

            if (!(flag & HTTP_RESPONSE_CONTENT_TYPE))
            {
                swString_append_ptr(response, ZEND_STRL("Content-Type: text/html\r\n"));
            }
        }
        if (!(flag & HTTP_RESPONSE_DATE))
        {
            date_str = sw_php_format_date(ZEND_STRL(SW_HTTP_DATE_FORMAT), SwooleGS->now, 0 TSRMLS_CC);
            n = snprintf(buf, sizeof(buf), "Date: %s\r\n", date_str);
            swString_append_ptr(response, buf, n);
            efree(date_str);
        }
    }
    else
    {
        swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\nContent-Type: text/html\r\n"));
        if (ctx->keepalive)
        {
            swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
        }
        else
        {
            swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
        }

        date_str = sw_php_format_date(ZEND_STRL(SW_HTTP_DATE_FORMAT), SwooleGS->now, 0 TSRMLS_CC);
        n = snprintf(buf, sizeof(buf), "Date: %s\r\n", date_str);
        efree(date_str);
        swString_append_ptr(response, buf, n);

        if (ctx->request.method == PHP_HTTP_OPTIONS)
        {
            n = snprintf(buf, sizeof(buf), "Allow: GET, POST, PUT, DELETE, HEAD, OPTIONS\r\nContent-Length: %d\r\n", 0);
            swString_append_ptr(response, buf, n);
        }
        else if (body_length > 0)
        {
#ifdef SW_HAVE_ZLIB
            if (ctx->gzip_enable)
            {
                body_length = swoole_zlib_buffer->length;
            }
#endif
            n = snprintf(buf, sizeof(buf), "Content-Length: %d\r\n", body_length);
            swString_append_ptr(response, buf, n);
        }
    }

    if (ctx->chunk)
    {
        swString_append_ptr(response, SW_STRL("Transfer-Encoding: chunked\r\n") - 1);
    }
    //http cookies
    if (ctx->response.zcookie)
    {
        zval *value;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ctx->response.zcookie), value)
        {
            if (Z_TYPE_P(value) != IS_STRING)
            {
                continue;
            }
            swString_append_ptr(response, SW_STRL("Set-Cookie: ") - 1);
            swString_append_ptr(response, Z_STRVAL_P(value), Z_STRLEN_P(value));
            swString_append_ptr(response, SW_STRL("\r\n") - 1);
        }
        SW_HASHTABLE_FOREACH_END();
    }
    //http compress
    if (ctx->gzip_enable)
    {
#ifdef SW_HTTP_COMPRESS_GZIP
        swString_append_ptr(response, SW_STRL("Content-Encoding: gzip\r\n") - 1);
#else
        swString_append_ptr(response, SW_STRL("Content-Encoding: deflate\r\n") - 1);
#endif
    }
    swString_append_ptr(response, ZEND_STRL("\r\n"));
    ctx->send_header = 1;
}

#ifdef SW_HAVE_ZLIB
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    return (voidpf)safe_emalloc(items, size, 0);
}

void php_zlib_free(voidpf opaque, voidpf address)
{
    efree((void*)address);
}

static int http_response_compress(swString *body, int level)
{
    assert(level > 0 || level < 10);

    size_t memory_size = ((size_t) ((double) body->length * (double) 1.015)) + 10 + 8 + 4 + 1;

    if (memory_size > swoole_zlib_buffer->size)
    {
        swString_extend(swoole_zlib_buffer, memory_size);
    }

    z_stream zstream;
    memset(&zstream, 0, sizeof(zstream));

    //deflate: -0xf, gzip: 0x1f
#ifdef SW_HTTP_COMPRESS_GZIP
    int encoding = 0x1f;
#else
    int encoding =  -0xf;
#endif

    int status;
    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    if (Z_OK == deflateInit2(&zstream, level, Z_DEFLATED, encoding, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY))
    {
        zstream.next_in = (Bytef *) body->str;
        zstream.next_out = (Bytef *) swoole_zlib_buffer->str;
        zstream.avail_in = body->length;
        zstream.avail_out = swoole_zlib_buffer->size;

        status = deflate(&zstream, Z_FINISH);
        deflateEnd(&zstream);

        if (Z_STREAM_END == status)
        {
            swoole_zlib_buffer->length = zstream.total_out;
            return SW_OK;
        }
    }
    else
    {
        swWarn("deflateInit2() failed.");
    }
    return SW_ERR;
}
#endif

static PHP_METHOD(swoole_http_response, end)
{
    zval *zdata = NULL;
    int ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|z", &zdata) == FAILURE)
    {
        return;
    }

    swString http_body;

    if (zdata)
    {
        int length = php_swoole_get_send_data(zdata, &http_body.str TSRMLS_CC);

        if (length < 0)
        {
            RETURN_FALSE;
        }
        else
        {
            http_body.length = length;
        }
    }
    else
    {
        http_body.length = 0;
        http_body.str = NULL;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->http2)
    {
        swoole_http2_do_response(ctx, &http_body);
        RETURN_TRUE;
    }
#endif

    if (ctx->chunk)
    {
        ret = swServer_tcp_send(SwooleG.serv, ctx->fd, SW_STRL("0\r\n\r\n") - 1);
        if (ret < 0)
        {
            RETURN_FALSE;
        }
        ctx->chunk = 0;
    }
    //no http chunk
    else
    {
        swString_clear(swoole_http_buffer);
#ifdef SW_HAVE_ZLIB
        if (ctx->gzip_enable)
        {
            if (http_body.length > 0)
            {
                http_response_compress(&http_body, ctx->gzip_level);
            }
            else
            {
                ctx->gzip_enable = 0;
            }
        }
#endif
        http_build_header(ctx, getThis(), swoole_http_buffer, http_body.length TSRMLS_CC);
        if (http_body.length > 0)
        {
#ifdef SW_HAVE_ZLIB
            if (ctx->gzip_enable)
            {
                swString_append(swoole_http_buffer, swoole_zlib_buffer);
            }
            else
#endif
            {
                swString_append(swoole_http_buffer, &http_body);
            }
        }

        ret = swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
        if (ret < 0)
        {
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }
    if (!ctx->keepalive)
    {
        SwooleG.serv->factory.end(&SwooleG.serv->factory, ctx->fd);
    }
    swoole_http_context_free(ctx TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, sendfile)
{
    char *filename;
    zend_size_t filename_length;
    long offset = 0;
    int ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &filename, &filename_length, &offset) == FAILURE)
    {
        return;
    }

    if (filename_length <= 0)
    {
        swoole_php_error(E_WARNING, "file name is empty.");
        RETURN_FALSE;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

#ifdef SW_HAVE_ZLIB
    if (ctx->gzip_enable)
    {
        swoole_php_error(E_ERROR, "cannot use sendfile when enable gzip compression.");
        RETURN_FALSE;
    }
#endif

    if (ctx->chunk)
    {
        swoole_php_error(E_ERROR, "cannot use sendfile when enable Http-Chunk.");
        RETURN_FALSE;
    }

    struct stat file_stat;
    if (stat(filename, &file_stat) < 0)
    {
        swoole_php_sys_error(E_WARNING, "stat(%s) failed.", filename);
        RETURN_FALSE;
    }

    if (file_stat.st_size <= offset)
    {
        swoole_php_error(E_WARNING, "file[offset=%ld] is empty.", offset);
        RETURN_FALSE;
    }

    swString_clear(swoole_http_buffer);
    http_build_header(ctx, getThis(), swoole_http_buffer, file_stat.st_size - offset TSRMLS_CC);

    ret = swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
    if (ret < 0)
    {
        ctx->send_header = 0;
        RETURN_FALSE;
    }

    ret = swServer_tcp_sendfile(SwooleG.serv, ctx->fd, filename, filename_length, offset);
    if (ret < 0)
    {
        ctx->send_header = 0;
        RETURN_FALSE;
    }
    if (!ctx->keepalive)
    {
        SwooleG.serv->factory.end(&SwooleG.serv->factory, ctx->fd);
    }
    swoole_http_context_free(ctx TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, cookie)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    long expires = 0;
    int encode = 1;
    zend_bool secure = 0, httponly = 0;
    zend_size_t name_len, value_len = 0, path_len = 0, domain_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|slssbb", &name, &name_len, &value, &value_len, &expires,
                &path, &path_len, &domain, &domain_len, &secure, &httponly) == FAILURE)
    {
        return;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

    zval *zcookie = ctx->response.zcookie;
    zval *zresponse_object = ctx->response.zobject;
    if (!zcookie)
    {
        swoole_http_server_array_init(cookie, response);
    }

    char *cookie, *encoded_value = NULL;
    int len = 0;
    char *dt;

    if (name && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        swoole_php_error(E_WARNING, "Cookie names cannot contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    len += name_len;
    if (encode && value)
    {
        int encoded_value_len;
        encoded_value = sw_php_url_encode(value, value_len, &encoded_value_len);
        len += encoded_value_len;
    }
    else if (value)
    {
        encoded_value = estrdup(value);
        len += value_len;
    }
    if (path)
    {
        len += path_len;
    }
    if (domain)
    {
        len += domain_len;
    }

    cookie = emalloc(len + 100);

    if (value && value_len == 0)
    {
        dt = sw_php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, 1, 0 TSRMLS_CC);
        snprintf(cookie, len + 100, "%s=deleted; expires=%s", name, dt);
        efree(dt);
    }
    else
    {
        snprintf(cookie, len + 100, "%s=%s", name, value ? encoded_value : "");
        if (expires > 0)
        {
            const char *p;
            strlcat(cookie, "; expires=", len + 100);
            dt = sw_php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, expires, 0 TSRMLS_CC);
            p = zend_memrchr(dt, '-', strlen(dt));
            if (!p || *(p + 5) != ' ')
            {
                efree(dt);
                efree(cookie);
                efree(encoded_value);
                swoole_php_error(E_WARNING, "Expiry date cannot have a year greater than 9999");
                RETURN_FALSE;
            }
            strlcat(cookie, dt, len + 100);
            efree(dt);
        }
    }
    if (encoded_value)
    {
        efree(encoded_value);
    }
    if (path && path_len > 0)
    {
        strlcat(cookie, "; path=", len + 100);
        strlcat(cookie, path, len + 100);
    }
    if (domain && domain_len > 0)
    {
        strlcat(cookie, "; domain=", len + 100);
        strlcat(cookie, domain, len + 100);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", len + 100);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", len + 100);
    }
    sw_add_next_index_stringl(zcookie, cookie, strlen(cookie), 0);
#if PHP_MAJOR_VERSION >= 7
    efree(cookie);
#endif
}

static PHP_METHOD(swoole_http_response, rawcookie)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    long expires = 0;
    int encode = 0;
    zend_bool secure = 0, httponly = 0;
    zend_size_t name_len, value_len = 0, path_len = 0, domain_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|slssbb", &name, &name_len, &value, &value_len, &expires,
                &path, &path_len, &domain, &domain_len, &secure, &httponly) == FAILURE)
    {
        return;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

    zval *zcookie = ctx->response.zcookie;
    zval *zresponse_object = ctx->response.zobject;
    if (!zcookie)
    {
        swoole_http_server_array_init(cookie, response);
    }

    char *cookie, *encoded_value = NULL;
    int len = 0;
    char *dt;

    if (name && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        swoole_php_error(E_WARNING, "Cookie names cannot contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    len += name_len;
    if (encode && value)
    {
        int encoded_value_len;
        encoded_value = sw_php_url_encode(value, value_len, &encoded_value_len);
        len += encoded_value_len;
    }
    else if (value)
    {
        encoded_value = estrdup(value);
        len += value_len;
    }
    if (path)
    {
        len += path_len;
    }
    if (domain)
    {
        len += domain_len;
    }

    cookie = emalloc(len + 100);

    if (value && value_len == 0)
    {
        dt = sw_php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, 1, 0 TSRMLS_CC);
        snprintf(cookie, len + 100, "%s=deleted; expires=%s", name, dt);
        efree(dt);
    }
    else
    {
        snprintf(cookie, len + 100, "%s=%s", name, value ? encoded_value : "");
        if (expires > 0)
        {
            const char *p;
            strlcat(cookie, "; expires=", len + 100);
            dt = sw_php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, expires, 0 TSRMLS_CC);
            p = zend_memrchr(dt, '-', strlen(dt));
            if (!p || *(p + 5) != ' ')
            {
                efree(dt);
                efree(cookie);
                efree(encoded_value);
                swoole_php_error(E_WARNING, "Expiry date cannot have a year greater than 9999");
                RETURN_FALSE;
            }
            strlcat(cookie, dt, len + 100);
            efree(dt);
        }
    }
    if (encoded_value)
    {
        efree(encoded_value);
    }
    if (path && path_len > 0)
    {
        strlcat(cookie, "; path=", len + 100);
        strlcat(cookie, path, len + 100);
    }
    if (domain && domain_len > 0)
    {
        strlcat(cookie, "; domain=", len + 100);
        strlcat(cookie, domain, len + 100);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", len + 100);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", len + 100);
    }
    sw_add_next_index_stringl(zcookie, cookie, strlen(cookie), 0);
#if PHP_MAJOR_VERSION >= 7
    efree(cookie);
#endif
}

static PHP_METHOD(swoole_http_response, status)
{
    long http_status;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &http_status) == FAILURE)
    {
        return;
    }

    http_context *client = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!client)
    {
        RETURN_FALSE;
    }

    client->response.status = http_status;
}

static PHP_METHOD(swoole_http_response, header)
{
    char *k, *v;
    zend_size_t klen, vlen;
    zend_bool ucwords = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b", &k, &klen, &v, &vlen, &ucwords) == FAILURE)
    {
        return;
    }

    http_context *ctx = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!ctx)
    {
        RETURN_FALSE;
    }

    zval *zheader = ctx->response.zheader;
    zval *zresponse_object = ctx->response.zobject;
    if (!zheader)
    {
        swoole_http_server_array_init(header, response);
    }
    if (klen > SW_HTTP_HEADER_KEY_SIZE - 1)
    {
        swoole_php_error(E_WARNING, "header key is too long.");
        RETURN_FALSE;
    }
    if (vlen > SW_HTTP_HEADER_VALUE_SIZE)
    {
        swoole_php_error(E_WARNING, "header value is too long.");
        RETURN_FALSE;
    }

    if (ucwords)
    {
        char key_buf[SW_HTTP_HEADER_KEY_SIZE];
        memcpy(key_buf, k, klen);
        key_buf[klen] = '\0';
        if (ctx->http2)
        {
            swoole_strtolower(key_buf, klen);
        }
        else
        {
            http_header_key_format(key_buf, klen);
        }
        sw_add_assoc_stringl_ex(zheader, key_buf, klen + 1, v, vlen, 1);
    }
    else
    {
        sw_add_assoc_stringl_ex(zheader, k, klen + 1, v, vlen, 1);
    }

}

#ifdef SW_HAVE_ZLIB
static PHP_METHOD(swoole_http_response, gzip)
{
    long level = Z_DEFAULT_COMPRESSION;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &level) == FAILURE)
    {
        return;
    }

    http_context *context = http_get_context(getThis(), 0 TSRMLS_CC);
    if (!context)
    {
        RETURN_FALSE;
    }

    if (context->send_header)
    {
        swoole_php_fatal_error(E_WARNING, "must use before send header.");
        RETURN_FALSE;
    }

    if (level > 9)
    {
        level = 9;
    }
    if (level < 0)
    {
        level = 0;
    }

    context->gzip_enable = 1;
    context->gzip_level = level;
}
#endif

static PHP_METHOD(swoole_http_response, __destruct)
{
    http_context *context = swoole_get_object(getThis());
    if (context)
    {
        zval *zobject = getThis();
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_response_class_entry_ptr, NULL, "end", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
}
