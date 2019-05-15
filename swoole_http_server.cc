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

#include "php_swoole_cxx.h"
#include "swoole_http.h"

extern "C"
{
#include "ext/standard/url.h"
#include "ext/standard/sha1.h"
#include "ext/standard/php_var.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_math.h"
#include "ext/standard/php_array.h"
#include "ext/date/php_date.h"
#include "ext/standard/md5.h"
}

#include "main/rfc1867.h"
#include "main/php_variables.h"

#include "websocket.h"
#include "connection.h"
#include "base64.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_HAVE_BROTLI
#include <brotli/encode.h>
#endif

#ifdef SW_USE_HTTP2
#include "http2.h"
#endif

using namespace swoole;

swString *swoole_http_buffer;
#ifdef SW_HAVE_ZLIB
swString *swoole_zlib_buffer;
#endif
swString *swoole_http_form_data_buffer;

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

zend_class_entry *swoole_http_server_ce;
zend_object_handlers swoole_http_server_handlers;

zend_class_entry *swoole_http_response_ce;
static zend_object_handlers swoole_http_response_handlers;

zend_class_entry *swoole_http_request_ce;
static zend_object_handlers swoole_http_request_handlers;

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(swoole_http_parser *parser);
static int http_request_message_complete(swoole_http_parser *parser);

static int multipart_body_on_header_field(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_header_value(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_data(multipart_parser* p, const char *at, size_t length);
static int multipart_body_on_header_complete(multipart_parser* p);
static int multipart_body_on_data_end(multipart_parser* p);

static http_context* http_get_context(zval *zobject, const bool check_end);
static void http_build_header(http_context *, zval *zobject, swString *response, int body_length);

static bool http_context_send_data(struct _http_context* ctx, const char *data, size_t length);
static bool http_context_disconnect(struct _http_context* ctx);

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

static inline char* http_trim_double_quote(char *ptr, int *len)
{
    int i;
    char *tmp = ptr;

    //ltrim('"')
    for (i = 0; i < *len; i++)
    {
        if (tmp[0] == '"')
        {
            (*len)--;
            tmp++;
            continue;
        }
        else
        {
            break;
        }
    }
    //rtrim('"')
    for (i = (*len) - 1; i >= 0; i--)
    {
        if (tmp[i] == '"')
        {
            tmp[i] = 0;
            (*len)--;
            continue;
        }
        else
        {
            break;
        }
    }
    return tmp;
}

static PHP_METHOD(swoole_http_request, getData);
static PHP_METHOD(swoole_http_request, rawContent);
static PHP_METHOD(swoole_http_request, __destruct);

static PHP_METHOD(swoole_http_response, write);
static PHP_METHOD(swoole_http_response, end);
static PHP_METHOD(swoole_http_response, sendfile);
static PHP_METHOD(swoole_http_response, redirect);
static PHP_METHOD(swoole_http_response, cookie);
static PHP_METHOD(swoole_http_response, rawcookie);
static PHP_METHOD(swoole_http_response, header);
static PHP_METHOD(swoole_http_response, initHeader);
static PHP_METHOD(swoole_http_response, detach);
static PHP_METHOD(swoole_http_response, create);
#ifdef SW_USE_HTTP2
static PHP_METHOD(swoole_http_response, trailer);
static PHP_METHOD(swoole_http_response, ping);
#endif
static PHP_METHOD(swoole_http_response, status);
static PHP_METHOD(swoole_http_response, __destruct);

static sw_inline const char* http_get_method_name(int method)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_status, 0, 0, 1)
    ZEND_ARG_INFO(0, http_code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_header, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, ucwords)
ZEND_END_ARG_INFO()

#ifdef SW_USE_HTTP2
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_trailer, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()
#endif

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
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_redirect, 0, 0, 1)
    ZEND_ARG_INFO(0, location)
    ZEND_ARG_INFO(0, http_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_create, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

static const swoole_http_parser_settings http_parser_settings =
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
    NULL,
};

const zend_function_entry swoole_http_request_methods[] =
{
    PHP_ME(swoole_http_request, rawContent, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, getData, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_response_methods[] =
{
    PHP_ME(swoole_http_response, initHeader, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, cookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, rawcookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, status, arginfo_swoole_http_response_status, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, header, arginfo_swoole_http_response_header, ZEND_ACC_PUBLIC)
#ifdef SW_USE_HTTP2
    PHP_ME(swoole_http_response, trailer, arginfo_swoole_http_response_trailer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, ping, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_http_response, write, arginfo_swoole_http_response_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, end, arginfo_swoole_http_response_end, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, sendfile, arginfo_swoole_http_response_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, redirect, arginfo_swoole_http_response_redirect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, detach, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, create, arginfo_swoole_http_response_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_http_response, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = (http_context *) parser->data;
    ctx->request.path = estrndup(at, length);
    ctx->request.path_len = length;
    return 0;
}

const swoole_http_parser_settings* swoole_http_get_parser_setting()
{
    return &http_parser_settings;
}

static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = (http_context *) parser->data;
    add_assoc_stringl_ex(ctx->request.zserver, ZEND_STRL("query_string"), (char *) at, length);
    //parse url params
    sapi_module.treat_data(
        PARSE_STRING,
        estrndup(at, length), // it will be freed by treat_data
        swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.zget, ZEND_STRL("get"))
    );
    return 0;
}

static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = (http_context *) parser->data;
    ctx->current_header_name = (char *) at;
    ctx->current_header_name_len = length;
    return 0;
}

int swoole_http_parse_form_data(http_context *ctx, const char *boundary_str, int boundary_len)
{
    multipart_parser *mt_parser = multipart_parser_init(boundary_str, boundary_len, &mt_parser_settings);
    if (!mt_parser)
    {
        swoole_php_fatal_error(E_WARNING, "multipart_parser_init() failed");
        return SW_ERR;
    }

    ctx->mt_parser = mt_parser;
    mt_parser->data = ctx;

    return SW_OK;
}

void swoole_http_parse_cookie(zval *zarray, const char *at, size_t length)
{
    char keybuf[SW_HTTP_COOKIE_KEYLEN];
    char valbuf[SW_HTTP_COOKIE_VALLEN];
    char *_c = (char *) at;

    char *_value;
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
                swWarn("cookie[%.*s...] name length %d is exceed the max name len %d", 8, (char *) at + j, klen, SW_HTTP_COOKIE_KEYLEN);
                return;
            }
            memcpy(keybuf, (char *) at + j, klen - 1);
            keybuf[klen - 1] = 0;

            j = i + 1;
            state = 1;
        }
        else if (state == 1 && *_c == ';')
        {
            vlen = i - j;
            if (vlen >= SW_HTTP_COOKIE_VALLEN)
            {
                swWarn("cookie[%s]'s value[v=%.*s...] length %d is exceed the max value len %d", keybuf, 8, (char *) at + j, vlen, SW_HTTP_COOKIE_VALLEN);
                return;
            }
            memcpy(valbuf, (char *) at + j, vlen);
            valbuf[vlen] = 0;
            _value = http_trim_double_quote(valbuf, &vlen);
            vlen = php_url_decode(_value, vlen);
            if (klen > 1)
            {
                add_assoc_stringl_ex(zarray, keybuf, klen - 1, _value, vlen);
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
    if (j < (off_t) length)
    {
        vlen = i - j;
        if (klen >= SW_HTTP_COOKIE_KEYLEN)
        {
            swWarn("cookie[%.*s...] name length %d is exceed the max name len %d", 8, keybuf, klen, SW_HTTP_COOKIE_KEYLEN);
            return;
        }
        keybuf[klen - 1] = 0;
        if (vlen >= SW_HTTP_COOKIE_VALLEN)
        {
            swWarn("cookie[%s]'s value[v=%.*s...] length %d is exceed the max value len %d", keybuf, 8, (char *) at + j, vlen, SW_HTTP_COOKIE_VALLEN);
            return;
        }
        memcpy(valbuf, (char *) at + j, vlen);
        valbuf[vlen] = 0;
        _value = http_trim_double_quote(valbuf, &vlen);
        vlen = php_url_decode(_value, vlen);
        if (klen > 1)
        {
            add_assoc_stringl_ex(zarray, keybuf, klen - 1, _value, vlen);
        }
    }
}

static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length)
{
    size_t offset = 0;
    http_context *ctx = (http_context *) parser->data;
    zval *zheader = ctx->request.zheader;
    size_t header_len = ctx->current_header_name_len;
    char *header_name = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (ctx->parse_cookie && strncmp(header_name, "cookie", header_len) == 0)
    {
        zval *zcookie = swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.zcookie, ZEND_STRL("cookie"));
        swoole_http_parse_cookie(zcookie, at, length);
        efree(header_name);
        return 0;
    }
    else if (strncmp(header_name, "upgrade", header_len) == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        swConnection *conn = swWorker_get_connection(SwooleG.serv, ctx->fd);
        if (!conn)
        {
            swWarn("connection[%d] is closed", ctx->fd);
            return SW_ERR;
        }
        swListenPort *port = (swListenPort *) SwooleG.serv->connection_list[conn->from_fd].object;
        if (port->open_websocket_protocol)
        {
            conn->websocket_status = WEBSOCKET_STATUS_CONNECTION;
        }
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
                // start offset
                offset = sizeof("multipart/form-data;") - 1;
                while (at[offset] == ' ')
                {
                    offset++;
                }
                offset += sizeof("boundary=") - 1;

                int boundary_len = length - offset;
                char *boundary_str = (char *) at + offset;

                // find ';'
                char *tmp = (char*) memchr(boundary_str, ';', boundary_len);
                if (tmp)
                {
                    boundary_len = tmp - boundary_str;
                }
                if (boundary_len <= 0)
                {
                    swWarn("invalid multipart/form-data body fd:%d", ctx->fd);
                    return 0;
                }
                // trim '"'
                if (boundary_len >= 2 && boundary_str[0] == '"' && *(boundary_str + boundary_len - 1) == '"')
                {
                    boundary_str++;
                    boundary_len -= 2;
                }
                swoole_http_parse_form_data(ctx, boundary_str, boundary_len);
            }
        }
    }
#ifdef SW_HAVE_ZLIB
    else if (ctx->enable_compression && strncmp(header_name, "accept-encoding", header_len) == 0)
    {
        swoole_http_get_compression_method(ctx, at, length);
    }
#endif

    add_assoc_stringl_ex(zheader, header_name, header_len, (char *) at, length);

    efree(header_name);

    return 0;
}

static int http_request_on_headers_complete(swoole_http_parser *parser)
{
    http_context *ctx = (http_context *) parser->data;
    ctx->current_header_name = NULL;

    return 0;
}

static int multipart_body_on_header_field(multipart_parser* p, const char *at, size_t length)
{
    http_context *ctx = (http_context *) p->data;
    return http_request_on_header_field(&ctx->parser, at, length);
}

static int multipart_body_on_header_value(multipart_parser* p, const char *at, size_t length)
{
    char value_buf[SW_HTTP_COOKIE_KEYLEN];
    int value_len;

    http_context *ctx = (http_context *) p->data;
    /**
     * Hash collision attack
     */
    if (ctx->input_var_num > PG(max_input_vars))
    {
        swoole_php_error(E_WARNING, "Input variables exceeded " ZEND_LONG_FMT ". "
                "To increase the limit change max_input_vars in php.ini", PG(max_input_vars));
        return SW_OK;
    }
    else
    {
        ctx->input_var_num++;
    }

    size_t header_len = ctx->current_header_name_len;
    char *headername = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (strncasecmp(headername, "content-disposition", header_len) == 0)
    {
        //not form data
        if (swoole_strnpos((char *) at, length, (char *) ZEND_STRL("form-data;")) < 0)
        {
            return SW_OK;
        }

        zval tmp_array;
        array_init(&tmp_array);
        swoole_http_parse_cookie(&tmp_array, (char *) at + sizeof("form-data;") - 1, length - sizeof("form-data;") + 1);

        zval *zform_name;
        if (!(zform_name = zend_hash_str_find(Z_ARRVAL(tmp_array), ZEND_STRL("name"))))
        {
            return SW_OK;
        }

        if (Z_STRLEN_P(zform_name) >= SW_HTTP_COOKIE_KEYLEN)
        {
            swWarn("form_name[%s] is too large", Z_STRVAL_P(zform_name));
            return SW_OK;
        }

        strncpy(value_buf, Z_STRVAL_P(zform_name), Z_STRLEN_P(zform_name));
        value_len = Z_STRLEN_P(zform_name);
        char *tmp = http_trim_double_quote(value_buf, &value_len);

        zval *zfilename;
        //POST form data
        if (!(zfilename = zend_hash_str_find(Z_ARRVAL(tmp_array), ZEND_STRL("filename"))))
        {
            ctx->current_form_data_name = estrndup(tmp, value_len);
            ctx->current_form_data_name_len = value_len;
        }
        //upload file
        else
        {
            if (Z_STRLEN_P(zfilename) >= SW_HTTP_COOKIE_KEYLEN)
            {
                swWarn("filename[%s] is too large", Z_STRVAL_P(zfilename));
                return SW_OK;
            }
            ctx->current_input_name = estrndup(tmp, value_len);

            zval *z_multipart_header = sw_malloc_zval();
            array_init(z_multipart_header);

            add_assoc_string(z_multipart_header, "name", (char *) "");
            add_assoc_string(z_multipart_header, "type", (char *) "");
            add_assoc_string(z_multipart_header, "tmp_name", (char *) "");
            add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_OK);
            add_assoc_long(z_multipart_header, "size", 0);

            strncpy(value_buf, Z_STRVAL_P(zfilename), Z_STRLEN_P(zfilename));
            value_len = Z_STRLEN_P(zfilename);
            tmp = http_trim_double_quote(value_buf, &value_len);

            add_assoc_stringl(z_multipart_header, "name", tmp, value_len);

            ctx->current_multipart_header = z_multipart_header;
        }
        zval_ptr_dtor(&tmp_array);
    }

    if (strncasecmp(headername, "content-type", header_len) == 0 && ctx->current_multipart_header)
    {
        add_assoc_stringl(ctx->current_multipart_header, "type", (char * ) at, length);
    }

    efree(headername);

    return 0;
}

static int multipart_body_on_data(multipart_parser* p, const char *at, size_t length)
{
    http_context *ctx = (http_context *) p->data;
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
    if (n != (off_t) length)
    {
        zval *z_multipart_header = ctx->current_multipart_header;
        add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_CANT_WRITE);

        fclose((FILE *) p->fp);
        p->fp = NULL;

        swSysWarn("write upload file failed");
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
    http_context *ctx = (http_context *) p->data;
    if (!ctx->current_input_name)
    {
        return 0;
    }

    zval *z_multipart_header = ctx->current_multipart_header;
    zval *zerr = NULL;
    if (!(zerr = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("error"))))
    {
        return 0;
    }
    if (Z_TYPE_P(zerr) == IS_LONG && Z_LVAL_P(zerr) != HTTP_UPLOAD_ERR_OK)
    {
        return 0;
    }

    char file_path[SW_HTTP_UPLOAD_TMPDIR_SIZE];
    snprintf(file_path, SW_HTTP_UPLOAD_TMPDIR_SIZE, "%s/swoole.upfile.XXXXXX", SwooleG.serv->upload_tmp_dir);
    int tmpfile = swoole_tmpfile(file_path);
    if (tmpfile < 0)
    {
        return 0;
    }

    FILE *fp = fdopen(tmpfile, "wb+");
    if (fp == NULL)
    {
        add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_NO_TMP_DIR);
        swSysWarn("fopen(%s) failed", file_path);
        return 0;
    }

    p->fp = fp;
    add_assoc_string(z_multipart_header, "tmp_name", file_path);

    size_t file_path_len = strlen(file_path);
    add_next_index_stringl(
        swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.ztmpfiles, ZEND_STRL("tmpfiles")),
        file_path, file_path_len
    );
    // support is_upload_file
    zend_hash_str_add_ptr(SG(rfc1867_uploaded_files), file_path, file_path_len, (char *) file_path);

    return 0;
}

static int multipart_body_on_data_end(multipart_parser* p)
{
    http_context *ctx = (http_context *) p->data;

    if (ctx->current_form_data_name)
    {
        php_register_variable_safe(
            ctx->current_form_data_name,
            swoole_http_form_data_buffer->str,
            swoole_http_form_data_buffer->length,
            swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post"))
        );

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

    zval *z_multipart_header = ctx->current_multipart_header;
    if (p->fp != NULL)
    {
        long size = swoole_file_get_size((FILE *) p->fp);
        add_assoc_long(z_multipart_header, "size", size);
        if (size == 0)
        {
            add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_NO_FILE);
        }

        fclose((FILE *) p->fp);
        p->fp = NULL;
    }

    php_register_variable_ex(
        ctx->current_input_name,
        z_multipart_header,
        swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.zfiles, ZEND_STRL("files"))
    );

    efree(ctx->current_input_name);
    ctx->current_input_name = NULL;
    efree(ctx->current_multipart_header);
    ctx->current_multipart_header = NULL;

    return 0;
}

static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = (http_context *) parser->data;

    ctx->request.post_length = length;

    if (ctx->parse_body && ctx->request.post_form_urlencoded)
    {
        sapi_module.treat_data(
            PARSE_STRING,
            estrndup(at, length), // do not free, it will be freed by treat_data
            swoole_http_init_and_read_property(swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post"))
        );
    }
    else if (ctx->mt_parser != NULL)
    {
        multipart_parser *multipart_parser = ctx->mt_parser;
        char *c = (char *) at;
        while (*c == '\r' && *(c + 1) == '\n')
        {
            c += 2;
            length -= 2;
        }
        size_t n = multipart_parser_execute(multipart_parser, c, length);
        if (n != length)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_INVALID_REQUEST, "parse multipart body failed, n=%zu", n);
        }
    }

    return 0;
}

static int http_request_message_complete(swoole_http_parser *parser)
{
    http_context *ctx = (http_context *) parser->data;
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

    if (ctx->mt_parser)
    {
        multipart_parser_free(ctx->mt_parser);
        ctx->mt_parser = NULL;
    }

    zval *zserver = ctx->request.zserver;
    add_assoc_string(zserver, "request_method", (char *) http_get_method_name(parser->method));
    add_assoc_stringl_ex(zserver, ZEND_STRL("request_uri"), ctx->request.path, ctx->request.path_len);

    // path_info should be decoded
    zend_string * zstr_path = zend_string_init(ctx->request.path, ctx->request.path_len, 0);
    ZSTR_LEN(zstr_path) = php_url_decode(ZSTR_VAL(zstr_path), ZSTR_LEN(zstr_path));
    add_assoc_str_ex(zserver, ZEND_STRL("path_info"), zstr_path);

    add_assoc_long_ex(zserver, ZEND_STRL("request_time"), time(NULL));
    add_assoc_double_ex(zserver, ZEND_STRL("request_time_float"), swoole_microtime());

    add_assoc_string(zserver, "server_protocol", (char *) (ctx->request.version == 101 ? "HTTP/1.1" : "HTTP/1.0"));

    ctx->keepalive = swoole_http_should_keep_alive(parser);
    ctx->completed = 1;

    return 0;
}

int php_swoole_http_onReceive(swServer *serv, swEventData *req)
{
    int fd = req->info.fd;
    int from_fd = req->info.from_fd;

    swConnection *conn = swServer_connection_verify_no_ssl(serv, fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[%d] is closed", fd);
        return SW_ERR;
    }

    swListenPort *port = (swListenPort *) serv->connection_list[from_fd].object;
    //other server port
    if (!port->open_http_protocol)
    {
        return php_swoole_onReceive(serv, req);
    }
    //websocket client
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swoole_websocket_onMessage(serv, req);
    }
#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        return swoole_http2_server_onFrame(conn, req);
    }
#endif

    http_context *ctx = swoole_http_context_new(fd);
    swoole_http_parser *parser = &ctx->parser;
    zval *zserver = ctx->request.zserver;

    parser->data = ctx;
    ctx->parse_cookie = serv->http_parse_cookie;
    ctx->parse_body = serv->http_parse_post;
#ifdef SW_HAVE_ZLIB
    ctx->enable_compression = serv->http_compression;
#endif
    ctx->private_data = serv;
    ctx->send = http_context_send_data;
    ctx->close = http_context_disconnect;

    zval *zdata = sw_malloc_zval();
    php_swoole_get_recv_data(zdata, req, NULL, 0);

    swTrace("http request from %d with %d bytes: <<EOF\n%.*s\nEOF", fd, (int)Z_STRLEN_P(zdata), (int)Z_STRLEN_P(zdata), Z_STRVAL_P(zdata));

    swoole_http_parser_init(parser, PHP_HTTP_REQUEST);
    long n = swoole_http_parser_execute(parser, &http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));

    if (n < 0)
    {
        sw_zval_free(zdata);
        swWarn("swoole_http_parser_execute failed");
        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            return serv->close(serv, fd, 1);
        }
    }
    else
    {
        zval args[2], *zrequest_object = &args[0], *zresponse_object = &args[1];
        args[0] = *ctx->request.zobject;
        args[1] = *ctx->response.zobject;

        swConnection *conn = swWorker_get_connection(serv, fd);
        if (!conn)
        {
            sw_zval_free(zdata);
            swWarn("connection[%d] is closed", fd);
            return SW_ERR;
        }

        add_assoc_long(zserver, "server_port", swConnection_get_port(&serv->connection_list[conn->from_fd]));
        add_assoc_long(zserver, "remote_port", swConnection_get_port(conn));
        add_assoc_string(zserver, "remote_addr", (char *) swConnection_get_ip(conn));
        add_assoc_long(zserver, "master_time", conn->last_time);

        swoole_set_property(zrequest_object, 0, zdata);

        // begin to check and call registerd callback
        zend_fcall_info_cache *fci_cache = NULL;

        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            fci_cache = php_swoole_server_get_fci_cache(serv, from_fd, SW_SERVER_CB_onHandShake);
            if (fci_cache == NULL)
            {
                swoole_websocket_onHandshake(serv, port, ctx);
                goto _dtor_and_return;
            }
            else
            {
                conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
                ctx->upgrade = 1;
            }
        }
        else
        {
            fci_cache = php_swoole_server_get_fci_cache(serv, from_fd, SW_SERVER_CB_onRequest);
            if (fci_cache == NULL)
            {
                swoole_websocket_onRequest(ctx);
                goto _dtor_and_return;
            }
        }

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, SwooleG.enable_coroutine)))
        {
            swoole_php_error(E_WARNING, "%s->onRequest handler error", ZSTR_VAL(swoole_http_server_ce->name));
#ifdef SW_HTTP_SERVICE_UNAVAILABLE_PACKET
            serv->send(serv, fd, (char *) SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET));
#endif
            serv->close(serv, fd, 0);
        }

        _dtor_and_return:
        zval_ptr_dtor(zrequest_object);
        zval_ptr_dtor(zresponse_object);
    }

    return SW_OK;
}

void php_swoole_http_onClose(swServer *serv, swDataHead *ev)
{
    int fd = ev->fd;
    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        return;
    }
#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        swoole_http2_server_session_free(conn);
    }
#endif
    php_swoole_onClose(serv, ev);
}

void swoole_http_server_init(int module_number)
{
    SW_INIT_CLASS_ENTRY_EX(swoole_http_server, "Swoole\\Http\\Server", "swoole_http_server", NULL, NULL, swoole_server);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_server, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_server, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_server);

    zend_declare_property_null(swoole_http_server_ce, ZEND_STRL("onRequest"), ZEND_ACC_PRIVATE);

    SW_INIT_CLASS_ENTRY(swoole_http_request, "Swoole\\Http\\Request", "swoole_http_request", NULL, swoole_http_request_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_request, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_request, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_request);

    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
#ifdef SW_USE_HTTP2
    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
#endif
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("server"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("request"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("get"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("files"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("post"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("tmpfiles"), ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY(swoole_http_response, "Swoole\\Http\\Response", "swoole_http_response", NULL, swoole_http_response_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_response, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_response, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_response);

    zend_declare_property_long(swoole_http_response_ce, ZEND_STRL("fd"), 0,  ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
#ifdef SW_USE_HTTP2
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("trailer"), ZEND_ACC_PUBLIC);
#endif
}

http_context* swoole_http_context_new(int fd)
{
    http_context *ctx = (http_context *) ecalloc(1, sizeof(http_context));
    if (UNEXPECTED(!ctx))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_MALLOC_FAIL, "ecalloc(%ld) failed", sizeof(http_context));
        return NULL;
    }

    zval *zrequest_object = &ctx->request._zobject;
    ctx->request.zobject = zrequest_object;
    object_init_ex(zrequest_object, swoole_http_request_ce);
    swoole_set_object(zrequest_object, ctx);

    zval *zresponse_object = &ctx->response._zobject;
    ctx->response.zobject = zresponse_object;
    object_init_ex(zresponse_object, swoole_http_response_ce);
    swoole_set_object(zresponse_object, ctx);

    zend_update_property_long(swoole_http_request_ce, zrequest_object, ZEND_STRL("fd"), fd);
    zend_update_property_long(swoole_http_response_ce, zresponse_object, ZEND_STRL("fd"), fd);

#if PHP_MEMORY_DEBUG
    php_vmstat.new_http_request ++;
#endif

    swoole_http_init_and_read_property(swoole_http_request_ce, zrequest_object, &ctx->request.zserver, ZEND_STRL("server"));
    swoole_http_init_and_read_property(swoole_http_request_ce, zrequest_object, &ctx->request.zheader, ZEND_STRL("header"));
    ctx->fd = fd;

    return ctx;
}

void swoole_http_context_free(http_context *ctx)
{
    swoole_set_object(ctx->response.zobject, NULL);
    http_request *req = &ctx->request;
    http_response *res = &ctx->response;
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
    if (res->reason)
    {
        efree(res->reason);
    }
    efree(ctx);
}

void php_swoole_http_server_init_global_variant()
{
    swoole_http_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
        return;
    }

    swoole_http_form_data_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_form_data_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
        return;
    }

    //for is_uploaded_file and move_uploaded_file
    if (!SG(rfc1867_uploaded_files))
    {
        ALLOC_HASHTABLE(SG(rfc1867_uploaded_files));
        zend_hash_init(SG(rfc1867_uploaded_files), 8, NULL, NULL, 0);
    }
}

static PHP_METHOD(swoole_http_request, rawContent)
{
    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    http_request *req = &ctx->request;
    if (req->post_length > 0)
    {
        zval *zdata = (zval *) swoole_get_property(getThis(), 0);
        RETVAL_STRINGL(Z_STRVAL_P(zdata) + Z_STRLEN_P(zdata) - req->post_length, req->post_length);
    }
#ifdef SW_USE_HTTP2
    else if (req->post_buffer)
    {
        RETVAL_STRINGL(req->post_buffer->str, req->post_buffer->length);
    }
#endif
    else
    {
        RETURN_EMPTY_STRING();
    }
}

static PHP_METHOD(swoole_http_request, getData)
{
    zval *zdata = (zval *) swoole_get_property(getThis(), 0);
    if (zdata)
    {
        RETURN_STRINGL(Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_http_request, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    zval *ztmpfiles = sw_zend_read_property(swoole_http_request_ce, getThis(), ZEND_STRL("tmpfiles"), 0);
    //upload files
    if (ztmpfiles && Z_TYPE_P(ztmpfiles) == IS_ARRAY)
    {
        zval *z_file_path;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztmpfiles), z_file_path)
        {
            if (Z_TYPE_P(z_file_path) != IS_STRING)
            {
                continue;
            }
            unlink(Z_STRVAL_P(z_file_path));
            if (SG(rfc1867_uploaded_files))
            {
                zend_hash_str_del(SG(rfc1867_uploaded_files), Z_STRVAL_P(z_file_path), Z_STRLEN_P(z_file_path));
            }
        }
        SW_HASHTABLE_FOREACH_END();
    }
    zval *zdata = (zval *) swoole_get_property(getThis(), 0);
    if (zdata)
    {
        sw_zval_free(zdata);
        swoole_set_property(getThis(), 0, NULL);
    }
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_http_response, write)
{
    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->stream)
    {
        swoole_php_error(E_WARNING, "Http2 client does not support HTTP-CHUNK");
        RETURN_FALSE;
    }
#endif

#ifdef SW_HAVE_ZLIB
    ctx->accept_compression = 0;
#endif

    ctx->private_data_2 = return_value;

    if (!ctx->send_header)
    {
        ctx->chunk = 1;
        swString_clear(swoole_http_buffer);
        http_build_header(ctx, getThis(), swoole_http_buffer, -1);
        if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length))
        {
            ctx->chunk = 0;
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }

    swString http_body;
    size_t length = php_swoole_get_send_data(zdata, &http_body.str);

    if (length == 0)
    {
        swoole_php_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }
    else
    {
        http_body.length = length;
    }

    // Why not enable compression?
    // If both compression and chunked encoding are enabled,
    // then the content stream is first compressed, then chunked;
    // so the chunk encoding itself is not compressed,
    // **and the data in each chunk is not compressed individually.**
    // The remote endpoint then decodes the stream by concatenating the chunks and uncompressing the result.
    swString_clear(swoole_http_buffer);
    char *hex_string = swoole_dec2hex(http_body.length, 16);
    int hex_len = strlen(hex_string);
    //"%.*s\r\n%.*s\r\n", hex_len, hex_string, body.length, body.str
    swString_append_ptr(swoole_http_buffer, hex_string, hex_len);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("\r\n"));
    swString_append_ptr(swoole_http_buffer, http_body.str, http_body.length);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("\r\n"));
    sw_free(hex_string);

    RETURN_BOOL(ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length));
}

static http_context* http_get_context(zval *zobject, const bool check_end)
{
    http_context *ctx = (http_context *) swoole_get_object(zobject);
    if (!ctx || (check_end && ctx->end))
    {
        swoole_php_fatal_error(E_WARNING, "http context is unavailable (maybe it has been ended or detached)");
        return NULL;
    }
    return ctx;
}

static void http_build_header(http_context *ctx, zval *zobject, swString *response, int body_length)
{
    char *buf = SwooleTG.buffer_stack->str;
    size_t l_buf = SwooleTG.buffer_stack->size;
    int n;
    char *date_str;

    assert(ctx->send_header == 0);

    /**
     * http status line
     */
    if (!ctx->response.reason)
    {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %s\r\n", swHttp_get_status_message(ctx->response.status));
    }
    else
    {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %d %s\r\n", ctx->response.status, ctx->response.reason);
    }
    swString_append_ptr(response, buf, n);

    /**
     * http header
     */
    zval *zheader = sw_zend_read_property(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("header"), 0);
    uint32_t header_flag = 0x0;
    if (ZVAL_IS_ARRAY(zheader))
    {
        HashTable *ht = Z_ARRVAL_P(zheader);
        zval *zvalue = NULL;
        char *key = NULL;
        uint32_t keylen = 0;
        int type;

        SW_HASHTABLE_FOREACH_START2(ht, key, keylen, type, zvalue)
        {
            // TODO: numeric key name neccessary?
            if (!key)
            {
                continue;
            }
            if (strncasecmp(key, "Server", keylen) == 0)
            {
                header_flag |= HTTP_HEADER_SERVER;
            }
            else if (strncasecmp(key, "Connection", keylen) == 0)
            {
                header_flag |= HTTP_HEADER_CONNECTION;
            }
            else if (strncasecmp(key, "Date", keylen) == 0)
            {
                header_flag |= HTTP_HEADER_DATE;
            }
            else if (strncasecmp(key, "Content-Length", keylen) == 0)
            {
                continue; // ignore
            }
            else if (strncasecmp(key, "Content-Type", keylen) == 0)
            {
                header_flag |= HTTP_HEADER_CONTENT_TYPE;
            }
            else if (strncasecmp(key, "Transfer-Encoding", keylen) == 0)
            {
                header_flag |= HTTP_HEADER_TRANSFER_ENCODING;
            }
            if (!ZVAL_IS_NULL(zvalue))
            {
                zend::string str_value(zvalue);
                n = sw_snprintf(buf, l_buf, "%.*s: %.*s\r\n", (int) keylen, key, (int) str_value.len(), str_value.val());
                swString_append_ptr(response, buf, n);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void)type;
    }

    if (!(header_flag & HTTP_HEADER_SERVER))
    {
        swString_append_ptr(response, ZEND_STRL("Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"));
    }
    //websocket protocol
    if (ctx->upgrade == 1)
    {
        swString_append_ptr(response, ZEND_STRL("\r\n"));
        ctx->send_header = 1;
        return;
    }
    if (!(header_flag & HTTP_HEADER_CONNECTION))
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
    if (!(header_flag & HTTP_HEADER_CONTENT_TYPE))
    {
        swString_append_ptr(response, ZEND_STRL("Content-Type: text/html\r\n"));
    }
    if (!(header_flag & HTTP_HEADER_DATE))
    {
        date_str = sw_php_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), time(NULL), 0);
        n = sw_snprintf(buf, l_buf, "Date: %s\r\n", date_str);
        swString_append_ptr(response, buf, n);
        efree(date_str);
    }

    if (ctx->chunk)
    {
        if (!(header_flag & HTTP_HEADER_TRANSFER_ENCODING))
        {
            swString_append_ptr(response, ZEND_STRL("Transfer-Encoding: chunked\r\n"));
        }
    }
    else
    // Content-Length
    {
#ifdef SW_HAVE_ZLIB
        if (ctx->accept_compression)
        {
            body_length = swoole_zlib_buffer->length;
        }
#endif
        n = sw_snprintf(buf, l_buf, "Content-Length: %d\r\n", body_length);
        swString_append_ptr(response, buf, n);
    }

    //http cookies
    zval *zcookie = sw_zend_read_property(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("cookie"), 0);
    if (ZVAL_IS_ARRAY(zcookie))
    {
        zval *zvalue;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zcookie), zvalue)
        {
            if (Z_TYPE_P(zvalue) != IS_STRING)
            {
                continue;
            }
            swString_append_ptr(response, ZEND_STRL("Set-Cookie: "));
            swString_append_ptr(response, Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
            swString_append_ptr(response, ZEND_STRL("\r\n"));
        }
        SW_HASHTABLE_FOREACH_END();
    }
#ifdef SW_HAVE_ZLIB
    //http compress
    if (ctx->accept_compression)
    {
        const char *content_encoding = swoole_http_get_content_encoding(ctx);
        swString_append_ptr(response, ZEND_STRL("Content-Encoding: "));
        swString_append_ptr(response, (char*) content_encoding, strlen(content_encoding));
        swString_append_ptr(response, ZEND_STRL("\r\n"));
    }
#endif
    swString_append_ptr(response, ZEND_STRL("\r\n"));
    ctx->send_header = 1;
}

#ifdef SW_HAVE_ZLIB
void swoole_http_get_compression_method(http_context *ctx, const char *accept_encoding, size_t length)
{
#ifdef SW_HAVE_BROTLI
    if (swoole_strnpos((char *) accept_encoding, length, (char *) ZEND_STRL("br")) >= 0)
    {
        ctx->enable_compression = 1;
        ctx->compression_level = SwooleG.serv->http_compression_level;
        ctx->compression_method = HTTP_COMPRESS_BR;
    }
    else
#endif
    if (swoole_strnpos((char *) accept_encoding, length, (char *) ZEND_STRL("gzip")) >= 0)
    {
        ctx->accept_compression = 1;
        ctx->compression_method = HTTP_COMPRESS_GZIP;
    }
    else if (swoole_strnpos((char *) accept_encoding, length, (char *) ZEND_STRL("deflate")) >= 0)
    {
        ctx->accept_compression = 1;
        ctx->compression_method = HTTP_COMPRESS_DEFLATE;
    }
    else
    {
        ctx->accept_compression = 0;
    }
}

const char* swoole_http_get_content_encoding(http_context *ctx)
{
    if (ctx->compression_method == HTTP_COMPRESS_GZIP)
    {
       return "gzip";
    }
    else if (ctx->compression_method == HTTP_COMPRESS_DEFLATE)
    {
        return "deflate";
    }
#ifdef SW_HAVE_BROTLI
    else if (ctx->compression_method == HTTP_COMPRESS_BR)
    {
        return "br";
    }
#endif
    else
    {
        return NULL;
    }
}

int swoole_http_response_compress(swString *body, int method, int level)
{
    int encoding;
    //gzip: 0x1f
    if (method == HTTP_COMPRESS_GZIP)
    {
        encoding = 0x1f;
    }
    //deflate: -0xf
    else if (method == HTTP_COMPRESS_DEFLATE)
    {
        encoding = -0xf;
    }
#ifdef SW_HAVE_BROTLI
    else if (method == HTTP_COMPRESS_BR)
    {
        if (level < BROTLI_MIN_QUALITY)
        {
            level = BROTLI_MAX_QUALITY;
        }
        else if (level > BROTLI_MAX_QUALITY)
        {
            level = BROTLI_MAX_QUALITY;
        }

        size_t memory_size = BrotliEncoderMaxCompressedSize(body->length);
        if (memory_size > swoole_zlib_buffer->size)
        {
            if (swString_extend(swoole_zlib_buffer, memory_size) < 0)
            {
                return SW_ERR;
            }
        }

        size_t input_size = body->length;
        const uint8_t *input_buffer = (uint8_t *) body->str;
        size_t encoded_size = swoole_zlib_buffer->size;
        uint8_t *encoded_buffer = (uint8_t *) swoole_zlib_buffer->str;

        if (BROTLI_TRUE != BrotliEncoderCompress(
            level, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            input_size, input_buffer, &encoded_size, encoded_buffer
        ))
        {
            swWarn("BrotliEncoderCompress() failed");
            return SW_ERR;
        }
        else
        {
            swoole_zlib_buffer->length = encoded_size;
            return SW_OK;
        }
    }
#endif
    else
    {
        swWarn("Unknown compression method");
        return SW_ERR;
    }

    // ==== ZLIB ====
    if (level == Z_NO_COMPRESSION)
    {
        level = Z_DEFAULT_COMPRESSION;
    }
    else if (level > Z_BEST_COMPRESSION)
    {
        level = Z_BEST_COMPRESSION;
    }

    size_t memory_size = ((size_t) ((double) body->length * (double) 1.015)) + 10 + 8 + 4 + 1;
    if (memory_size > swoole_zlib_buffer->size)
    {
        if (swString_extend(swoole_zlib_buffer, memory_size) < 0)
        {
            return SW_ERR;
        }
    }

    z_stream zstream;
    memset(&zstream, 0, sizeof(zstream));

    int status;
    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    int retval = deflateInit2(&zstream, level, Z_DEFLATED, encoding, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

    if (Z_OK == retval)
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
        swWarn("deflateInit2() failed, Error: [%d]", retval);
    }
    return SW_ERR;
}
#endif

static PHP_METHOD(swoole_http_response, initHeader)
{
    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }
    zval *zresponse_object = ctx->response.zobject;
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.zheader, ZEND_STRL("header"));
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.zcookie, ZEND_STRL("cookie"));
#ifdef SW_USE_HTTP2
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.ztrailer, ZEND_STRL("trailer"));
#endif
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, end)
{
    zval *zdata = NULL;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_EX(zdata, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    swString http_body;

    if (zdata)
    {
        http_body.length = php_swoole_get_send_data(zdata, &http_body.str);
    }
    else
    {
        http_body.length = 0;
        http_body.str = NULL;
    }

#ifdef SW_USE_HTTP2
    if (ctx->stream)
    {
        RETURN_BOOL(swoole_http2_server_do_response(ctx, &http_body) == SW_OK);
    }
#endif

    ctx->private_data_2 = return_value;

    if (ctx->chunk)
    {
        if (!ctx->send(ctx, ZEND_STRL("0\r\n\r\n")))
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
        if (ctx->accept_compression)
        {
            if (http_body.length == 0 || swoole_http_response_compress(&http_body, ctx->compression_method, ctx->compression_level) != SW_OK)
            {
                ctx->accept_compression = 0;
            }
        }
#endif
        http_build_header(ctx, getThis(), swoole_http_buffer, http_body.length);

        char *send_body_str;
        size_t send_body_len;

        if (http_body.length > 0)
        {
#ifdef SW_HAVE_ZLIB
            if (ctx->accept_compression)
            {
                send_body_str = swoole_zlib_buffer->str;
                send_body_len = swoole_zlib_buffer->length;
            }
            else
#endif
            {
                send_body_str = http_body.str;
                send_body_len = http_body.length;
            }
            /**
             *
             */
#ifdef SW_HTTP_SEND_TWICE
            if (send_body_len < SwooleG.pagesize)
#endif
            {
                if (swString_append_ptr(swoole_http_buffer, send_body_str, send_body_len) < 0)
                {
                    ctx->send_header = 0;
                    RETURN_FALSE;
                }
            }
#ifdef SW_HTTP_SEND_TWICE
            else
            {
                if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length))
                {
                    ctx->send_header = 0;
                    RETURN_FALSE;
                }
                if (!ctx->send(ctx,  send_body_str, send_body_len))
                {
                    ctx->close(ctx);
                    swoole_http_context_free(ctx);
                    RETURN_FALSE;
                }
                goto _skip_copy;
            }
#endif
        }

        if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length))
        {
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }

#ifdef SW_HTTP_SEND_TWICE
    _skip_copy:
#endif
    if (ctx->upgrade)
    {
        swConnection *conn = swWorker_get_connection(SwooleG.serv, ctx->fd);
        if (conn && conn->websocket_status == WEBSOCKET_STATUS_HANDSHAKE)
        {
            if (ctx->response.status == 101)
            {
                conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
            }
            else
            {
                /* connection should be closed when handshake failed */
                conn->websocket_status = WEBSOCKET_STATUS_NONE;
                ctx->keepalive = 0;
            }
        }
    }
    if (!ctx->keepalive)
    {
        ctx->close(ctx);
    }
    swoole_http_context_free(ctx);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, sendfile)
{
    char *filename;
    size_t filename_length;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &filename, &filename_length, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (filename_length <= 0)
    {
        swoole_php_error(E_WARNING, "file name is empty");
        RETURN_FALSE;
    }

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

#ifdef SW_HAVE_ZLIB
    ctx->accept_compression = 0;
#endif

    if (ctx->chunk)
    {
        swoole_php_fatal_error(E_ERROR, "can't use sendfile when Http-Chunk is enabled");
        RETURN_FALSE;
    }

    struct stat file_stat;
    if (stat(filename, &file_stat) < 0)
    {
        swoole_php_sys_error(E_WARNING, "stat(%s) failed", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0)
    {
        swoole_php_sys_error(E_WARNING, "can't send empty file[%s]", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_php_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        swoole_php_sys_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }

    swString_clear(swoole_http_buffer);
    http_build_header(ctx, getThis(), swoole_http_buffer, length);

    swServer *serv = SwooleG.serv;

    int ret = serv->send(serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
    if (ret < 0)
    {
        ctx->send_header = 0;
        RETURN_FALSE;
    }
    ret = serv->sendfile(serv, ctx->fd, filename, filename_length, offset, length);
    if (ret < 0)
    {
        ctx->send_header = 0;
        RETURN_FALSE;
    }
    if (!ctx->keepalive)
    {
        serv->close(serv, ctx->fd, 0);
    }
    swoole_http_context_free(ctx);
    RETURN_TRUE;
}

static void swoole_http_response_cookie(INTERNAL_FUNCTION_PARAMETERS, const bool url_encode)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    zend_long expires = 0;
    size_t name_len, value_len = 0, path_len = 0, domain_len = 0;
    zend_bool secure = 0, httponly = 0;

    ZEND_PARSE_PARAMETERS_START(1, 7)
        Z_PARAM_STRING(name, name_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(value, value_len)
        Z_PARAM_LONG(expires)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_STRING(domain, domain_len)
        Z_PARAM_BOOL(secure)
        Z_PARAM_BOOL(httponly)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    int cookie_size = name_len /* + value_len */ + path_len + domain_len + 100;
    char *cookie = NULL, *date = NULL;

    if (name_len > 0 && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        swoole_php_error(E_WARNING, "Cookie names can't contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }
    if (value_len == 0)
    {
        cookie = (char *) emalloc(cookie_size);
        date = sw_php_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), 1, 0);
        snprintf(cookie, cookie_size, "%s=deleted; expires=%s", name, date);
        efree(date);
    }
    else
    {
        if (url_encode)
        {
            char *encoded_value;
            int encoded_value_len;
            encoded_value = sw_php_url_encode(value, value_len, &encoded_value_len);
            cookie_size += encoded_value_len;
            cookie = (char *) emalloc(cookie_size);
            snprintf(cookie, cookie_size, "%s=%s", name, encoded_value);
            efree(encoded_value);
        }
        else
        {
            cookie_size += value_len;
            cookie = (char *) emalloc(cookie_size);
            snprintf(cookie, cookie_size, "%s=%s", name, value);
        }
        if (expires > 0)
        {
            strlcat(cookie, "; expires=", cookie_size);
            date = sw_php_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), expires, 0);
            const char *p = (const char *) zend_memrchr(date, '-', strlen(date));
            if (!p || *(p + 5) != ' ')
            {
                swoole_php_error(E_WARNING, "Expiry date can't be a year greater than 9999");
                efree(date);
                efree(cookie);
                RETURN_FALSE;
            }
            strlcat(cookie, date, cookie_size);
            efree(date);
        }
    }
    if (path_len > 0)
    {
        strlcat(cookie, "; path=", cookie_size);
        strlcat(cookie, path, cookie_size);
    }
    if (domain_len > 0)
    {
        strlcat(cookie, "; domain=", cookie_size);
        strlcat(cookie, domain, cookie_size);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", cookie_size);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", cookie_size);
    }
    add_next_index_stringl(
        swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.zcookie, ZEND_STRL("cookie")),
        cookie, strlen(cookie)
    );
    efree(cookie);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, cookie)
{
    swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_METHOD(swoole_http_response, rawcookie)
{
    swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_http_response, status)
{
    zend_long http_status;
    char* reason = NULL;
    size_t reason_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(http_status)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(reason, reason_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    ctx->response.status = http_status;
    if (reason_len > 0)
    {
        ctx->response.reason = (char *) emalloc(SW_MEM_ALIGNED_SIZE(reason_len + 1));
        strncpy(ctx->response.reason, reason, reason_len);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, header)
{
    char *k, *v;
    size_t klen, vlen;
    zend_bool ucwords = 1;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(k, klen)
        Z_PARAM_STRING_EX(v, vlen, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(ucwords)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1))
    {
        swoole_php_error(E_WARNING, "header key is too long");
        RETURN_FALSE;
    }
    if (UNEXPECTED(vlen > SW_HTTP_HEADER_VALUE_SIZE - 1))
    {
        swoole_php_error(E_WARNING, "header value is too long");
        RETURN_FALSE;
    }
    zval *zheader = swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.zheader, ZEND_STRL("header"));
    if (ucwords)
    {
        char key_buf[SW_HTTP_HEADER_KEY_SIZE];
        strncpy(key_buf, k, klen)[klen] = '\0';
#ifdef SW_USE_HTTP2
        if (ctx->stream)
        {
            swoole_strtolower(key_buf, klen);
        }
        else
#endif
        {
            http_header_key_format(key_buf, klen);
        }
        if (UNEXPECTED(!v))
        {
            add_assoc_null_ex(zheader, key_buf, klen);
        }
        else
        {
            add_assoc_stringl_ex(zheader, key_buf, klen, v, vlen);
        }
    }
    else
    {
        if (UNEXPECTED(!v))
        {
            add_assoc_null_ex(zheader, k, klen);
        }
        else
        {
            add_assoc_stringl_ex(zheader, k, klen, v, vlen);
        }
    }
    RETURN_TRUE;
}

#ifdef SW_USE_HTTP2
static PHP_METHOD(swoole_http_response, trailer)
{
    char *k, *v;
    size_t klen, vlen;
    char key_buf[SW_HTTP_HEADER_KEY_SIZE];

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(k, klen)
        Z_PARAM_STRING_EX(v, vlen, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (!ctx || !ctx->stream)
    {
        RETURN_FALSE;
    }
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1))
    {
        swoole_php_error(E_WARNING, "trailer key is too long");
        RETURN_FALSE;
    }
    if (UNEXPECTED(vlen > SW_HTTP_HEADER_VALUE_SIZE - 1))
    {
        swoole_php_error(E_WARNING, "trailer value is too long");
        RETURN_FALSE;
    }
    zval *ztrailer = swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.ztrailer, ZEND_STRL("trailer"));
    strncpy(key_buf, k, klen)[klen] = '\0';
    swoole_strtolower(key_buf, klen);
    if (UNEXPECTED(!v))
    {
        add_assoc_null_ex(ztrailer, key_buf, klen);
    }
    else
    {
        add_assoc_stringl_ex(ztrailer, key_buf, klen, v, vlen);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, ping)
{
    http_context *ctx = http_get_context(getThis(), 0);
    if (!ctx || !ctx->stream)
    {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swoole_http2_server_ping(ctx));
}
#endif

static PHP_METHOD(swoole_http_response, detach)
{
    http_context *context = http_get_context(getThis(), 0);
    if (!context)
    {
        RETURN_FALSE;
    }
    context->detached = 1;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, create)
{
    zend_long fd;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = (http_context *) ecalloc(1, sizeof(http_context));
    if (UNEXPECTED(!ctx))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_MALLOC_FAIL, "ecalloc(%ld) failed", sizeof(http_context));
        RETURN_FALSE;
    }
    ctx->fd = (int) fd;

    object_init_ex(return_value, swoole_http_response_ce);
    swoole_set_object(return_value, ctx);
    ctx->response.zobject = return_value;
    sw_copy_to_stack(ctx->response.zobject, ctx->response._zobject);

    zend_update_property_long(swoole_http_response_ce, return_value, ZEND_STRL("fd"), ctx->fd);
}

static PHP_METHOD(swoole_http_response, redirect)
{
    zval *zurl;
    zval *zhttp_code = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(zurl)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_EX(zhttp_code, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = http_get_context(getThis(), 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    // status
    if (zhttp_code)
    {
        ctx->response.status = zval_get_long(zhttp_code);
    }
    else
    {
        ctx->response.status = 302;
    }

    zval zkey;
    ZVAL_STRINGL(&zkey, "Location", 8);
    sw_zend_call_method_with_2_params(getThis(), NULL, NULL, "header", return_value, &zkey, zurl);
    zval_ptr_dtor(&zkey);
    if (!Z_BVAL_P(return_value))
    {
        return;
    }
    sw_zend_call_method_with_0_params(getThis(), NULL, NULL, "end", NULL);
}

static PHP_METHOD(swoole_http_response, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    http_context *context = (http_context *) swoole_get_object(getThis());
    if (context)
    {
        swConnection *conn = swWorker_get_connection(SwooleG.serv, context->fd);
        if (!conn || conn->closed || conn->removed || context->detached)
        {
            swoole_http_context_free(context);
        }
        else
        {
            if (context->response.status == 0)
            {
                context->response.status = 500;
            }
            sw_zend_call_method_with_0_params(getThis(), swoole_http_response_ce, NULL, "end", NULL);
            context = (http_context *) swoole_get_object(getThis());
            if (context)
            {
                swoole_http_context_free(context);
            }
        }
    }
}

static bool http_context_send_data(http_context* ctx, const char *data, size_t length)
{
    swServer *serv = (swServer *) ctx->private_data;
    zval *return_value = (zval *) ctx->private_data_2;
    ssize_t ret = serv->send(serv, ctx->fd, (void*) data, length);
    if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && SwooleG.serv && serv->send_yield)
    {
        zval _yield_data;
        ZVAL_STRINGL(&_yield_data, swoole_http_buffer->str, swoole_http_buffer->length);
        php_swoole_server_send_yield(serv, ctx->fd, &_yield_data, return_value);
        if (Z_TYPE_P(return_value) == IS_FALSE)
        {
            ctx->chunk = 0;
            ctx->send_header = 0;
        }
    }
    return ret == SW_OK;
}

static bool http_context_disconnect(http_context* ctx)
{
    swServer *serv = (swServer *) ctx->private_data;
    return serv->close(serv, ctx->fd, 0) == SW_OK;
}
