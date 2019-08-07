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

zend_class_entry *swoole_http_request_ce;
static zend_object_handlers swoole_http_request_handlers;

static PHP_METHOD(swoole_http_request, getData);
static PHP_METHOD(swoole_http_request, rawContent);
static PHP_METHOD(swoole_http_request, __destruct);

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

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length)
{
    http_context *ctx = (http_context *) parser->data;
    ctx->request.path = estrndup(at, length);
    ctx->request.path_len = length;
    return 0;
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

const zend_function_entry swoole_http_request_methods[] =
{
    PHP_ME(swoole_http_request, rawContent, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, getData, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

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

size_t swoole_http_requset_parse(http_context *ctx, const char *data, size_t length)
{
    return swoole_http_parser_execute(&ctx->parser, &http_parser_settings, data, length);
}

void php_swoole_http_request_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http_request, "Swoole\\Http\\Request", "swoole_http_request", NULL, swoole_http_request_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_request, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_request, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_request);

    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
#ifdef SW_USE_HTTP2
    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
#endif
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("server"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("get"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("files"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("post"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("tmpfiles"), ZEND_ACC_PUBLIC);
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
        php_swoole_fatal_error(E_WARNING, "multipart_parser_init() failed");
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
                j++;
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
        ctx->websocket = 1;
        if (ctx->co_socket)
        {
            return 0;
        }
        swServer *serv = (swServer *) ctx->private_data;
        swConnection *conn = swWorker_get_connection(serv, ctx->fd);
        if (!conn)
        {
            swWarn("connection[%d] is closed", ctx->fd);
            return SW_ERR;
        }
        swListenPort *port = (swListenPort *) serv->connection_list[conn->server_fd].object;
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
                swTraceLog(SW_TRACE_HTTP, "form_data, boundary_str=%s", boundary_str);
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
    char value_buf[SW_HTTP_FORM_KEYLEN];
    int value_len;

    http_context *ctx = (http_context *) p->data;
    /**
     * Hash collision attack
     */
    if (ctx->input_var_num > PG(max_input_vars))
    {
        php_swoole_error(E_WARNING, "Input variables exceeded " ZEND_LONG_FMT ". "
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

        if (Z_STRLEN_P(zform_name) >= SW_HTTP_FORM_KEYLEN)
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
            if (Z_STRLEN_P(zfilename) >= SW_HTTP_FORM_KEYLEN)
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
    snprintf(file_path, SW_HTTP_UPLOAD_TMPDIR_SIZE, "%s/swoole.upfile.XXXXXX", ctx->upload_tmp_dir);
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

    ctx->request.body_length = length;

    swTraceLog(SW_TRACE_HTTP, "length=%ld", length);

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

#ifdef SW_HAVE_ZLIB
void swoole_http_get_compression_method(http_context *ctx, const char *accept_encoding, size_t length)
{
#ifdef SW_HAVE_BROTLI
    if (swoole_strnpos((char *) accept_encoding, length, (char *) ZEND_STRL("br")) >= 0)
    {
        ctx->accept_compression = 1;
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
#endif

static PHP_METHOD(swoole_http_request, rawContent)
{
    http_context *ctx = swoole_http_context_get(ZEND_THIS, 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    http_request *req = &ctx->request;
    if (req->body_length > 0)
    {
        zval *zdata = &req->zdata;
        RETURN_STRINGL(Z_STRVAL_P(zdata) + Z_STRLEN_P(zdata) - req->body_length, req->body_length);
    }
#ifdef SW_USE_HTTP2
    else if (req->h2_data_buffer && req->h2_data_buffer->length > 0)
    {
        RETURN_STRINGL(req->h2_data_buffer->str, req->h2_data_buffer->length);
    }
#endif

    RETURN_EMPTY_STRING();
}

static PHP_METHOD(swoole_http_request, getData)
{
    http_context *ctx = swoole_http_context_get(ZEND_THIS, 0);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->stream)
    {
        php_swoole_fatal_error(E_WARNING, "unable to get data from HTTP2 request");
        RETURN_FALSE;
    }
#endif

    if (Z_TYPE(ctx->request.zdata) == IS_STRING)
    {
        RETURN_ZVAL(&ctx->request.zdata, 1, 0);
    }

    RETURN_EMPTY_STRING();
}

static PHP_METHOD(swoole_http_request, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    zval *ztmpfiles = sw_zend_read_property(swoole_http_request_ce, ZEND_THIS, ZEND_STRL("tmpfiles"), 0);
    //upload files
    if (ztmpfiles && ZVAL_IS_ARRAY(ztmpfiles))
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
    http_context *ctx = (http_context *) swoole_get_object(ZEND_THIS);
    if (ctx)
    {
        ctx->request.zobject = NULL;
    }
    swoole_set_object(ZEND_THIS, NULL);
}
