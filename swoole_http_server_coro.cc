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

#include <string>
#include <map>
#include <algorithm>

using namespace std;
using namespace swoole;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_pattern, 0, 0, 2)
    ZEND_ARG_INFO(0, pattern)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

static zend_class_entry *swoole_http_server_coro_ce;
static zend_object_handlers swoole_http_server_coro_handlers;

static bool http_context_send_data(http_context* ctx, const char *data, size_t length);
static bool http_context_send_file(http_context* ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
static bool http_context_disconnect(http_context* ctx);

class http_server
{
public:
    Socket *socket;
    map<string, php_swoole_fci *> handlers;
    php_swoole_fci *default_handler;
    bool running;

public:
    http_server(enum swSocket_type type)
    {
        socket = new Socket(type);
        running = true;
        default_handler = nullptr;
    }

    void set_handler(string pattern, php_swoole_fci *fci)
    {
        if (pattern == "/")
        {
            if (default_handler)
            {
                sw_fci_cache_discard(&default_handler->fci_cache);
                efree(default_handler);
            }
            default_handler = fci;
        }
        else
        {
            auto find_fci = handlers.find(pattern);
            if (find_fci != handlers.end())
            {
                sw_fci_cache_discard(&find_fci->second->fci_cache);
                efree(find_fci->second);
            }
            handlers[pattern] = fci;
        }
        sw_fci_cache_persist(&fci->fci_cache);
    }

    php_swoole_fci* get_handler(http_context *ctx)
    {
        for (auto i = handlers.begin(); i != handlers.end(); i++)
        {
            if (strncasecmp(i->first.c_str(), ctx->request.path, i->first.length()) == 0)
            {
                return i->second;
            }
        }
        return default_handler;
    }

    http_context* create_context(Socket *conn, zval *zconn)
    {
        http_context *ctx = swoole_http_context_new(conn->get_fd());
        swoole_http_parser *parser = &ctx->parser;
        parser->data = ctx;
        ctx->parse_body = 1;
        ctx->parse_cookie = 1;
#ifdef SW_HAVE_ZLIB
        ctx->enable_compression = 1;
        ctx->compression_level = Z_BEST_SPEED;
#endif
        ctx->private_data = conn;
        ctx->co_socket = 1;
        ctx->send = http_context_send_data;
        ctx->sendfile = http_context_send_file;
        ctx->close = http_context_disconnect;

        zend_update_property(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("socket"), zconn);

        swoole_http_parser_init(parser, PHP_HTTP_REQUEST);

        return ctx;
    }
};

typedef struct
{
    http_server *server;
    zend_object std;
} http_server_coro_t;

static PHP_METHOD(swoole_http_server_coro, __construct);
static PHP_METHOD(swoole_http_server_coro, handle);
static PHP_METHOD(swoole_http_server_coro, start);
static PHP_METHOD(swoole_http_server_coro, shutdown);
static PHP_METHOD(swoole_http_server_coro, onAccept);
static PHP_METHOD(swoole_http_server_coro, __destruct);

static const zend_function_entry swoole_http_server_coro_methods[] =
{
    PHP_ME(swoole_http_server_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, handle, arginfo_swoole_http_server_coro_pattern, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, onAccept, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, shutdown, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object *swoole_http_server_coro_create_object(zend_class_entry *ce)
{
    http_server_coro_t *hsc = (http_server_coro_t *) ecalloc(1, sizeof(http_server_coro_t) + zend_object_properties_size(ce));
    zend_object_std_init(&hsc->std, ce);
    object_properties_init(&hsc->std, ce);
    hsc->std.handlers = &swoole_http_server_coro_handlers;
    return &hsc->std;
}

static sw_inline http_server_coro_t* swoole_http_server_coro_fetch_object(zend_object *obj)
{
    return (http_server_coro_t *) ((char *) obj - swoole_http_server_coro_handlers.offset);
}

static sw_inline http_server* http_server_get_object(zend_object *obj)
{
    return swoole_http_server_coro_fetch_object(obj)->server;
}

static bool http_context_send_data(http_context* ctx, const char *data, size_t length)
{
    Socket *sock = (Socket *) ctx->private_data;
    return sock->send_all(data, length) == (ssize_t) length;
}

static bool http_context_send_file(http_context* ctx, const char *file, uint32_t l_file, off_t offset, size_t length)
{
    Socket *sock = (Socket *) ctx->private_data;
    return sock->sendfile(file, offset, length);
}

static bool http_context_disconnect(http_context* ctx)
{
    Socket *sock = (Socket *) ctx->private_data;
    return sock->close();
}

static void swoole_http_server_coro_free_object(zend_object *object)
{
    http_server_coro_t *hsc = swoole_http_server_coro_fetch_object(object);
    if (hsc->server)
    {
        http_server *hs = hsc->server;
        if (hs->default_handler)
        {
            sw_fci_cache_discard(&hs->default_handler->fci_cache);
            efree(hs->default_handler);
        }
        for (auto i = hs->handlers.begin(); i != hs->handlers.end(); i++)
        {
            sw_fci_cache_discard(&i->second->fci_cache);
            efree(i->second);
        }
        delete hs;
    }
    zend_object_std_dtor(&hsc->std);
}

void swoole_http_server_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http_server_coro, "Swoole\\Coroutine\\Http\\Server", NULL, "Co\\Http\\Server", swoole_http_server_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_server_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_server_coro, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_server_coro);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_server_coro, swoole_http_server_coro_create_object, swoole_http_server_coro_free_object, http_server_coro_t, std);
    swoole_http_server_coro_ce->ce_flags |= ZEND_ACC_FINAL;
}

static PHP_METHOD(swoole_http_server_coro, __construct)
{
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_bool ssl = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
        Z_PARAM_STRING(host, l_host)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_server_coro_ce, getThis(), ZEND_STRL("host"), host, l_host);
    zend_update_property_long(swoole_http_server_coro_ce, getThis(), ZEND_STRL("port"), port);
    zend_update_property_bool(swoole_http_server_coro_ce, getThis(), ZEND_STRL("ssl"), ssl);

    // check host
    if (l_host == 0)
    {
        zend_throw_exception_ex(swoole_exception_ce, EINVAL, "host is empty");
        RETURN_FALSE;
    }
    //check ssl
#ifndef SW_USE_OPENSSL
    if (ssl)
    {
        zend_throw_exception_ex(
                swoole_exception_ce,
                EPROTONOSUPPORT, "you must configure with `enable-openssl` to support ssl connection"
        );
        RETURN_FALSE;
    }
#endif

    http_server_coro_t *hsc = swoole_http_server_coro_fetch_object(Z_OBJ_P(getThis()));
    string host_str(host, l_host);
    hsc->server = new http_server(Socket::get_type(host_str));
    Socket *sock = hsc->server->socket;
    if (!sock->bind(host_str, port))
    {
        zend_throw_exception_ex(swoole_exception_ce, EINVAL, "bind(%s:%d) failed", host, (int) port);
        RETURN_FALSE
    }
    if (!sock->listen())
    {
        zend_throw_exception_ex(swoole_exception_ce, EINVAL, "listen() failed");
        RETURN_FALSE
    }
}

static PHP_METHOD(swoole_http_server_coro, handle)
{
    char *pattern;
    size_t pattern_len;

    http_server *hs = http_server_get_object(Z_OBJ_P(getThis()));
    php_swoole_fci *fci = (php_swoole_fci *) ecalloc(1, sizeof(php_swoole_fci));

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(pattern, pattern_len)
        Z_PARAM_FUNC(fci->fci, fci->fci_cache)
    ZEND_PARSE_PARAMETERS_END();

    string key(pattern, pattern_len);
    hs->set_handler(key, fci);
}

static PHP_METHOD(swoole_http_server_coro, start)
{
    http_server *hs = http_server_get_object(Z_OBJ_P(getThis()));

    auto sock = hs->socket;
    char *func_name = NULL;
    zend_fcall_info_cache func_cache;
    zval zcallback;
    ZVAL_STRING(&zcallback, "onAccept");

    if (!sw_zend_is_callable_ex(&zcallback, getThis(), 0, &func_name, NULL, &func_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    zval argv[1];

    php_swoole_http_server_init_global_variant();

    while (hs->running)
    {
        auto conn = sock->accept();
        if (conn)
        {
            php_swoole_init_socket_object(&argv[0], conn);
            PHPCoroutine::create(&func_cache, 1, argv);
            zval_dtor(&argv[0]);
        }
        else
        {
            /*
             * Too many connection, wait 1s
             */
            if (sock->errCode == EMFILE || sock->errCode == ENFILE)
            {
                System::sleep(1.0);
            }
            else if (sock->errCode == ETIMEDOUT)
            {
                continue;
            }
            else if (sock->errCode == ECANCELED)
            {
                break;
            }
            else
            {
                swoole_php_fatal_error(E_WARNING, "accept failed, Error: %s[%d]", sock->errMsg, sock->errCode);
                break;
            }
        }
    }

    zval_dtor(&zcallback);

    RETURN_TRUE
}

static PHP_METHOD(swoole_http_server_coro, __destruct)
{

}

static PHP_METHOD(swoole_http_server_coro, onAccept)
{
    http_server *hs = http_server_get_object(Z_OBJ_P(getThis()));
    zval *zconn;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_OBJECT(zconn)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *sock = php_swoole_get_socket(zconn);
    size_t total_bytes = 0;
    size_t parsed_n;
    http_context *ctx = nullptr;

    while (true)
    {
        auto buffer = sock->get_read_buffer();
        ssize_t retval = sock->recv(buffer->str + buffer->offset, buffer->size - buffer->offset);
        if (unlikely(retval <= 0))
        {
            break;
        }

        if (!ctx)
        {
            ctx = hs->create_context(sock, zconn);
        }

        total_bytes += retval;
        parsed_n = swoole_http_parser_execute(&ctx->parser, swoole_http_get_parser_setting(), buffer->str, retval);
        swTraceLog(SW_TRACE_HTTP_CLIENT, "parsed_n=%ld, retval=%ld, total_bytes=%ld, completed=%d", parsed_n, retval, total_bytes, ctx->completed);

        if (!ctx->completed)
        {
            continue;
        }
        if (retval > (ssize_t) parsed_n)
        {
            buffer->offset = retval - parsed_n;
            memmove(buffer->str, buffer->str + parsed_n, buffer->offset);
        }
        else
        {
            buffer->offset = 0;
        }

        zval *zserver = ctx->request.zserver;
        add_assoc_long(zserver, "server_port", hs->socket->get_bind_port());
        add_assoc_long(zserver, "remote_port", (zend_long) swConnection_get_port(sock->socket));
        add_assoc_string(zserver, "remote_addr", (char *) swConnection_get_ip(sock->socket));

        php_swoole_fci *fci = hs->get_handler(ctx);
        zval args[2];
        args[0] = *ctx->request.zobject;
        args[1] = *ctx->response.zobject;

        bool keep_alive = swoole_http_should_keep_alive(&ctx->parser) && !ctx->websocket;

        if (fci)
        {
            if (UNEXPECTED(!zend::function::call(&fci->fci_cache, 2, args, NULL, 0)))
            {
                swoole_php_error(E_WARNING, "handler error");
            }
        }
        else
        {
            ctx->response.status = 404;
        }

        zval_dtor(&args[0]);
        zval_dtor(&args[1]);

        if (hs->running && keep_alive)
        {
            swTraceLog(SW_TRACE_CO_HTTP_SERVER, "http_server_coro keepalive");
            ctx = nullptr;
            continue;
        }
        else
        {
            break;
        }
    }
}

static PHP_METHOD(swoole_http_server_coro, shutdown)
{
    http_server *hs = http_server_get_object(Z_OBJ_P(getThis()));
    hs->running = false;
    hs->socket->cancel(SW_EVENT_READ);
}
