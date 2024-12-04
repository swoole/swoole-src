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
#include "php_swoole_client.h"
#include "swoole_mqtt.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_client_async_arginfo.h"
END_EXTERN_C()

#include "ext/standard/basic_functions.h"

using swoole::network::Client;
using swoole::network::Socket;

static PHP_METHOD(swoole_client_async, __construct);
static PHP_METHOD(swoole_client_async, __destruct);
static PHP_METHOD(swoole_client_async, connect);
static PHP_METHOD(swoole_client_async, sleep);
static PHP_METHOD(swoole_client_async, wakeup);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_async, enableSSL);
#endif
static PHP_METHOD(swoole_client_async, isConnected);
static PHP_METHOD(swoole_client_async, close);
static PHP_METHOD(swoole_client_async, on);

static void client_onConnect(Client *cli);
static void client_onReceive(Client *cli, const char *data, size_t length);
static void client_onClose(Client *cli);
static void client_onError(Client *cli);
static void client_onBufferFull(Client *cli);
static void client_onBufferEmpty(Client *cli);

zend_class_entry *swoole_client_async_ce;
static zend_object_handlers swoole_client_async_handlers;

void php_swoole_client_async_free_object(ClientObject *client_obj) {
    if (client_obj->async->onConnect) {
        sw_callable_free(client_obj->async->onConnect);
    }
    if (client_obj->async->onReceive) {
        sw_callable_free(client_obj->async->onReceive);
    }
    if (client_obj->async->onClose) {
        sw_callable_free(client_obj->async->onClose);
    }
    if (client_obj->async->onError) {
        sw_callable_free(client_obj->async->onError);
    }
    if (client_obj->async->onBufferFull) {
        sw_callable_free(client_obj->async->onBufferFull);
    }
    if (client_obj->async->onBufferEmpty) {
        sw_callable_free(client_obj->async->onBufferEmpty);
    }
#ifdef SW_USE_OPENSSL
    if (client_obj->async->onSSLReady) {
        sw_callable_free(client_obj->async->onSSLReady);
    }
#endif
    delete client_obj->async;
}

static sw_inline void client_execute_callback(zval *zobject, enum php_swoole_client_callback_type type) {
    auto client_obj = php_swoole_client_fetch_object(zobject);
    const char *callback_name;
    zend::Callable *cb;

    switch (type) {
    case SW_CLIENT_CB_onConnect:
        callback_name = "onConnect";
        cb = client_obj->async->onConnect;
        break;
    case SW_CLIENT_CB_onError:
        callback_name = "onError";
        cb = client_obj->async->onError;
        break;
    case SW_CLIENT_CB_onClose:
        callback_name = "onClose";
        cb = client_obj->async->onClose;
        break;
    case SW_CLIENT_CB_onBufferFull:
        callback_name = "onBufferFull";
        cb = client_obj->async->onBufferFull;
        break;
    case SW_CLIENT_CB_onBufferEmpty:
        callback_name = "onBufferEmpty";
        cb = client_obj->async->onBufferEmpty;
        break;
#ifdef SW_USE_OPENSSL
    case SW_CLIENT_CB_onSSLReady:
        callback_name = "onSSLReady";
        cb = client_obj->async->onSSLReady;
        break;
#endif
    default:
        abort();
        return;
    }

    if (!cb) {
        php_swoole_fatal_error(E_WARNING, "%s has no %s callback", SW_Z_OBJCE_NAME_VAL_P(zobject), callback_name);
        return;
    }

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, cb->ptr(), 1, zobject, NULL) != SUCCESS)) {
        php_swoole_fatal_error(E_WARNING, "%s->%s handler error", SW_Z_OBJCE_NAME_VAL_P(zobject), callback_name);
    }
}

// clang-format off
static const zend_function_entry swoole_client_async_methods[] = {
    PHP_ME(swoole_client_async, __construct, arginfo_class_Swoole_Async_Client___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, __destruct, arginfo_class_Swoole_Async_Client___destruct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, connect, arginfo_class_Swoole_Async_Client_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, sleep, arginfo_class_Swoole_Async_Client_sleep, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, wakeup, arginfo_class_Swoole_Async_Client_wakeup, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_client_async, pause, sleep, arginfo_class_Swoole_Async_Client_sleep, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_client_async, resume, wakeup, arginfo_class_Swoole_Async_Client_wakeup, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client_async, enableSSL, arginfo_class_Swoole_Async_Client_enableSSL, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client_async, isConnected, arginfo_class_Swoole_Async_Client_isConnected, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, close, arginfo_class_Swoole_Async_Client_close, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_async, on, arginfo_class_Swoole_Async_Client_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_client_async_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_EX(
        swoole_client_async, "Swoole\\Async\\Client", nullptr, swoole_client_async_methods, swoole_client);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_client_async);
    SW_SET_CLASS_CLONEABLE(swoole_client_async, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_client_async, sw_zend_class_unset_property_deny);

    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onConnect"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onError"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onReceive"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onClose"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onBufferFull"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onBufferEmpty"), ZEND_ACC_PRIVATE);
#ifdef SW_USE_OPENSSL
    zend_declare_property_null(swoole_client_async_ce, ZEND_STRL("onSSLReady"), ZEND_ACC_PRIVATE);
#endif
}

static void client_onReceive(Client *cli, const char *data, size_t length) {
    zval *zobject = (zval *) cli->object;
    auto client_obj = php_swoole_client_fetch_object(zobject);
    zend_fcall_info_cache *fci_cache = client_obj->async->onReceive->ptr();
    zval args[2];

    args[0] = *zobject;
    ZVAL_STRINGL(&args[1], data, length);

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, fci_cache, 2, args, NULL) != SUCCESS)) {
        php_swoole_fatal_error(E_WARNING, "%s->onReceive handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }

    zval_ptr_dtor(&args[1]);
}

static void client_onConnect(Client *cli) {
    zval *zobject = (zval *) cli->object;
#ifdef SW_USE_OPENSSL
    if (cli->ssl_wait_handshake) {
        cli->ssl_wait_handshake = 0;
        client_execute_callback(zobject, SW_CLIENT_CB_onSSLReady);
        return;
    }
#endif
    client_execute_callback(zobject, SW_CLIENT_CB_onConnect);
}

static void client_onClose(Client *cli) {
    zval *zobject = (zval *) cli->object;
    client_execute_callback(zobject, SW_CLIENT_CB_onClose);
    zval_ptr_dtor(zobject);
}

static void client_onError(Client *cli) {
    zval *zobject = (zval *) cli->object;
    zend_update_property_long(swoole_client_async_ce, Z_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
    client_execute_callback(zobject, SW_CLIENT_CB_onError);
    zval_ptr_dtor(zobject);
}

static void client_onBufferFull(Client *cli) {
    zval *zobject = (zval *) cli->object;
    client_execute_callback(zobject, SW_CLIENT_CB_onBufferFull);
}

static void client_onBufferEmpty(Client *cli) {
    zval *zobject = (zval *) cli->object;
    client_execute_callback(zobject, SW_CLIENT_CB_onBufferEmpty);
}

static PHP_METHOD(swoole_client_async, __construct) {
    zend_long type = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &type) == FAILURE) {
        zend_throw_error(NULL, "socket type param is required");
        RETURN_FALSE;
    }

    int client_type = php_swoole_get_socket_type(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_DGRAM) {
        const char *space, *class_name = get_active_class_name(&space);
        zend_type_error("%s%s%s() expects parameter %d to be client type, unknown type " ZEND_LONG_FMT " given",
                        class_name,
                        space,
                        get_active_function_name(),
                        1,
                        type);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();

    zend_update_property_long(swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("type"), type);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_async, __destruct) {
    SW_PREVENT_USER_DESTRUCT();

    Client *cli = (Client *) php_swoole_client_get_cli(ZEND_THIS);
    if (cli && cli->active) {
        sw_zend_call_method_with_0_params(ZEND_THIS, swoole_client_async_ce, NULL, "close", NULL);
    }
}

static Client *php_swoole_client_async_new(zval *zobject, char *host, int host_len, int port) {
    zval *ztype = sw_zend_read_property_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TYPE), 0);
    if (ztype == nullptr || ZVAL_IS_NULL(ztype)) {
        php_swoole_fatal_error(E_ERROR, "failed to get swoole_client->type");
        return nullptr;
    }

    long type = Z_LVAL_P(ztype);
    int client_type = php_swoole_get_socket_type(type);
    if ((client_type == SW_SOCK_TCP || client_type == SW_SOCK_TCP6) && (port <= 0 || port > SW_CLIENT_MAX_PORT)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return nullptr;
    }

    Client *cli = new Client(php_swoole_get_socket_type(type), true);
    if (cli->socket == nullptr) {
        php_swoole_sys_error(E_WARNING, "Client_create() failed");
        zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), errno);
        delete cli;
        return nullptr;
    }

    zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("sock"), cli->socket->fd);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        cli->enable_ssl_encrypt();
    }
#endif

    return cli;
}

static PHP_METHOD(swoole_client_async, connect) {
    char *host;
    size_t host_len;
    zend_long port = 0;
    double timeout = SW_CLIENT_CONNECT_TIMEOUT;
    zend_long sock_flag = 0;

    ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_STRING(host, host_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(port)
    Z_PARAM_DOUBLE(timeout)
    Z_PARAM_LONG(sock_flag)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (host_len == 0) {
        php_swoole_fatal_error(E_WARNING, "The host is empty");
        RETURN_FALSE;
    }

    auto client_obj = php_swoole_client_fetch_object(ZEND_THIS);
    if (client_obj->cli) {
        php_swoole_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }

    if (!client_obj->async) {
        php_swoole_fatal_error(E_WARNING, "async client is not initialized");
        RETURN_FALSE;
    }

    auto cli = php_swoole_client_async_new(ZEND_THIS, host, host_len, port);
    if (cli == NULL) {
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property(swoole_client_async_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    if (zset && ZVAL_IS_ARRAY(zset)) {
        php_swoole_client_check_setting(cli, zset);
    }
    if (!client_obj->async->onReceive) {
        php_swoole_fatal_error(E_ERROR, "no 'onReceive' callback function");
        RETURN_FALSE;
    }
    if (cli->get_socket()->is_stream()) {
        if (!client_obj->async->onConnect) {
            php_swoole_fatal_error(E_ERROR, "no 'onConnect' callback function");
            RETURN_FALSE;
        }
        if (!client_obj->async->onError) {
            php_swoole_fatal_error(E_ERROR, "no 'onError' callback function");
            RETURN_FALSE;
        }
        if (!client_obj->async->onClose) {
            php_swoole_fatal_error(E_ERROR, "no 'onClose' callback function");
            RETURN_FALSE;
        }
        cli->onConnect = client_onConnect;
        cli->onClose = client_onClose;
        cli->onError = client_onError;
        cli->onReceive = client_onReceive;
        if (client_obj->async->onBufferFull) {
            cli->onBufferFull = client_onBufferFull;
        }
        if (client_obj->async->onBufferEmpty) {
            cli->onBufferEmpty = client_onBufferEmpty;
        }
    } else {
        if (client_obj->async->onConnect) {
            cli->onConnect = client_onConnect;
        }
        if (client_obj->async->onClose) {
            cli->onClose = client_onClose;
        }
        if (client_obj->async->onError) {
            cli->onError = client_onError;
        }
        cli->onReceive = client_onReceive;
    }

    client_obj->async->_zobject = *ZEND_THIS;
    client_obj->cli = cli;
    cli->object = &client_obj->async->_zobject;
    Z_TRY_ADDREF_P(ZEND_THIS);

    // nonblock async
    if (cli->connect(cli, host, port, timeout, sock_flag) < 0) {
        if (errno == 0) {
            auto error = swoole_get_last_error();
            if (error == SW_ERROR_DNSLOOKUP_RESOLVE_FAILED) {
                php_swoole_error(E_WARNING,
                                 "connect to server[%s:%d] failed. Error: %s[%d]",
                                 host,
                                 (int) port,
                                 swoole_strerror(error),
                                 error);
            }
            zend_update_property_long(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), error);
        } else {
            php_swoole_sys_error(E_WARNING, "connect to server[%s:%d] failed", host, (int) port);
            zend_update_property_long(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), errno);
        }
        Client *cli = (Client *) php_swoole_client_get_cli(ZEND_THIS);
        if (cli && cli->onError == NULL) {
            php_swoole_client_free(ZEND_THIS, cli);
            zval_ptr_dtor(ZEND_THIS);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_async, isConnected) {
    Client *cli = (Client *) php_swoole_client_get_cli(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->socket) {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->active);
}

static PHP_METHOD(swoole_client_async, close) {
    int ret = 1;

    Client *cli = (Client *) php_swoole_client_get_cli(ZEND_THIS);
    if (!cli || !cli->socket) {
        php_swoole_fatal_error(E_WARNING, "client is not connected to the server");
        RETURN_FALSE;
    }
    if (cli->closed) {
        php_swoole_error(E_WARNING, "client socket is closed");
        RETURN_FALSE;
    }
    if (cli->async && cli->active == 0) {
        zval *zobject = ZEND_THIS;
        zval_ptr_dtor(zobject);
    }
    ret = cli->close();
    php_swoole_client_free(ZEND_THIS, cli);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client_async, on) {
    char *cb_name;
    size_t cb_name_len;
    zval *zcallback;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE) {
        RETURN_FALSE;
    }

    auto client_obj = php_swoole_client_fetch_object(ZEND_THIS);
    auto cb = sw_callable_create(zcallback);
    if (!cb) {
        return;
    }

    if (!client_obj->async) {
        client_obj->async = new AsyncClientObject();
    }

    if (strncasecmp("connect", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onConnect"), zcallback);
        if (client_obj->async->onConnect) {
            sw_callable_free(client_obj->async->onConnect);
        }
        client_obj->async->onConnect = cb;
    } else if (strncasecmp("receive", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onReceive"), zcallback);
        if (client_obj->async->onReceive) {
            sw_callable_free(client_obj->async->onReceive);
        }
        client_obj->async->onReceive = cb;
    } else if (strncasecmp("close", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onClose"), zcallback);
        if (client_obj->async->onClose) {
            sw_callable_free(client_obj->async->onClose);
        }
        client_obj->async->onClose = cb;
    } else if (strncasecmp("error", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onError"), zcallback);
        if (client_obj->async->onError) {
            sw_callable_free(client_obj->async->onError);
        }
        client_obj->async->onError = cb;
    } else if (strncasecmp("bufferFull", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onBufferFull"), zcallback);
        if (client_obj->async->onBufferFull) {
            sw_callable_free(client_obj->async->onBufferFull);
        }
        client_obj->async->onBufferFull = cb;
    } else if (strncasecmp("bufferEmpty", cb_name, cb_name_len) == 0) {
        zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onBufferEmpty"), zcallback);
        if (client_obj->async->onBufferEmpty) {
            sw_callable_free(client_obj->async->onBufferEmpty);
        }
        client_obj->async->onBufferEmpty = cb;
    } else {
        php_swoole_fatal_error(E_WARNING, "Unknown event callback type name '%s'", cb_name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_async, sleep) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(cli->sleep());
}

static PHP_METHOD(swoole_client_async, wakeup) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(cli->wakeup());
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_async, enableSSL) {
    zval *zcallback = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(zcallback)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zcallback == nullptr) {
        zend_throw_exception(swoole_exception_ce, "require `onSslReady` callback", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!php_swoole_client_enable_ssl_encryption(cli, ZEND_THIS)) {
        RETURN_FALSE;
    }

    auto client_obj = php_swoole_client_fetch_object(ZEND_THIS);
    if (swoole_event_set(cli->socket, SW_EVENT_WRITE) < 0) {
        RETURN_FALSE;
    }

    if (client_obj->async->onSSLReady) {
        sw_callable_free(client_obj->async->onSSLReady);
    }

    auto cb = sw_callable_create(zcallback);
    if (!cb) {
        RETURN_FALSE;
    }
    zend_update_property(swoole_client_async_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("onSSLReady"), zcallback);
    client_obj->async->onSSLReady = cb;
    cli->ssl_wait_handshake = 1;
    cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;

    RETURN_TRUE;
}
#endif
