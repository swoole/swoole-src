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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"
#include "swoole_proxy.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_client_coro_arginfo.h"
END_EXTERN_C()

using swoole::String;
using swoole::coroutine::Socket;
using swoole::network::Address;
#ifdef SW_USE_OPENSSL
using swoole::SSLContext;
#endif

static zend_class_entry *swoole_client_coro_ce;
static zend_object_handlers swoole_client_coro_handlers;

struct ClientCoroObject {
    Socket *socket;
    zval socket_object;
    /* safety zval */
    zval zobject;
    zend_object std;
};

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_client_coro, __construct);
static PHP_METHOD(swoole_client_coro, __destruct);
static PHP_METHOD(swoole_client_coro, set);
static PHP_METHOD(swoole_client_coro, connect);
static PHP_METHOD(swoole_client_coro, recv);
static PHP_METHOD(swoole_client_coro, peek);
static PHP_METHOD(swoole_client_coro, send);
static PHP_METHOD(swoole_client_coro, sendfile);
static PHP_METHOD(swoole_client_coro, sendto);
static PHP_METHOD(swoole_client_coro, recvfrom);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL);
static PHP_METHOD(swoole_client_coro, getPeerCert);
static PHP_METHOD(swoole_client_coro, verifyPeerCert);
#endif
static PHP_METHOD(swoole_client_coro, exportSocket);
static PHP_METHOD(swoole_client_coro, isConnected);
static PHP_METHOD(swoole_client_coro, getsockname);
static PHP_METHOD(swoole_client_coro, getpeername);
static PHP_METHOD(swoole_client_coro, close);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct,    arginfo_class_Swoole_Coroutine_Client___construct,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, __destruct,     arginfo_class_Swoole_Coroutine_Client___destruct,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, set,            arginfo_class_Swoole_Coroutine_Client_set,            ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, connect,        arginfo_class_Swoole_Coroutine_Client_connect,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recv,           arginfo_class_Swoole_Coroutine_Client_recv,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, peek,           arginfo_class_Swoole_Coroutine_Client_peek,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, send,           arginfo_class_Swoole_Coroutine_Client_send,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendfile,       arginfo_class_Swoole_Coroutine_Client_sendfile,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendto,         arginfo_class_Swoole_Coroutine_Client_sendto,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recvfrom,       arginfo_class_Swoole_Coroutine_Client_recvfrom,       ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client_coro, enableSSL,      arginfo_class_Swoole_Coroutine_Client_enableSSL,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getPeerCert,    arginfo_class_Swoole_Coroutine_Client_getPeerCert,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, verifyPeerCert, arginfo_class_Swoole_Coroutine_Client_verifyPeerCert, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client_coro, isConnected,    arginfo_class_Swoole_Coroutine_Client_isConnected,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getsockname,    arginfo_class_Swoole_Coroutine_Client_getsockname,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getpeername,    arginfo_class_Swoole_Coroutine_Client_getpeername,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, close,          arginfo_class_Swoole_Coroutine_Client_close,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, exportSocket,   arginfo_class_Swoole_Coroutine_Client_exportSocket,   ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

#define CLIENT_CORO_GET_SOCKET(__sock)                                                                                 \
    zval tmp_socket;                                                                                                   \
    Socket *__sock = client_coro_get_socket_check_liveness(ZEND_THIS, &tmp_socket);                                    \
    if (!__sock) {                                                                                                     \
        RETURN_FALSE;                                                                                                  \
    }                                                                                                                  \
    ON_SCOPE_EXIT {                                                                                                    \
        zval_ptr_dtor(&tmp_socket);                                                                                    \
    };

static sw_inline ClientCoroObject *client_coro_fetch_object(zend_object *obj) {
    return (ClientCoroObject *) ((char *) obj - swoole_client_coro_handlers.offset);
}

static sw_inline ClientCoroObject *client_coro_get_client(zval *zobject) {
    return client_coro_fetch_object(Z_OBJ_P(zobject));
}

static sw_inline Socket *client_coro_get_socket(zval *zobject) {
    return client_coro_get_client(zobject)->socket;
}

static void client_coro_free_object(zend_object *object) {
    ClientCoroObject *client = client_coro_fetch_object(object);
    if (client->socket) {
        client->socket->close();
    }
    zend_object_std_dtor(&client->std);
}

static zend_object *client_coro_create_object(zend_class_entry *ce) {
    ClientCoroObject *sock = (ClientCoroObject *) zend_object_alloc(sizeof(ClientCoroObject), ce);
    zend_object_std_init(&sock->std, ce);
    object_properties_init(&sock->std, ce);
    sock->std.handlers = &swoole_client_coro_handlers;
    ZVAL_OBJ(&sock->zobject, &sock->std);
    return &sock->std;
}

static void client_coro_socket_dtor(ClientCoroObject *client) {
    if (client->socket->protocol.private_data) {
        sw_zend_fci_cache_discard((zend_fcall_info_cache *) client->socket->protocol.private_data);
        efree(client->socket->protocol.private_data);
        client->socket->protocol.private_data = nullptr;
    }
    client->socket = nullptr;
    zend_update_property_null(Z_OBJCE_P(&client->zobject), SW_Z8_OBJ_P(&client->zobject), ZEND_STRL("socket"));
    zend_update_property_bool(Z_OBJCE_P(&client->zobject), SW_Z8_OBJ_P(&client->zobject), ZEND_STRL("connected"), 0);
    zval_ptr_dtor(&client->socket_object);
}

static bool client_coro_create_socket(zval *zobject, zend_long type) {
    enum swSocketType socket_type = (enum swSocketType) php_swoole_get_socket_type(type);
    auto object = php_swoole_create_socket(socket_type);
    if (UNEXPECTED(!object)) {
        php_swoole_socket_set_error_properties(zobject, errno, strerror(errno));
        return false;
    }
    auto client = client_coro_get_client(zobject);
    ZVAL_OBJ(&client->socket_object, object);
    client->socket = php_swoole_get_socket(&client->socket_object);

    client->socket->set_dtor([client](Socket *_socket) { client_coro_socket_dtor(client); });

    zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("fd"), client->socket->get_fd());
    zend_update_property(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("socket"), &client->socket_object);

    client->socket->set_buffer_allocator(sw_zend_string_allocator());
    client->socket->set_zero_copy(true);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        client->socket->enable_ssl_encrypt();
    }
#endif

    return true;
}

void php_swoole_client_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_client_coro, "Swoole\\Coroutine\\Client", "Co\\Client", swoole_client_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_client_coro);
    SW_SET_CLASS_CLONEABLE(swoole_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_client_coro, client_coro_create_object, client_coro_free_object, ClientCoroObject, std);

    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_client_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("fd"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_coro_ce, ZEND_STRL("socket"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("type"), SW_SOCK_TCP, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_OOB"), MSG_OOB);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_PEEK"), MSG_PEEK);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL);
}

static sw_inline Socket *client_coro_get_socket_check_liveness(zval *zobject, zval *tmp_socket) {
    auto client = client_coro_get_client(zobject);
    if (client->socket) {
        *tmp_socket = client->socket_object;
        zval_add_ref(tmp_socket);
        return php_swoole_get_socket(tmp_socket);
    } else {
        php_swoole_socket_set_error_properties(
            zobject, SW_ERROR_CLIENT_NO_CONNECTION, swoole_strerror(SW_ERROR_CLIENT_NO_CONNECTION));
        return nullptr;
    }
}

static sw_inline Socket *client_coro_get_socket_for_connect(zval *zobject, int port) {
    auto client = client_coro_get_client(zobject);
    if (client->socket) {
        php_swoole_socket_set_error_properties(zobject, EISCONN, strerror(EISCONN));
        return nullptr;
    }

    zval *ztype = sw_zend_read_property(swoole_client_coro_ce, zobject, ZEND_STRL("type"), 1);
    auto socket_type = php_swoole_get_socket_type(zval_get_long(ztype));
    if ((socket_type == SW_SOCK_TCP || socket_type == SW_SOCK_TCP6) && (port <= 0 || port > SW_CLIENT_MAX_PORT)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        return nullptr;
    }

    if (!client_coro_create_socket(zobject, zval_get_long(ztype))) {
        return nullptr;
    }

    zval *zset = sw_zend_read_property_ex(swoole_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (zset && ZVAL_IS_ARRAY(zset)) {
        php_swoole_socket_set(client->socket, zset);
    }

    return client->socket;
}

static PHP_METHOD(swoole_client_coro, __construct) {
    if (client_coro_get_client(ZEND_THIS)->socket) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long type = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    enum swSocketType socket_type = (enum swSocketType) php_swoole_get_socket_type(type);
    if (socket_type < SW_SOCK_TCP || socket_type > SW_SOCK_UNIX_DGRAM) {
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
    zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("type"), type);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, __destruct) {}

static PHP_METHOD(swoole_client_coro, set) {
    zval *zset, *zsetting;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(zset) == 0) {
        RETURN_FALSE;
    } else {
        zsetting = sw_zend_read_and_convert_property_array(swoole_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
        Socket *cli = client_coro_get_socket(ZEND_THIS);
        if (cli) {
            RETURN_BOOL(php_swoole_socket_set(cli, zset));
        }
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, connect) {
    char *host;
    size_t host_len;
    zend_long port = 0;
    double timeout = 0;
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

    Socket *socket = client_coro_get_socket_for_connect(ZEND_THIS, port);
    if (!socket) {
        RETURN_FALSE;
    }
    socket->set_timeout(timeout, Socket::TIMEOUT_CONNECT);
    if (!socket->connect(host, port, sock_flag)) {
        php_swoole_socket_set_error_properties(ZEND_THIS, socket);
        socket->close();
        RETURN_FALSE;
    }
    socket->set_timeout(timeout, Socket::TIMEOUT_RDWR);
    zend_update_property_bool(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connected"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, send) {
    char *data;
    size_t data_len;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(data, data_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (data_len == 0) {
        php_swoole_fatal_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }

    CLIENT_CORO_GET_SOCKET(cli);

    Socket::TimeoutSetter ts(cli, timeout, Socket::TIMEOUT_WRITE);
    ssize_t ret = cli->send_all(data, data_len);
    if (ret < 0) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        RETURN_FALSE;
    }

    if ((size_t) ret < data_len && cli->errCode) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
    }
    RETURN_LONG(ret);
}

static PHP_METHOD(swoole_client_coro, sendto) {
    char *host;
    size_t host_len;
    zend_long port;
    char *data;
    size_t len;

    ZEND_PARSE_PARAMETERS_START(3, 3)
    Z_PARAM_STRING(host, host_len)
    Z_PARAM_LONG(port)
    Z_PARAM_STRING(data, len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (len == 0) {
        RETURN_FALSE;
    }

    Socket *socket = nullptr;
    auto client = client_coro_get_client(ZEND_THIS);
    if (client->socket == nullptr) {
        socket = client_coro_get_socket_for_connect(ZEND_THIS, 0);
    } else {
        socket = client->socket;
    }
    if (!socket) {
        RETURN_FALSE;
    }

    if ((socket->get_type() == SW_SOCK_TCP || socket->get_type() == SW_SOCK_TCP6) &&
        (port <= 0 || port > SW_CLIENT_MAX_PORT)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        RETURN_FALSE;
    }

    ssize_t ret = socket->sendto(std::string(host, host_len), port, data, len);
    if (ret < 0) {
        php_swoole_socket_set_error_properties(ZEND_THIS, socket);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, recvfrom) {
    zend_long length;
    zval *address, *port;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz/|z/", &length, &address, &port) == FAILURE) {
        RETURN_FALSE;
    }

    if (length <= 0) {
        RETURN_FALSE;
    }

    Socket *socket = nullptr;
    auto client = client_coro_get_client(ZEND_THIS);
    if (client->socket == nullptr) {
        socket = client_coro_get_socket_for_connect(ZEND_THIS, 0);
    } else {
        socket = client->socket;
    }
    if (!socket) {
        RETURN_FALSE;
    }

    zend_string *retval = zend_string_alloc(length, 0);
    ssize_t n_bytes = socket->recvfrom(ZSTR_VAL(retval), length);
    if (n_bytes < 0) {
        zend_string_free(retval);
        php_swoole_socket_set_error_properties(ZEND_THIS, socket);
        RETURN_FALSE;
    } else {
        zval_ptr_dtor(address);
        ZVAL_STRING(address, socket->get_ip());
        if (port) {
            zval_ptr_dtor(port);
            ZVAL_LONG(port, socket->get_port());
        }

        ZSTR_LEN(retval) = n_bytes;
        ZSTR_VAL(retval)[ZSTR_LEN(retval)] = '\0';
        RETURN_STR(retval);
    }
}

static PHP_METHOD(swoole_client_coro, sendfile) {
    char *file;
    size_t file_len;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &file, &file_len, &offset, &length) == FAILURE) {
        RETURN_FALSE;
    }
    if (file_len == 0) {
        php_swoole_fatal_error(E_WARNING, "file to send is empty");
        RETURN_FALSE;
    }

    CLIENT_CORO_GET_SOCKET(cli);

    // only stream socket can sendfile
    if (!(cli->get_type() == SW_SOCK_TCP || cli->get_type() == SW_SOCK_TCP6 ||
          cli->get_type() == SW_SOCK_UNIX_STREAM)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), EINVAL);
        zend_update_property_string(
            swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), "dgram socket cannot use sendfile");
        RETURN_FALSE;
    }
    if (!cli->sendfile(file, offset, length)) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        RETVAL_FALSE;
    } else {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, recv) {
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    CLIENT_CORO_GET_SOCKET(cli);

    ssize_t retval;
    zend_string *result = nullptr;

    if (cli->open_length_check || cli->open_eof_check) {
        retval = cli->recv_packet(timeout);
        if (retval > 0) {
            auto strval = cli->pop_packet();
            if (strval == nullptr) {
                retval = -1;
                cli->set_err(ENOMEM);
            } else {
                result = zend::fetch_zend_string_by_val(strval);
            }
        }
    } else {
        result = zend_string_alloc(SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string), 0);
        Socket::TimeoutSetter ts(cli, timeout, Socket::TIMEOUT_READ);
        retval = cli->recv(ZSTR_VAL(result), SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string));
        if (retval <= 0) {
            zend_string_free(result);
        }
    }
    if (retval < 0) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        RETURN_FALSE;
    } else if (retval == 0) {
        RETURN_EMPTY_STRING();
    } else {
        ZSTR_VAL(result)[retval] = '\0';
        ZSTR_LEN(result) = retval;
        RETURN_STR(result);
    }
}

static PHP_METHOD(swoole_client_coro, peek) {
    zend_long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    int ret;
    char *buf = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(buf_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    CLIENT_CORO_GET_SOCKET(cli);

    buf = (char *) emalloc(buf_len + 1);
    ret = cli->peek(buf, buf_len);
    if (ret < 0) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        efree(buf);
        RETURN_FALSE;
    } else {
        buf[ret] = 0;
        RETVAL_STRINGL(buf, ret);
        efree(buf);
    }
}

static PHP_METHOD(swoole_client_coro, isConnected) {
    Socket *cli = client_coro_get_socket(ZEND_THIS);
    if (cli && cli->is_connected()) {
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, getsockname) {
    CLIENT_CORO_GET_SOCKET(cli);

    Address sa;
    if (!cli->getsockname(&sa)) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        RETURN_FALSE;
    }

    array_init(return_value);
    zval zaddress;
    ZVAL_STRING(&zaddress, sa.get_ip());
    add_assoc_zval(return_value, "host", &zaddress); /* backward compatibility */
    Z_ADDREF(zaddress);
    add_assoc_zval(return_value, "address", &zaddress);
    add_assoc_long(return_value, "port", sa.get_port());
}

/**
 * export Swoole\Coroutine\Socket object
 */
static PHP_METHOD(swoole_client_coro, exportSocket) {
    auto cli = client_coro_get_client(ZEND_THIS);
    RETURN_ZVAL(&cli->socket_object, 1, 0);
}

static PHP_METHOD(swoole_client_coro, getpeername) {
    CLIENT_CORO_GET_SOCKET(cli);

    Address sa;
    if (!cli->getpeername(&sa)) {
        php_swoole_socket_set_error_properties(ZEND_THIS, cli);
        RETURN_FALSE;
    }

    array_init(return_value);
    zval zaddress;
    ZVAL_STRING(&zaddress, sa.get_ip());
    add_assoc_zval(return_value, "host", &zaddress); /* backward compatibility */
    Z_ADDREF(zaddress);
    add_assoc_zval(return_value, "address", &zaddress);
    add_assoc_long(return_value, "port", sa.get_port());
}

static PHP_METHOD(swoole_client_coro, close) {
    auto client = client_coro_get_client(ZEND_THIS);
    if (client->socket == nullptr) {
        php_swoole_socket_set_error_properties(ZEND_THIS, EBADF, strerror(EBADF));
        RETURN_FALSE;
    }
    zend_update_property_bool(Z_OBJCE_P(ZEND_THIS), SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connected"), 0);
    zval tmp_socket = client->socket_object;
    zval_add_ref(&tmp_socket);
    ON_SCOPE_EXIT {
        zval_ptr_dtor(&tmp_socket);
    };
    Socket *_socket = php_swoole_get_socket(&tmp_socket);
    if (!_socket->close()) {
        php_swoole_socket_set_error_properties(ZEND_THIS, _socket);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL) {
    CLIENT_CORO_GET_SOCKET(cli);
    if (cli->get_type() != SW_SOCK_TCP && cli->get_type() != SW_SOCK_TCP6) {
        php_swoole_fatal_error(E_WARNING, "cannot use enableSSL");
        RETURN_FALSE;
    }
    if (cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL has been enabled");
        RETURN_FALSE;
    }

    cli->enable_ssl_encrypt();

    zval *zset = sw_zend_read_property_ex(swoole_client_coro_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (php_swoole_array_length_safe(zset) > 0) {
        php_swoole_socket_set_ssl(cli, zset);
    }
    RETURN_BOOL(cli->ssl_handshake());
}

static PHP_METHOD(swoole_client_coro, getPeerCert) {
    CLIENT_CORO_GET_SOCKET(cli);
    if (!cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    if (!cli->get_socket()->ssl_get_peer_certificate(sw_tg_buffer())) {
        RETURN_FALSE;
    }
    RETURN_SW_STRING(sw_tg_buffer());
}

static PHP_METHOD(swoole_client_coro, verifyPeerCert) {
    CLIENT_CORO_GET_SOCKET(cli);
    if (!cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &allow_self_signed) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->ssl_verify(allow_self_signed));
}
#endif
