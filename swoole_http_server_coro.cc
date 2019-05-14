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

using swoole::coroutine::Socket;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_class_entry *swoole_http_server_coro_ce;
static zend_object_handlers swoole_http_server_coro_handlers;

typedef struct
{
    Socket *socket;
    zend_object std;
} http_server_coro;

static PHP_METHOD(swoole_http_server_coro, __construct);
static PHP_METHOD(swoole_http_server_coro, handle);
static PHP_METHOD(swoole_http_server_coro, start);
static PHP_METHOD(swoole_http_server_coro, __destruct);

static const zend_function_entry swoole_http_server_coro_methods[] =
{
    PHP_ME(swoole_http_server_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, handle, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object *swoole_http_server_coro_create_object(zend_class_entry *ce)
{
    http_server_coro *hs = (http_server_coro *) ecalloc(1, sizeof(http_server_coro) + zend_object_properties_size(ce));
    zend_object_std_init(&hs->std, ce);
    object_properties_init(&hs->std, ce);
    hs->std.handlers = &swoole_http_server_coro_handlers;
    hs->socket = new Socket(SW_SOCK_TCP);
    return &hs->std;
}

static sw_inline http_server_coro* swoole_http_server_coro_fetch_object(zend_object *obj)
{
    return (http_server_coro *) ((char *) obj - swoole_http_server_coro_handlers.offset);
}

static void swoole_http_server_coro_free_object(zend_object *object)
{
    http_server_coro *hs = swoole_http_server_coro_fetch_object(object);
    if (hs->socket)
    {
        delete hs->socket;
    }
    zend_object_std_dtor(&hs->std);
}

void swoole_http_server_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http_server_coro, "Swoole\\Coroutine\\Http\\Server", NULL, "Co\\Http\\Server", swoole_http_server_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_server_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_server_coro, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_server_coro);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_server_coro, swoole_http_server_coro_create_object, swoole_http_server_coro_free_object, http_server_coro, std);

    zend_declare_property_null(swoole_http_server_ce, ZEND_STRL("onRequest"), ZEND_ACC_PRIVATE);
}

static PHP_METHOD(swoole_http_server_coro, __construct)
{
    http_server_coro *hsc = swoole_http_server_coro_fetch_object(Z_OBJ_P(getThis()));
    char *host;
    size_t host_len;
    zend_long port = 80;
    zend_bool ssl = 0;

       ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
           Z_PARAM_STRING(host, host_len)
           Z_PARAM_OPTIONAL
           Z_PARAM_LONG(port)
           Z_PARAM_BOOL(ssl)
       ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

       zend_update_property_stringl(swoole_http_client_coro_ce, getThis(), ZEND_STRL("host"), host, host_len);
       zend_update_property_long(swoole_http_client_coro_ce,getThis(), ZEND_STRL("port"), port);
       zend_update_property_bool(swoole_http_client_coro_ce,getThis(), ZEND_STRL("ssl"), ssl);
       // check host
       if (host_len == 0)
       {
           zend_throw_exception_ex(swoole_http_client_coro_exception_ce, EINVAL, "host is empty");
           RETURN_FALSE;
       }
       // check ssl
   #ifndef SW_USE_OPENSSL
       if (ssl)
       {
           zend_throw_exception_ex(
               swoole_http_client_coro_exception_ce,
               EPROTONOSUPPORT, "you must configure with `enable-openssl` to support ssl connection"
           );
           RETURN_FALSE;
       }
   #endif
}
