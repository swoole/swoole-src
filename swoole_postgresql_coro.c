#include "php_swoole.h"
#include <libpq-fe.h>

static PHP_METHOD(swoole_postgresql_coro, __construct);
static PHP_METHOD(swoole_postgresql_coro, __destruct);
static PHP_METHOD(swoole_postgresql_coro, connect);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_postgresql_coro_methods[] =
{
    PHP_ME(swoole_postgresql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_postgresql_coro, connect, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_postgresql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

static zend_class_entry swoole_postgresql_coro_ce;
static zend_class_entry *swoole_postgresql_coro_class_entry_ptr;

void swoole_postgresql_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_postgresql_coro_ce, "Swoole\\Coroutine\\PostgreSql", swoole_postgresql_coro_methods);
    swoole_postgresql_coro_class_entry_ptr = zend_register_internal_class(&swoole_postgresql_coro_ce TSRMLS_CC);
    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\PostgreSql", swoole_postgresql_coro_class_entry_ptr);
    }
}
static PHP_METHOD(swoole_postgresql_coro, __construct)
{

}
static PHP_METHOD(swoole_postgresql_coro, connect)
{
    //PGconn

}
static PHP_METHOD(swoole_postgresql_coro, __destruct)
{

}
