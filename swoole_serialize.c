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
  | Author: xinhua.guo  <woshiguo35@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "swoole_serialize.h"

#if PHP_MAJOR_VERSION == 7

static PHP_METHOD(swoole_serialize, __construct);
static PHP_METHOD(swoole_serialize, __destruct);
static PHP_METHOD(swoole_serialize, pack);
static PHP_METHOD(swoole_serialize, fastPack);
static PHP_METHOD(swoole_serialize, unpack);


static const zend_function_entry swoole_serialize_methods[] =
{
    PHP_ME(swoole_serialize, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_serialize, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_serialize, pack, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(swoole_serialize, fastPack, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(swoole_serialize, unpack, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};

zend_class_entry swoole_serialize_ce;
zend_class_entry *swoole_serialize_class_entry_ptr;

void swoole_serialize_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_serialize_ce, "swoole_serialize", "Swoole\\Serialize", swoole_serialize_methods);
    swoole_serialize_class_entry_ptr = zend_register_internal_class(&swoole_serialize_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_serialize, "Swoole\\Serialize");
}



static PHP_METHOD(swoole_serialize, pack)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

}

static PHP_METHOD(swoole_serialize, fastPack)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

}


static PHP_METHOD(swoole_serialize, unpack)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

}


#endif