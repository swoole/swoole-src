/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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
#include "module.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_module_call, 0, 0, 2)
    ZEND_ARG_INFO(0, func)
    ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_module_ce;
static zend_class_entry *swoole_module_class_entry_ptr;

static PHP_METHOD(swoole_module, __call);

static const zend_function_entry swoole_module_methods[] =
{
    PHP_ME(swoole_module, __call, arginfo_swoole_module_call, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_module_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_module_ce, "swoole_module", "Swoole\\Module", swoole_module_methods);
    swoole_module_class_entry_ptr = zend_register_internal_class(&swoole_module_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_module, "Swoole\\Module");
}

PHP_FUNCTION(swoole_load_module)
{
    char *name;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &len) == FAILURE)
    {
        return;
    }
    if (access(name, R_OK) < 0)
    {
        swoole_php_error(E_WARNING, "file[%s] not found.", name);
        RETURN_FALSE;
    }
    swModule *module = swModule_load(name);
    if (module == NULL)
    {
        RETURN_FALSE;
    }
    object_init_ex(return_value, swoole_module_class_entry_ptr);
    swoole_set_object(return_value, module);
}

typedef void (*swModule_function)(swModule *, zval *, zval *);

static PHP_METHOD(swoole_module, __call)
{
    zval *params;
    char *name;
    zend_size_t name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &name_len, &params) == FAILURE)
    {
        return;
    }
    swModule *module = swoole_get_object(getThis());
    if (module == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Please use swoole_load_module().");
        return;
    }
    swModule_function func = swHashMap_find(module->functions, name, name_len);
    if (func == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Module[%s] does not have [%s] function.", module->name, name);
        return;
    }
    func(module, params, return_value);
}

