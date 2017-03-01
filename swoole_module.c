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

static zend_class_entry swoole_module_ce;
static zend_class_entry *swoole_module_class_entry_ptr;

void swoole_module_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_module_ce, "swoole_module", "Swoole\\Module", NULL);
    swoole_module_class_entry_ptr = zend_register_internal_class(&swoole_module_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_module, "Swoole\\Module");
}

static zval *loaded_modules = NULL;

PHP_FUNCTION(swoole_load_module)
{
    char *name;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &len) == FAILURE)
    {
        return;
    }

    if (loaded_modules == NULL)
    {
        SW_ALLOC_INIT_ZVAL(loaded_modules);
        array_init(loaded_modules);
    }
    else
    {
        zval *value;
        if (sw_zend_hash_find(Z_ARRVAL_P(loaded_modules), name, len + 1, (void **) &value) == SUCCESS)
        {
            RETURN_ZVAL(value, 1, 0);
        }
    }

    swModule *module = swModule_load(name);
    if (module == NULL)
    {
        RETURN_FALSE;
    }
    object_init_ex(return_value, swoole_module_class_entry_ptr);
    swoole_set_object(return_value, module);
    sw_zend_hash_update(Z_ARRVAL_P(loaded_modules), name, len + 1, return_value, sizeof(return_value), NULL);
}
