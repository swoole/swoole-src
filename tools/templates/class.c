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

#include "php_swoole_private.h"

using swoole::{{class_name}};

zend_class_entry *swoole_{{module_name}}_ce;
zend_object_handlers swoole_{{module_name}}_handlers;

struct {{type_name}} {
    {{class_name}} *{{var_name}};
    zend_object std;
};

static zend_always_inline {{class_name}} *swoole_{{module_name}}_get_handle(zend_object *object) {
    return (({{type_name}} *) ((char *) object - swoole_{{module_name}}_handlers.offset))->{{var_name}};
}

static zend_always_inline {{type_name}} *swoole_{{module_name}}_get_object(zend_object *object) {
    return ({{type_name}} *) ((char *) object - swoole_{{module_name}}_handlers.offset);
}

static zend_always_inline {{class_name}} *swoole_{{module_name}}_get_handle(zval *zobject) {
    return (({{type_name}} *) ((char *) Z_OBJ_P(zobject) - swoole_{{module_name}}_handlers.offset))->{{var_name}};
}

static zend_always_inline {{type_name}} *swoole_{{module_name}}_get_object(zval *zobject) {
    return ({{type_name}} *) ((char *) Z_OBJ_P(zobject) - swoole_{{module_name}}_handlers.offset);
}

static zend_always_inline {{type_name}} *swoole_{{module_name}}_get_object_safe(zval *zobject) {
    {{class_name}} *{{var_name}} = swoole_{{module_name}}_get_handle(zobject);
    if (!{{var_name}}) {
        php_swoole_fatal_error(E_ERROR, "you must call {{module_name}} constructor first");
    }
    return swoole_{{module_name}}_get_object(zobject);
}

static zend_always_inline {{type_name}} *swoole_{{module_name}}_get_object_safe(zend_object *object) {
    {{class_name}} *{{var_name}} = swoole_{{module_name}}_get_handle(object);
    if (!{{var_name}}) {
        php_swoole_fatal_error(E_ERROR, "you must call {{module_name}} constructor first");
    }
    return swoole_{{module_name}}_get_object(object);
}

static zend_object *swoole_{{module_name}}_create_object(zend_class_entry *ce) {
    {{type_name}} *{{php_var_name}} = ({{type_name}} *) zend_object_alloc(sizeof(*{{php_var_name}}), ce);

    zend_object_std_init(&{{php_var_name}}->std, ce);
    object_properties_init(&{{php_var_name}}->std, ce);
    {{php_var_name}}->std.handlers = &swoole_{{module_name}}_handlers;
    {{php_var_name}}->{{var_name}} = new {{class_name}};

    return &{{php_var_name}}->std;
}

static void swoole_{{module_name}}_free_object(zend_object *object) {
    {{type_name}} *{{php_var_name}} = swoole_{{module_name}}_get_object(object);
    zend_object_std_dtor(&{{php_var_name}}->std);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_{{module_name}}__construct, 0, ZEND_RETURN_VALUE, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_LONG, 0)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_{{module_name}}, __construct) {
    zend_long value;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END();
}

static const zend_function_entry swoole_{{module_name}}_methods[] = {
    PHP_ME(swoole_{{module_name}}, __construct, arginfo_swoole_{{module_name}}__construct, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

int swoole_{{module_name}}_module_init(INIT_FUNC_ARGS) {
    SW_INIT_CLASS_ENTRY_STD(swoole_{{module_name}}, "Swoole\\{{class_name}}", swoole_{{module_name}}_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_{{module_name}});
    SW_SET_CLASS_CLONEABLE(swoole_{{module_name}}, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_{{module_name}}, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
            swoole_{{module_name}}, swoole_{{module_name}}_create_object, swoole_{{module_name}}_free_object, {{type_name}}, std);

    return SUCCESS;
}
