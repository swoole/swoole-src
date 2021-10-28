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

#include "php_swoole_private.h"
#include "swoole_resolve_context_x_arginfo.h"

using swoole::ResolveContext;

BEGIN_EXTERN_C()

zend_class_entry *swoole_resolve_context_ce;
zend_object_handlers swoole_resolve_context_handlers;

struct ResolveContextObject {
    ResolveContext *resolve_context;
    zend_object std;
};

static zend_always_inline ResolveContext *swoole_resolve_context_get_handle(zend_object *object) {
    return ((ResolveContextObject *) ((char *) object - swoole_resolve_context_handlers.offset))->resolve_context;
}

static zend_always_inline ResolveContextObject *swoole_resolve_context_get_object(zend_object *object) {
    return (ResolveContextObject *) ((char *) object - swoole_resolve_context_handlers.offset);
}

static zend_always_inline ResolveContextObject *swoole_resolve_context_get_object_safe(zend_object *object) {
    ResolveContext *resolve_context = swoole_resolve_context_get_handle(object);
    if (!resolve_context) {
        php_swoole_fatal_error(E_ERROR, "must call resolve_context constructor first");
    }
    return swoole_resolve_context_get_object(object);
}

static zend_object *swoole_resolve_context_create_object(zend_class_entry *ce) {
    ResolveContextObject *resolve_context_object =
        (ResolveContextObject *) zend_object_alloc(sizeof(*resolve_context_object), ce);

    zend_object_std_init(&resolve_context_object->std, ce);
    object_properties_init(&resolve_context_object->std, ce);
    resolve_context_object->std.handlers = &swoole_resolve_context_handlers;
    resolve_context_object->resolve_context = new ResolveContext();

    return &resolve_context_object->std;
}

static void swoole_resolve_context_free_object(zend_object *object) {
    ResolveContextObject *resolve_context_object = swoole_resolve_context_get_object(object);
    delete resolve_context_object->resolve_context;
    zend_object_std_dtor(&resolve_context_object->std);
}

ZEND_METHOD(Swoole_ResolveContext, __construct) {
    zend_long family = AF_INET;
    zend_bool with_port = false;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(family)
    Z_PARAM_BOOL(with_port)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ResolveContextObject *obj = swoole_resolve_context_get_object_safe(Z_OBJ_P(ZEND_THIS));
    obj->resolve_context->with_port = with_port;
    obj->resolve_context->type = family;
}

void php_swoole_resolve_context_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_STD(swoole_resolve_context, "Swoole\\ResolveContext", class_Swoole_ResolveContext_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_resolve_context);
    SW_SET_CLASS_CLONEABLE(swoole_resolve_context, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_resolve_context, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_resolve_context,
                               swoole_resolve_context_create_object,
                               swoole_resolve_context_free_object,
                               ResolveContextObject,
                               std);
}

PHP_FUNCTION(swoole_name_resolver_lookup) {
    char *name;
    size_t l_name;
    zval *zcontext;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(name, l_name)
    Z_PARAM_OBJECT(zcontext)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ResolveContextObject *obj = swoole_resolve_context_get_object_safe(Z_OBJ_P(zcontext));
    auto result = swoole_name_resolver_lookup(std::string(name, l_name), obj->resolve_context);
    RETURN_STRINGL(result.c_str(), result.length());
}

END_EXTERN_C()
