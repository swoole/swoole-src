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

BEGIN_EXTERN_C()
#include "stubs/php_swoole_name_resolver_arginfo.h"
END_EXTERN_C()

using swoole::NameResolver;

BEGIN_EXTERN_C()

#include "ext/spl/php_spl.h"

zend_class_entry *swoole_name_resolver_context_ce;
zend_object_handlers swoole_name_resolver_context_handlers;

struct ContextObject {
    NameResolver::Context *context;
    zend_object std;
};

static zend_always_inline NameResolver::Context *swoole_name_resolver_context_get_handle(zend_object *object) {
    return ((ContextObject *) ((char *) object - swoole_name_resolver_context_handlers.offset))->context;
}

static zend_always_inline ContextObject *swoole_name_resolver_context_get_object(zend_object *object) {
    return (ContextObject *) ((char *) object - swoole_name_resolver_context_handlers.offset);
}

static zend_always_inline ContextObject *swoole_name_resolver_context_get_object_safe(zend_object *object) {
    NameResolver::Context *name_resolver_context = swoole_name_resolver_context_get_handle(object);
    if (!name_resolver_context) {
        php_swoole_fatal_error(E_ERROR, "must call name_resolver_context constructor first");
    }
    return swoole_name_resolver_context_get_object(object);
}

static zend_object *swoole_name_resolver_context_create_object(zend_class_entry *ce) {
    ContextObject *name_resolver_context_object =
        (ContextObject *) zend_object_alloc(sizeof(*name_resolver_context_object), ce);

    zend_object_std_init(&name_resolver_context_object->std, ce);
    object_properties_init(&name_resolver_context_object->std, ce);
    name_resolver_context_object->std.handlers = &swoole_name_resolver_context_handlers;
    name_resolver_context_object->context = new NameResolver::Context();

    return &name_resolver_context_object->std;
}

static void swoole_name_resolver_context_free_object(zend_object *object) {
    ContextObject *name_resolver_context_object = swoole_name_resolver_context_get_object(object);
    delete name_resolver_context_object->context;
    zend_object_std_dtor(&name_resolver_context_object->std);
}

ZEND_METHOD(Swoole_NameResolver_Context, __construct) {
    zend_long family = AF_INET;
    zend_bool with_port = false;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(family)
    Z_PARAM_BOOL(with_port)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ContextObject *obj = swoole_name_resolver_context_get_object_safe(Z_OBJ_P(ZEND_THIS));
    obj->context->with_port = with_port;
    obj->context->type = family;
}

void php_swoole_name_resolver_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_STD(
        swoole_name_resolver_context, "Swoole\\NameResolver\\Context", class_Swoole_NameResolver_Context_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_name_resolver_context);
    SW_SET_CLASS_CLONEABLE(swoole_name_resolver_context, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_name_resolver_context, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_name_resolver_context,
                               swoole_name_resolver_context_create_object,
                               swoole_name_resolver_context_free_object,
                               ContextObject,
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

    ContextObject *obj = swoole_name_resolver_context_get_object_safe(Z_OBJ_P(zcontext));
    auto result = swoole_name_resolver_lookup(std::string(name, l_name), obj->context);
    RETURN_STRINGL(result.c_str(), result.length());
}

PHP_FUNCTION(swoole_name_resolver_add) {
    zval *zresolver;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_OBJECT(zresolver)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(php_swoole_name_resolver_add(zresolver));
}

PHP_FUNCTION(swoole_name_resolver_remove) {
    zval *zresolver;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_OBJECT(zresolver)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    auto hash_1 = sw_php_spl_object_hash(zresolver);
    bool found = false;
    swoole_name_resolver_each(
        [&found, hash_1, zresolver](const std::list<NameResolver>::iterator &iter) -> swTraverseOperation {
            if (found) {
                return SW_TRAVERSE_STOP;
            }
            auto hash_2 = sw_php_spl_object_hash((zval *) iter->private_data);
            bool equals = zend_string_equals(hash_2, hash_1);
            zend_string_release(hash_2);
            if (iter->type == NameResolver::TYPE_PHP && iter->private_data && equals) {
                zval_dtor(zresolver);
                efree(iter->private_data);
                found = true;
                return SW_TRAVERSE_REMOVE;
            } else {
                return SW_TRAVERSE_KEEP;
            }
        });
    zend_string_release(hash_1);
    RETURN_BOOL(found);
}

END_EXTERN_C()

bool php_swoole_name_resolver_add(zval *zresolver) {
    auto ce = zend_lookup_class(SW_ZSTR_KNOWN(SW_ZEND_STR_CLASS_NAME_RESOLVER));
    if (ce == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "Class \"%s\" not found", SW_ZSTR_KNOWN(SW_ZEND_STR_CLASS_NAME_RESOLVER)->val);
        return false;
    }
    if (!instanceof_function(Z_OBJCE_P(zresolver), ce)) {
        php_swoole_fatal_error(E_WARNING,
                               "the given object is not an instance of %s",
                               SW_ZSTR_KNOWN(SW_ZEND_STR_CLASS_NAME_RESOLVER)->val);
        return false;
    }
    zval_add_ref(zresolver);
    NameResolver resolver{php_swoole_name_resolver_lookup, sw_zval_dup(zresolver), NameResolver::TYPE_PHP};
    swoole_name_resolver_add(resolver);
    return true;
}

std::string php_swoole_name_resolver_lookup(const std::string &name, NameResolver::Context *ctx, void *_resolver) {
    zval *zcluster_object;
    zval retval;
    zval *zresolver = (zval *) _resolver;

    if (!ctx->private_data) {
    _lookup:
        zval zname;
        ZVAL_STRINGL(&zname, name.c_str(), name.length());
        zend_call_method_with_1_params(SW_Z8_OBJ_P(zresolver), NULL, NULL, "lookup", &retval, &zname);
        zval_dtor(&zname);
        if (Z_TYPE(retval) == IS_OBJECT) {
            ctx->private_data = zcluster_object = (zval *) ecalloc(1, sizeof(zval));
            ctx->dtor = [](NameResolver::Context *ctx) {
                zval *_zcluster_object = (zval *) ctx->private_data;
                zval_dtor(_zcluster_object);
                efree(_zcluster_object);
            };
            *zcluster_object = retval;
            ctx->cluster_ = true;
            ctx->final_ = false;
        } else if (Z_TYPE(retval) == IS_STRING) {
            ctx->final_ = true;
            ctx->cluster_ = false;
            return std::string(Z_STRVAL(retval), Z_STRLEN(retval));
        } else {
            ctx->final_ = false;
            ctx->cluster_ = false;
            return "";
        }
    } else {
        zcluster_object = (zval *) ctx->private_data;
        // no available node, resolve again
        sw_zend_call_method_with_0_params(zcluster_object, NULL, NULL, "count", &retval);
        if (zval_get_long(&retval) == 0) {
            ctx->dtor(ctx);
            ctx->private_data = nullptr;
            goto _lookup;
        }
    }

    sw_zend_call_method_with_0_params(zcluster_object, NULL, NULL, "pop", &retval);
    if (!ZVAL_IS_ARRAY(&retval)) {
        return "";
    }
    zval *zhost = zend_hash_str_find(HASH_OF(&retval), ZEND_STRL("host"));
    if (zhost == nullptr || !ZVAL_IS_STRING(zhost)) {
        return "";
    }
    std::string result(Z_STRVAL_P(zhost), Z_STRLEN_P(zhost));
    if (ctx->with_port) {
        result.append(":");
        zval *zport = zend_hash_str_find(HASH_OF(&retval), ZEND_STRL("port"));
        if (zport == nullptr) {
            return "";
        }
        result.append(std::to_string(zval_get_long(zport)));
    }
    zval_ptr_dtor(&retval);
    return result;
}

NameResolver::Context *php_swoole_name_resolver_get_context(zval *zobject) {
    return swoole_name_resolver_context_get_handle(Z_OBJ_P(zobject));
}
