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
    bool resolving;
    zend_object std;
};

static zend_always_inline NameResolver::Context *swoole_name_resolver_context_get_handle(zend_object *object) {
    return reinterpret_cast<ContextObject *>(reinterpret_cast<char *>(object) -
                                             swoole_name_resolver_context_handlers.offset)
        ->context;
}

static zend_always_inline ContextObject *swoole_name_resolver_context_get_object(zend_object *object) {
    return reinterpret_cast<ContextObject *>(reinterpret_cast<char *>(object) -
                                             swoole_name_resolver_context_handlers.offset);
}

static zend_always_inline ContextObject *swoole_name_resolver_context_get_object_safe(zend_object *object) {
    NameResolver::Context *name_resolver_context = swoole_name_resolver_context_get_handle(object);
    if (UNEXPECTED(!name_resolver_context)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return swoole_name_resolver_context_get_object(object);
}

static zend_object *swoole_name_resolver_context_create_object(zend_class_entry *ce) {
    auto *name_resolver_context_object = static_cast<ContextObject *>(zend_object_alloc(sizeof(ContextObject), ce));

    zend_object_std_init(&name_resolver_context_object->std, ce);
    object_properties_init(&name_resolver_context_object->std, ce);
    name_resolver_context_object->std.handlers = &swoole_name_resolver_context_handlers;
    name_resolver_context_object->context = new NameResolver::Context();
    name_resolver_context_object->resolving = false;

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

    if (family != AF_INET && family != AF_INET6) {
        zend_argument_value_error(1, "must be AF_INET or AF_INET6");
        RETURN_THROWS();
    }
    ContextObject *obj = swoole_name_resolver_context_get_object_safe(Z_OBJ_P(ZEND_THIS));
    if (obj->resolving) {
        zend_throw_error(nullptr, "NameResolver Context is already in use");
        RETURN_THROWS();
    }
    obj->context->reset();
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
    Z_PARAM_OBJECT_OF_CLASS(zcontext, swoole_name_resolver_context_ce)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ContextObject *obj = swoole_name_resolver_context_get_object_safe(Z_OBJ_P(zcontext));
    if (l_name == 0 || memchr(name, '\0', l_name)) {
        zend_argument_value_error(1, "must be nonempty and contain no null bytes");
        RETURN_THROWS();
    }
    if (obj->resolving) {
        zend_throw_error(nullptr, "NameResolver Context is already in use");
        RETURN_THROWS();
    }
    obj->resolving = true;
    ON_SCOPE_EXIT {
        obj->resolving = false;
    };
    auto result = swoole_name_resolver_lookup(std::string(name, l_name), obj->context);
    if (EG(exception)) {
        RETURN_THROWS();
    }
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

    bool found = false;
    swoole_name_resolver_each(
        [&found, zresolver](const std::list<NameResolver>::iterator &iter) -> swTraverseOperation {
            if (found) {
                return SW_TRAVERSE_STOP;
            }
            if (iter->type != NameResolver::TYPE_PHP || iter->private_data == nullptr) {
                return SW_TRAVERSE_KEEP;
            }
            zval *stored_resolver = static_cast<zval *>(iter->private_data);
            if (Z_OBJ_P(stored_resolver) == Z_OBJ_P(zresolver)) {
                found = true;
                return SW_TRAVERSE_REMOVE;
            } else {
                return SW_TRAVERSE_KEEP;
            }
        });
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
    bool exists = false;
    swoole_name_resolver_each(
        [&exists, zresolver](const std::list<NameResolver>::iterator &iter) -> swTraverseOperation {
            if (iter->type == NameResolver::TYPE_PHP && iter->private_data &&
                Z_OBJ_P(static_cast<zval *>(iter->private_data)) == Z_OBJ_P(zresolver)) {
                exists = true;
                return SW_TRAVERSE_STOP;
            }
            return SW_TRAVERSE_KEEP;
        });
    if (exists) {
        return true;
    }
    auto owner = std::shared_ptr<zval>(sw_zval_dup(zresolver), [](zval *value) {
        zval_ptr_dtor(value);
        efree(value);
    });
    Z_TRY_ADDREF_P(owner.get());
    NameResolver resolver{php_swoole_name_resolver_lookup, owner.get(), NameResolver::TYPE_PHP, owner};
    swoole_name_resolver_add(resolver);
    return true;
}

std::string php_swoole_name_resolver_lookup(const std::string &name, NameResolver::Context *ctx, void *_resolver) {
    zval retval;
    ZVAL_UNDEF(&retval);
    zval *zresolver = (zval *) _resolver;

    if (!ctx->private_data) {
        zval zname;
        ZVAL_STRINGL(&zname, name.c_str(), name.length());
        zend_call_method_with_1_params(SW_Z8_OBJ_P(zresolver), nullptr, nullptr, "lookup", &retval, &zname);
        zval_dtor(&zname);
        if (EG(exception)) {
            zval_ptr_dtor(&retval);
            ctx->final_ = true;
            return "";
        }
        if (Z_TYPE(retval) == IS_OBJECT) {
            auto class_name = zend_string_init(ZEND_STRL("Swoole\\NameResolver\\Cluster"), false);
            auto ce = zend_lookup_class(class_name);
            zend_string_release(class_name);
            if (!ce || !instanceof_function(Z_OBJCE(retval), ce)) {
                zval_ptr_dtor(&retval);
                zend_type_error("NameResolver::lookup() must return a Cluster, node array, IP string, false or null");
                ctx->final_ = true;
                return "";
            }
            auto *zcluster_object = (zval *) emalloc(sizeof(zval));
            ZVAL_OBJ(zcluster_object, Z_OBJ_HT(retval)->clone_obj(Z_OBJ(retval)));
            zval_ptr_dtor(&retval);
            if (EG(exception)) {
                zval_ptr_dtor(zcluster_object);
                efree(zcluster_object);
                ctx->final_ = true;
                return "";
            }
            ctx->private_data = zcluster_object;
            ctx->dtor = [](NameResolver::Context *ctx) {
                zval *_zcluster_object = (zval *) ctx->private_data;
                zval_dtor(_zcluster_object);
                efree(_zcluster_object);
            };
            ctx->resolver = _resolver;
            ctx->cluster_ = true;
            ctx->final_ = false;
        } else if (Z_TYPE(retval) == IS_STRING) {
            ctx->final_ = true;
            ctx->cluster_ = false;
            std::string result(Z_STRVAL(retval), Z_STRLEN(retval));
            zval_ptr_dtor(&retval);
            if (!result.empty() && !swoole::network::Address::verify_ip(ctx->type, result)) {
                zend_value_error("NameResolver::lookup() returned an invalid IP address for the requested family");
                return "";
            }
            if (!result.empty()) {
                ctx->resolver = _resolver;
                ctx->exhausted = true;
            }
            return result;
        } else if (Z_TYPE(retval) != IS_ARRAY) {
            ctx->final_ = false;
            ctx->cluster_ = false;
            if (Z_TYPE(retval) != IS_FALSE && Z_TYPE(retval) != IS_NULL) {
                zend_type_error("NameResolver::lookup() must return a Cluster, node array, IP string, false or null");
                ctx->final_ = true;
            }
            zval_ptr_dtor(&retval);
            return "";
        }
    }

    ctx->final_ = true;
    while (true) {
        if (ctx->private_data) {
            ZVAL_UNDEF(&retval);
            sw_zend_call_method_with_0_params((zval *) ctx->private_data, nullptr, nullptr, "pop", &retval);
            if (EG(exception)) {
                zval_ptr_dtor(&retval);
                return "";
            }
            if (Z_TYPE(retval) == IS_FALSE) {
                zval_ptr_dtor(&retval);
                ctx->exhausted = true;
                return "";
            }
        }
        if (Z_TYPE(retval) != IS_ARRAY) {
            zval_ptr_dtor(&retval);
            zend_type_error("NameResolver cluster nodes must be arrays");
            return "";
        }
        zval *zhost = zend_hash_str_find(Z_ARRVAL(retval), ZEND_STRL("host"));
        zval *zport = zend_hash_str_find(Z_ARRVAL(retval), ZEND_STRL("port"));
        if (!zhost || Z_TYPE_P(zhost) != IS_STRING ||
            (!swoole::network::Address::verify_ip(AF_INET, std::string(Z_STRVAL_P(zhost), Z_STRLEN_P(zhost))) &&
             !swoole::network::Address::verify_ip(AF_INET6, std::string(Z_STRVAL_P(zhost), Z_STRLEN_P(zhost)))) ||
            !zport || Z_TYPE_P(zport) != IS_LONG || Z_LVAL_P(zport) < 1 || Z_LVAL_P(zport) > 65535) {
            zval_ptr_dtor(&retval);
            zend_value_error("NameResolver node must contain a valid IP host and an integer port between 1 and 65535");
            return "";
        }
        std::string result(Z_STRVAL_P(zhost), Z_STRLEN_P(zhost));
        if (!swoole::network::Address::verify_ip(ctx->type, result)) {
            zval_ptr_dtor(&retval);
            if (ctx->private_data) {
                continue;
            }
            return "";
        }
        if (ctx->with_port) {
            result.append(ctx->type == AF_INET6 ? "@" : ":");
            result.append(std::to_string(Z_LVAL_P(zport)));
        }
        if (!ctx->private_data) {
            ctx->resolver = _resolver;
            ctx->exhausted = true;
        }
        zval_ptr_dtor(&retval);
        return result;
    }
}

NameResolver::Context *php_swoole_name_resolver_get_context(zval *zobject) {
    return swoole_name_resolver_context_get_handle(Z_OBJ_P(zobject));
}
