/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: b29d035d9a0fdb9b381bed781e790e6892ab209f */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_get_objects, 0, 0, MAY_BE_FALSE|MAY_BE_ARRAY)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_get_vm_status, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_get_object_by_handle, 0, 1, MAY_BE_FALSE|MAY_BE_OBJECT)
	ZEND_ARG_TYPE_INFO(0, handle, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_name_resolver_lookup, 0, 2, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, ctx, Swoole\\NameResolver\\Context, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_name_resolver_add, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ns, Swoole\\NameResolver, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_name_resolver_remove arginfo_swoole_name_resolver_add


ZEND_FUNCTION(swoole_get_objects);
ZEND_FUNCTION(swoole_get_vm_status);
ZEND_FUNCTION(swoole_get_object_by_handle);
ZEND_FUNCTION(swoole_name_resolver_lookup);
ZEND_FUNCTION(swoole_name_resolver_add);
ZEND_FUNCTION(swoole_name_resolver_remove);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(swoole_get_objects, arginfo_swoole_get_objects)
	ZEND_FE(swoole_get_vm_status, arginfo_swoole_get_vm_status)
	ZEND_FE(swoole_get_object_by_handle, arginfo_swoole_get_object_by_handle)
	ZEND_FE(swoole_name_resolver_lookup, arginfo_swoole_name_resolver_lookup)
	ZEND_FE(swoole_name_resolver_add, arginfo_swoole_name_resolver_add)
	ZEND_FE(swoole_name_resolver_remove, arginfo_swoole_name_resolver_remove)
	ZEND_FE_END
};
