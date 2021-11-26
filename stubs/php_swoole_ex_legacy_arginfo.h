/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: b34ba6d3ec570bd039d385f75fe01778a7494b25 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_get_objects, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_get_vm_status arginfo_swoole_get_objects

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_get_object_by_handle, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_name_resolver_lookup, 0, 0, 2)
	ZEND_ARG_INFO(0, name)
	ZEND_ARG_INFO(0, ctx)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_name_resolver_add, 0, 0, 1)
	ZEND_ARG_INFO(0, ns)
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
