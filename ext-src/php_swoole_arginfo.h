/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 7d05091fc87828ebabc77c6c797984366e7afd4a */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_get_objects, 0, 0, MAY_BE_ARRAY|MAY_BE_BOOL)
ZEND_END_ARG_INFO()

#define arginfo_swoole_get_vm_status arginfo_swoole_get_objects

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_get_object_by_handle, 0, 1, MAY_BE_OBJECT|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO(0, handle, IS_LONG, 0)
ZEND_END_ARG_INFO()


ZEND_FUNCTION(swoole_get_objects);
ZEND_FUNCTION(swoole_get_vm_status);
ZEND_FUNCTION(swoole_get_object_by_handle);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(swoole_get_objects, arginfo_swoole_get_objects)
	ZEND_FE(swoole_get_vm_status, arginfo_swoole_get_vm_status)
	ZEND_FE(swoole_get_object_by_handle, arginfo_swoole_get_object_by_handle)
	ZEND_FE_END
};
