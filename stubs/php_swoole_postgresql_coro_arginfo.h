/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: f5d2fcbed05b70d92a528926b229eb75d91c0b3c */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQL___destruct arginfo_class_Swoole_Coroutine_PostgreSQL___construct

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_connect, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, conninfo, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "2")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_escape, 0, 1, MAY_BE_FALSE|MAY_BE_STRING)
	ZEND_ARG_TYPE_INFO(0, string, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQL_escapeLiteral arginfo_class_Swoole_Coroutine_PostgreSQL_escape

#define arginfo_class_Swoole_Coroutine_PostgreSQL_escapeIdentifier arginfo_class_Swoole_Coroutine_PostgreSQL_escape

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_query, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, query, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_prepare, 0, 2, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, stmtname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, query, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_execute, 0, 2, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, stmtname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, pv_param_arr, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAll, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_INFO(0, result)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_ASSOC")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_affectedRows, 0, 1, IS_LONG, 0)
	ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQL_numRows arginfo_class_Swoole_Coroutine_PostgreSQL_affectedRows

#define arginfo_class_Swoole_Coroutine_PostgreSQL_fieldCount arginfo_class_Swoole_Coroutine_PostgreSQL_affectedRows

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_metaData, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO(0, table_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_fetchObject, 0, 1, MAY_BE_FALSE|MAY_BE_OBJECT)
	ZEND_ARG_INFO(0, result)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, class_name, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, ctor_params, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAssoc, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_INFO(0, result)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_ASSOC")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_fetchArray, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_INFO(0, result)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_BOTH")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_fetchRow, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_INFO(0, result)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_NUM")
ZEND_END_ARG_INFO()
