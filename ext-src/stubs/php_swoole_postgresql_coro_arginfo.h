/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: ee056d9d6e3dce3bf2198fbc7fb6bdd1aaab5206 */

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

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_query, 0, 1, Swoole\\Coroutine\\PostgreSQLStatement, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, query, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQL_prepare arginfo_class_Swoole_Coroutine_PostgreSQL_query

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQL_metaData, 0, 1, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO(0, table_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_execute, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, params, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fetchAll, 0, 0, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_ASSOC")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_affectedRows, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQLStatement_numRows arginfo_class_Swoole_Coroutine_PostgreSQLStatement_affectedRows

#define arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fieldCount arginfo_class_Swoole_Coroutine_PostgreSQLStatement_affectedRows

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fetchObject, 0, 0, MAY_BE_FALSE|MAY_BE_OBJECT)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, class_name, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, ctor_params, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fetchAssoc, 0, 0, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_ASSOC")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fetchArray, 0, 0, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_BOTH")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_PostgreSQLStatement_fetchRow, 0, 0, MAY_BE_FALSE|MAY_BE_ARRAY)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, row, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, result_type, IS_LONG, 0, "SW_PGSQL_NUM")
ZEND_END_ARG_INFO()
