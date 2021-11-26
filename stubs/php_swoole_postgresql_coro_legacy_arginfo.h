ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_connect, 0, 0, -1)
    ZEND_ARG_INFO(0, conninfo)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_query, 0, 0, 0)
    ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_send_prepare, 0, 0, 2)
    ZEND_ARG_INFO(0, stmtname)
    ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_send_execute, 0, 0, 2)
    ZEND_ARG_INFO(0, stmtname)
    ZEND_ARG_INFO(0, pv_param_arr)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_all, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_affected_rows, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_num_rows, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_field_count, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_meta_data, 0, 0, 1)
    ZEND_ARG_INFO(0, table_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_row, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_assoc, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_array, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_object, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, class_name)
    ZEND_ARG_INFO(0, ctor_params)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_PostgreSQL___construct      arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_PostgreSQL_connect          arginfo_pg_connect
#define arginfo_class_Swoole_Coroutine_PostgreSQL_query            arginfo_pg_query
#define arginfo_class_Swoole_Coroutine_PostgreSQL_prepare          arginfo_pg_send_prepare
#define arginfo_class_Swoole_Coroutine_PostgreSQL_execute          arginfo_pg_send_execute
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAll         arginfo_pg_fetch_all
#define arginfo_class_Swoole_Coroutine_PostgreSQL_affectedRows     arginfo_pg_affected_rows
#define arginfo_class_Swoole_Coroutine_PostgreSQL_numRows          arginfo_pg_num_rows
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fieldCount       arginfo_pg_field_count
#define arginfo_class_Swoole_Coroutine_PostgreSQL_metaData         arginfo_pg_meta_data
#define arginfo_class_Swoole_Coroutine_PostgreSQL_escape           arginfo_pg_escape
#define arginfo_class_Swoole_Coroutine_PostgreSQL_escapeLiteral    arginfo_pg_escape
#define arginfo_class_Swoole_Coroutine_PostgreSQL_escapeIdentifier arginfo_pg_escape
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fetchObject      arginfo_pg_fetch_object
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAssoc       arginfo_pg_fetch_assoc
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fetchArray       arginfo_pg_fetch_array
#define arginfo_class_Swoole_Coroutine_PostgreSQL_fetchRow         arginfo_pg_fetch_row
#define arginfo_class_Swoole_Coroutine_PostgreSQL___destruct       arginfo_swoole_void
