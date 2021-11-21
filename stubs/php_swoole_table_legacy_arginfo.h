ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, table_size)
    ZEND_ARG_INFO(0, conflict_proportion)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_column, 0, 0, 2)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_set, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_ARRAY_INFO(0, value, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_get, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, field)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_del, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_incr, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, column)
    ZEND_ARG_INFO(0, incrby)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_decr, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, column)
    ZEND_ARG_INFO(0, decrby)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_rewind, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_next, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_current, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_key, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_valid, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_table_iterator_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Table___construct    arginfo_swoole_table_construct
#define arginfo_class_Swoole_Table_column         arginfo_swoole_table_column
#define arginfo_class_Swoole_Table_create         arginfo_swoole_table_void
#define arginfo_class_Swoole_Table_destroy        arginfo_swoole_table_void
#define arginfo_class_Swoole_Table_set            arginfo_swoole_table_set
#define arginfo_class_Swoole_Table_get            arginfo_swoole_table_get
#define arginfo_class_Swoole_Table_count          arginfo_swoole_table_iterator_count
#define arginfo_class_Swoole_Table_del            arginfo_swoole_table_del
#define arginfo_class_Swoole_Table_exists         arginfo_swoole_table_exists
#define arginfo_class_Swoole_Table_incr           arginfo_swoole_table_incr
#define arginfo_class_Swoole_Table_decr           arginfo_swoole_table_decr
#define arginfo_class_Swoole_Table_getSize        arginfo_swoole_table_void
#define arginfo_class_Swoole_Table_getMemorySize  arginfo_swoole_table_void
#define arginfo_class_Swoole_Table_stats          arginfo_swoole_table_void
#define arginfo_class_Swoole_Table_rewind         arginfo_swoole_table_iterator_rewind
#define arginfo_class_Swoole_Table_valid          arginfo_swoole_table_iterator_valid
#define arginfo_class_Swoole_Table_next           arginfo_swoole_table_iterator_next
#define arginfo_class_Swoole_Table_current        arginfo_swoole_table_iterator_current
#define arginfo_class_Swoole_Table_key            arginfo_swoole_table_iterator_key
