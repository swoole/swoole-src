/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 6a9cfe85f83be95d7600172f5d9f9f50ba4cd1ea */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table___construct, 0, 0, 1)
	ZEND_ARG_INFO(0, table_size)
	ZEND_ARG_INFO(0, conflict_proportion)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_column, 0, 0, 2)
	ZEND_ARG_INFO(0, name)
	ZEND_ARG_INFO(0, type)
	ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_create, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_set, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_get, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, field)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_del, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Table_exists arginfo_class_Swoole_Table_del

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Table_incr, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, column)
	ZEND_ARG_INFO(0, incrby)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Table_decr arginfo_class_Swoole_Table_incr

#define arginfo_class_Swoole_Table_count arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_destroy arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_getSize arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_getMemorySize arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_stats arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_rewind arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_next arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_current arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_key arginfo_class_Swoole_Table_create

#define arginfo_class_Swoole_Table_valid arginfo_class_Swoole_Table_create
