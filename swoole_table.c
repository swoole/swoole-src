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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/


#include "php_swoole.h"
#include "atomic.h"

typedef struct
{
    HashTable *columns;
    swLock lock;
    sw_atomic_t *row_locks;
    uint32_t size;
    uint32_t row_size;
    void *memory;
} swTable;

typedef struct
{
   uint8_t type;
   uint16_t size;
   swString* name;
} swTableColumn;

enum swoole_table_type
{
    SW_TABLE_INT = 1,
    SW_TABLE_STRING,
    SW_TABLE_FLOAT,
};

static sw_inline swTable* php_swoole_table_get(zval *object TSRMLS_DC)
{
    zval **zres;
    swTable *table = NULL;
    if (zend_hash_find(Z_OBJPROP_P(object), SW_STRL("_table"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE_NO_RETURN(table, swTable*, zres, -1, SW_RES_TABLE_NAME, le_swoole_table);
    }
    assert(table != NULL);
    return table;
}

void swoole_destory_table(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
    swTable *table = (swTable *) rsrc->ptr;
}

PHP_METHOD(swoole_table, __construct)
{
    long table_size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &table_size) == FAILURE)
    {
        RETURN_FALSE;
    }
    swTable *table = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swTable));
    if (table == NULL)
    {
        zend_error(E_WARNING, "alloc failed.");
        RETURN_FALSE;
    }
    if (swMutex_create(&table->lock, 1) < 0)
    {
        zend_error(E_WARNING, "mutex create failed.");
        RETURN_FALSE;
    }
    table->size = table_size;
    zval *zres;
    MAKE_STD_ZVAL(zres);

    ZEND_REGISTER_RESOURCE(zres, table, le_swoole_table);
    zend_update_property(swoole_table_class_entry_ptr, getThis(), ZEND_STRL("_table"), zres TSRMLS_CC);

    zend_hash_init(table->columns, 16, NULL, ZVAL_PTR_DTOR, 0);

    zval_ptr_dtor(&zres);
}

PHP_METHOD(swoole_table, column)
{
    char *name;
    int len;
    long type;
    long size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|lb", &name, &len, &type, &size) == FAILURE)
    {
        RETURN_FALSE;
    }
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    swTableColumn col;
    col.name = swString_dup(name, len);
    if (!col.name)
    {
        RETURN_FALSE;
    }
    switch(type)
    {
    case SW_TABLE_INT:
        if (size == 1 || size == 2 || size == 4 || size == 8)
        {
            col.size = size;
        }
        else
        {
            col.size = 4;
        }
        break;
    case SW_TABLE_FLOAT:
        if (size == 4 || size == 8)
        {
            col.size = size;
        }
        else
        {
            col.size = 4;
        }
        break;
    default:
        col.size = size;
        type = SW_TABLE_STRING;
        break;
    }
    col.type = type;
    table->row_size += size;
    zend_hash_add(table->columns, name, len, &col, sizeof(col), NULL);
    RETURN_TRUE;
}

PHP_METHOD(swoole_table, create)
{
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    uint32_t row_num = table->size * (1 + SW_TABLE_CONFLICT_PROPORTION);
    void *memory = sw_shm_malloc((sizeof(sw_atomic_t) * table->size) + (table->row_size * row_num));
    if (memory == NULL)
    {
        RETURN_FALSE;
    }
    table->row_locks = memory;
    table->memory = memory + (sizeof(sw_atomic_t) * table->size);
    RETURN_TRUE;
}
