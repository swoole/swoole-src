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
#include "table.h"

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
    if (table)
    {
        swTable_free(table);
    }
}

void swoole_table_init(TSRMLS_D)
{
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_INT")-1, SW_TABLE_INT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_STRING")-1, SW_TABLE_STRING TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_FLOAT")-1, SW_TABLE_FLOAT TSRMLS_CC);

    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_GT")-1, SW_TABLE_FIND_GT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_LT")-1, SW_TABLE_FIND_LT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_EQ")-1, SW_TABLE_FIND_EQ TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_NEQ")-1, SW_TABLE_FIND_NEQ TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_LEFTLIKE")-1, SW_TABLE_FIND_LEFTLIKE TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_RIGHTLIKE")-1, SW_TABLE_FIND_RIGHTLIKE TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("FIND_LIKE")-1, SW_TABLE_FIND_LIKE TSRMLS_CC);
}

void swoole_table_column_free(swTableColumn *col)
{
    swString_free(col->name);
}

PHP_METHOD(swoole_table, __construct)
{
    long table_size;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &table_size) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (table_size < 1)
    {
        RETURN_FALSE;
    }
    swTable *table = swTable_new(table_size);
    zval *zres;
    MAKE_STD_ZVAL(zres);

    ZEND_REGISTER_RESOURCE(zres, table, le_swoole_table);
    zend_update_property(swoole_table_class_entry_ptr, getThis(), ZEND_STRL("_table"), zres TSRMLS_CC);

    zval_ptr_dtor(&zres);
}

PHP_METHOD(swoole_table, column)
{
    char *name;
    int len;
    long type;
    long size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &name, &len, &type, &size) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (type == SW_TABLE_STRING && size < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string length must be more than 0.");
        RETURN_FALSE;
    }
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    swTableColumn_add(table, name, len, type, size);
    RETURN_TRUE;
}

PHP_METHOD(swoole_table, create)
{
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    swTable_create(table);
    RETURN_TRUE;
}

PHP_METHOD(swoole_table, add)
{
    zval *array;
    char *key;
    int keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &keylen, &array) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    swTableRow *row = swTableRow_add(table, key, keylen);
    swTableColumn *col;
    zval *v;
    char *k;
    int klen;
    Bucket *p = Z_ARRVAL_P(array)->pListHead;

    do
    {
        v = p->pDataPtr;
        k = (char *) p->arKey;
        klen = p->nKeyLength - 1;
        p = p->pListNext;

        col = swTableColumn_get(table, k, klen);
        if (col == NULL)
        {
            continue;
        }
        else if (col->type == SW_TABLE_STRING)
        {
            convert_to_string(v);
            swTableRow_set(row, col, Z_STRVAL_P(v), Z_STRLEN_P(v));
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            convert_to_double(v);
            swTableRow_set(row, col, &Z_DVAL_P(v), 0);
        }
        else
        {
            convert_to_long(v);
            swTableRow_set(row, col, (void *) Z_LVAL_P(v), 0);
        }
    } while (p);
}

PHP_METHOD(swoole_table, get)
{
    char *key;
    int keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    array_init(return_value);

    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    swTableRow *row = swTableRow_get(table, key, keylen);
    swTableColumn *col = NULL;

    void *tmp = NULL;
    char *k;

    while(1)
    {
        tmp = swHashMap_foreach(&table->columns, &k, (void **) &col, tmp);
        if (col->type == SW_TABLE_STRING)
        {
            uint16_t vlen = *(int16_t *) (row->data + col->index);
            add_assoc_stringl_ex(return_value, col->name->str, col->name->length + 1, row->data + col->index + 2, vlen, 1);
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            double dval = *(double *) (row->data + col->index);
            add_assoc_double_ex(return_value, col->name->str, col->name->length + 1, dval);
        }
        else
        {
            int64_t lval;
            switch (col->type)
            {
            case SW_TABLE_INT8:
                lval = *(int8_t *) (row->data + col->index);
                break;
            case SW_TABLE_INT16:
                lval = *(int16_t *) (row->data + col->index);
                break;
            case SW_TABLE_INT32:
                lval = *(int32_t *) (row->data + col->index);
                break;
            default:
                lval = *(int64_t *) (row->data + col->index);
                break;
            }
            add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, lval);
        }
        if (tmp == NULL)
        {
            break;
        }
    }
}

PHP_METHOD(swoole_table, lock)
{
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    SW_LOCK_CHECK_RETURN(table->lock.lock(&table->lock));
}

PHP_METHOD(swoole_table, unlock)
{
    swTable *table = php_swoole_table_get(getThis() TSRMLS_CC);
    SW_LOCK_CHECK_RETURN(table->lock.unlock(&table->lock));
}
