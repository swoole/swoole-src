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
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/


#include "php_swoole.h"

#ifdef HAVE_PCRE
#include <ext/spl/spl_iterators.h>
#endif

#include "include/table.h"

zend_class_entry swoole_table_ce;
zend_class_entry *swoole_table_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, table_size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_column, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_set, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_get, 0, 0, 1)
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

static PHP_METHOD(swoole_table, __construct);
static PHP_METHOD(swoole_table, __destruct);
static PHP_METHOD(swoole_table, column);
static PHP_METHOD(swoole_table, create);
static PHP_METHOD(swoole_table, set);
static PHP_METHOD(swoole_table, get);
static PHP_METHOD(swoole_table, del);
static PHP_METHOD(swoole_table, incr);
static PHP_METHOD(swoole_table, decr);
static PHP_METHOD(swoole_table, lock);
static PHP_METHOD(swoole_table, unlock);
static PHP_METHOD(swoole_table, count);

#ifdef HAVE_PCRE
static PHP_METHOD(swoole_table, rewind);
static PHP_METHOD(swoole_table, next);
static PHP_METHOD(swoole_table, current);
static PHP_METHOD(swoole_table, key);
static PHP_METHOD(swoole_table, valid);
#endif

static const zend_function_entry swoole_table_methods[] =
{
    PHP_ME(swoole_table, __construct, arginfo_swoole_table_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_table, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_table, column,      arginfo_swoole_table_column, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, create,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, set,         arginfo_swoole_table_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, get,         arginfo_swoole_table_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, count,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, del,         arginfo_swoole_table_del, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, incr,        arginfo_swoole_table_incr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, decr,        arginfo_swoole_table_decr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, lock,        arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, unlock,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
#ifdef HAVE_PCRE
    PHP_ME(swoole_table, rewind,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, next,        arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, current,     arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, key,         arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, valid,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

static void php_swoole_table_row2array(swTable *table, swTableRow *row, zval *return_value)
{
    array_init(return_value);

    swTableColumn *col = NULL;
    swTable_string_length_t vlen = 0;
    double dval = 0;
    int64_t lval = 0;
    char *k;

    sw_spinlock(&row->lock);
    while(1)
    {
        col = swHashMap_each(table->columns, &k);
        if (col == NULL)
        {
            break;
        }
        if (col->type == SW_TABLE_STRING)
        {
            memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
            add_assoc_stringl_ex(return_value, col->name->str, col->name->length + 1, row->data + col->index + sizeof(swTable_string_length_t), vlen, 1);
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            memcpy(&dval, row->data + col->index, sizeof(dval));
            add_assoc_double_ex(return_value, col->name->str, col->name->length + 1, dval);
        }
        else
        {
            switch (col->type)
            {
            case SW_TABLE_INT8:
                memcpy(&lval, row->data + col->index, 1);
                break;
            case SW_TABLE_INT16:
                memcpy(&lval, row->data + col->index, 2);
                break;
            case SW_TABLE_INT32:
                memcpy(&lval, row->data + col->index, 4);
                break;
            default:
                memcpy(&lval, row->data + col->index, 8);
                break;
            }
            add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, lval);
        }
    }
    sw_spinlock_release(&row->lock);
}

void swoole_table_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_table_ce, "swoole_table", swoole_table_methods);
    swoole_table_class_entry_ptr = zend_register_internal_class(&swoole_table_ce TSRMLS_CC);

#ifdef HAVE_PCRE
    zend_class_implements(swoole_table_class_entry_ptr TSRMLS_CC, 2, spl_ce_Iterator, spl_ce_Countable);
#endif

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
    swoole_set_object(getThis(), table);
}

PHP_METHOD(swoole_table, __destruct)
{
    swTable *table = swoole_get_object(getThis());
    if (table)
    {
        swTable_free(table);
    }
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
    swTable *table = swoole_get_object(getThis());
    swTableColumn_add(table, name, len, type, size);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, create)
{
    swTable *table = swoole_get_object(getThis());
    swTable_create(table);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, set)
{
    zval *array;
    char *key;
    int keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &keylen, &array) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTableRow_set(table, key, keylen);
    if (!row)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *col;
    zval *v;
    char *k;
    int klen;
    Bucket *p = Z_ARRVAL_P(array)->pListHead;

    sw_atomic_t *lock = &row->lock;
    sw_spinlock(lock);
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
            swTableRow_set_value(row, col, Z_STRVAL_P(v), Z_STRLEN_P(v));
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            convert_to_double(v);
            swTableRow_set_value(row, col, &Z_DVAL_P(v), 0);
        }
        else
        {
            convert_to_long(v);
            swTableRow_set_value(row, col, &Z_LVAL_P(v), 0);
        }
    } while (p);
    sw_spinlock_release(lock);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, incr)
{
    char *key;
    int key_len;
    char *col;
    int col_len;
    zval* incrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &incrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTableRow_set(table, key, key_len);
    if (!row)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *column;
    sw_atomic_t *lock = &row->lock;
    sw_spinlock(lock);

    column = swTableColumn_get(table, col, col_len);
    if (column == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "column[%s] not exist.", col);
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use incr with string column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (incrby)
        {
            convert_to_double(incrby);
            set_value += Z_DVAL_P(incrby);
        }
        else
        {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
    }
    else
    {
        uint64_t set_value;
        memcpy(&set_value, row->data + column->index, column->size);
        if (incrby)
        {
            convert_to_long(incrby);
            set_value += Z_LVAL_P(incrby);
        }
        else
        {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
    }
    sw_spinlock_release(lock);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, decr)
{
    char *key;
    int key_len;
    char *col;
    int col_len;
    zval *decrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &decrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTableRow_set(table, key, key_len);
    if (!row)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *column;
    sw_atomic_t *lock = &row->lock;
    sw_spinlock(lock);

    column = swTableColumn_get(table, col, col_len);
    if (column == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "column[%s] not exist.", col);
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use incr with string column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (decrby)
        {
            convert_to_double(decrby);
            set_value -= Z_DVAL_P(decrby);
        }
        else
        {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
    }
    else
    {
        uint64_t set_value;
        memcpy(&set_value, row->data + column->index, column->size);
        if (decrby)
        {
            convert_to_long(decrby);
            set_value -= Z_LVAL_P(decrby);
        }
        else
        {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
    }
    sw_spinlock_release(lock);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, get)
{
    char *key;
    int keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }
    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTableRow_get(table, key, keylen);
    if (!row)
    {
        RETURN_FALSE;
    }
    php_swoole_table_row2array(table, row, return_value);
}

static PHP_METHOD(swoole_table, del)
{
    char *key;
    int keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    SW_CHECK_RETURN(swTableRow_del(table, key, keylen));
}

static PHP_METHOD(swoole_table, lock)
{
    swTable *table = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(table->lock.lock(&table->lock));
}

static PHP_METHOD(swoole_table, unlock)
{
    swTable *table = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(table->lock.unlock(&table->lock));
}

static PHP_METHOD(swoole_table, count)
{
    #define COUNT_NORMAL            0
    #define COUNT_RECURSIVE         1

    long mode = COUNT_NORMAL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &mode) == FAILURE)
    {
        return;
    }

    swTable *table = swoole_get_object(getThis());

    if (mode == COUNT_NORMAL)
    {
        RETURN_LONG(table->row_num);
    }
    else
    {
        RETURN_LONG(table->row_num * table->column_num);
    }
}

#ifdef HAVE_PCRE

static PHP_METHOD(swoole_table, rewind)
{
    if (zend_parse_parameters_none() == FAILURE)
    {
        return;
    }

    swTable *table = swoole_get_object(getThis());
    swTable_iterator_rewind(table);
}

static PHP_METHOD(swoole_table, current)
{
    if (zend_parse_parameters_none() == FAILURE)
    {
        return;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTable_iterator_current(table);
    php_swoole_table_row2array(table, row, return_value);
}

static PHP_METHOD(swoole_table, key)
{
    if (zend_parse_parameters_none() == FAILURE)
    {
        return;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTable_iterator_current(table);
    RETURN_LONG(row->crc32);
}

static PHP_METHOD(swoole_table, next)
{
    if (zend_parse_parameters_none() == FAILURE)
    {
        return;
    }
    swTable *table = swoole_get_object(getThis());
    swTable_iterator_forward(table);
}

static PHP_METHOD(swoole_table, valid)
{
    if (zend_parse_parameters_none() == FAILURE)
    {
        return;
    }

    swTable *table = swoole_get_object(getThis());
    swTableRow *row = swTable_iterator_current(table);
    RETURN_BOOL(row != NULL);
}

#endif
