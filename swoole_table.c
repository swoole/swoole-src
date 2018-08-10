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

static zend_class_entry swoole_table_ce;
static zend_class_entry *swoole_table_class_entry_ptr;

static zend_class_entry swoole_table_row_ce;
static zend_class_entry *swoole_table_row_class_entry_ptr;

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_exist, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_offsetExists, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_offsetGet, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_offsetSet, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_table_offsetUnset, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
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
static PHP_METHOD(swoole_table, column);
static PHP_METHOD(swoole_table, create);
static PHP_METHOD(swoole_table, set);
static PHP_METHOD(swoole_table, get);
static PHP_METHOD(swoole_table, del);
static PHP_METHOD(swoole_table, exist);
static PHP_METHOD(swoole_table, incr);
static PHP_METHOD(swoole_table, decr);
static PHP_METHOD(swoole_table, count);
static PHP_METHOD(swoole_table, destroy);
static PHP_METHOD(swoole_table, getMemorySize);
static PHP_METHOD(swoole_table, offsetExists);
static PHP_METHOD(swoole_table, offsetGet);
static PHP_METHOD(swoole_table, offsetSet);
static PHP_METHOD(swoole_table, offsetUnset);

#ifdef HAVE_PCRE
static PHP_METHOD(swoole_table, rewind);
static PHP_METHOD(swoole_table, next);
static PHP_METHOD(swoole_table, current);
static PHP_METHOD(swoole_table, key);
static PHP_METHOD(swoole_table, valid);
#endif

static PHP_METHOD(swoole_table_row, offsetExists);
static PHP_METHOD(swoole_table_row, offsetGet);
static PHP_METHOD(swoole_table_row, offsetSet);
static PHP_METHOD(swoole_table_row, offsetUnset);
static PHP_METHOD(swoole_table_row, __destruct);

static const zend_function_entry swoole_table_methods[] =
{
    PHP_ME(swoole_table, __construct, arginfo_swoole_table_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_table, column,      arginfo_swoole_table_column, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, create,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, destroy,     arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, set,         arginfo_swoole_table_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, get,         arginfo_swoole_table_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, count,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, del,         arginfo_swoole_table_del, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, exist,       arginfo_swoole_table_exist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, incr,        arginfo_swoole_table_incr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, decr,        arginfo_swoole_table_decr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, getMemorySize,    arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetExists,     arginfo_swoole_table_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetGet,        arginfo_swoole_table_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetSet,        arginfo_swoole_table_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetUnset,      arginfo_swoole_table_offsetUnset, ZEND_ACC_PUBLIC)
#ifdef HAVE_PCRE
    PHP_ME(swoole_table, rewind,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, next,        arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, current,     arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, key,         arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, valid,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

static const zend_function_entry swoole_table_row_methods[] =
{
    PHP_ME(swoole_table_row, offsetExists,     arginfo_swoole_table_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetGet,        arginfo_swoole_table_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetSet,        arginfo_swoole_table_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetUnset,      arginfo_swoole_table_offsetUnset, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, __destruct,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

static inline void php_swoole_table_row2array(swTable *table, swTableRow *row, zval *return_value)
{
    array_init(return_value);

    swTableColumn *col = NULL;
    swTable_string_length_t vlen = 0;
    double dval = 0;
    int64_t lval = 0;
    char *k;

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
            sw_add_assoc_stringl_ex(return_value, col->name->str, col->name->length + 1, row->data + col->index + sizeof(swTable_string_length_t), vlen, 1);
        }
        else if (col->type == SW_TABLE_FLOAT)
        {
            memcpy(&dval, row->data + col->index, sizeof(dval));
            sw_add_assoc_double_ex(return_value, col->name->str, col->name->length + 1, dval);
        }
        else
        {
            switch (col->type)
            {
            case SW_TABLE_INT8:
                memcpy(&lval, row->data + col->index, 1);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int8_t) lval);
                break;
            case SW_TABLE_INT16:
                memcpy(&lval, row->data + col->index, 2);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int16_t) lval);
                break;
            case SW_TABLE_INT32:
                memcpy(&lval, row->data + col->index, 4);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, (int32_t) lval);
                break;
            default:
                memcpy(&lval, row->data + col->index, 8);
                sw_add_assoc_long_ex(return_value, col->name->str, col->name->length + 1, lval);
                break;
            }
        }
    }
}

static inline void php_swoole_table_get_field_value(swTable *table, swTableRow *row, zval *return_value, char *field, uint16_t field_len)
{
    swTable_string_length_t vlen = 0;
    double dval = 0;
    int64_t lval = 0;

    swTableColumn *col = swHashMap_find(table->columns, field, field_len);
    if (!col)
    {
        ZVAL_BOOL(return_value, 0);
        return;
    }
    if (col->type == SW_TABLE_STRING)
    {
        memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
        SW_ZVAL_STRINGL(return_value, row->data + col->index + sizeof(swTable_string_length_t), vlen, 1);
    }
    else if (col->type == SW_TABLE_FLOAT)
    {
        memcpy(&dval, row->data + col->index, sizeof(dval));
        ZVAL_DOUBLE(return_value, dval);
    }
    else
    {
        switch (col->type)
        {
        case SW_TABLE_INT8:
            memcpy(&lval, row->data + col->index, 1);
            ZVAL_LONG(return_value, (int8_t) lval);
            break;
        case SW_TABLE_INT16:
            memcpy(&lval, row->data + col->index, 2);
            ZVAL_LONG(return_value, (int16_t) lval);
            break;
        case SW_TABLE_INT32:
            memcpy(&lval, row->data + col->index, 4);
            ZVAL_LONG(return_value, (int32_t) lval);
            break;
        default:
            memcpy(&lval, row->data + col->index, 8);
            ZVAL_LONG(return_value, lval);
            break;
        }
    }
}

void swoole_table_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_table_ce, "swoole_table", "Swoole\\Table", swoole_table_methods);
    swoole_table_class_entry_ptr = zend_register_internal_class(&swoole_table_ce TSRMLS_CC);
    swoole_table_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_table_class_entry_ptr->unserialize = zend_class_unserialize_deny;
    SWOOLE_CLASS_ALIAS(swoole_table, "Swoole\\Table");
    zend_class_implements(swoole_table_class_entry_ptr TSRMLS_CC, 1, zend_ce_arrayaccess);

#ifdef HAVE_PCRE
    zend_class_implements(swoole_table_class_entry_ptr TSRMLS_CC, 2, spl_ce_Iterator, spl_ce_Countable);
#endif

    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_INT")-1, SW_TABLE_INT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_STRING")-1, SW_TABLE_STRING TSRMLS_CC);
    zend_declare_class_constant_long(swoole_table_class_entry_ptr, SW_STRL("TYPE_FLOAT")-1, SW_TABLE_FLOAT TSRMLS_CC);

    SWOOLE_INIT_CLASS_ENTRY(swoole_table_row_ce, "swoole_table_row", "Swoole\\Table\\Row", swoole_table_row_methods);
    swoole_table_row_class_entry_ptr = zend_register_internal_class(&swoole_table_row_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_table_row, "Swoole\\Table\\Row");
    zend_class_implements(swoole_table_row_class_entry_ptr TSRMLS_CC, 1, zend_ce_arrayaccess);

    zend_declare_property_null(swoole_table_row_class_entry_ptr, ZEND_STRL("key"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_table_row_class_entry_ptr, ZEND_STRL("value"), ZEND_ACC_PUBLIC TSRMLS_CC);
}

void swoole_table_column_free(swTableColumn *col)
{
    swString_free(col->name);
}

PHP_METHOD(swoole_table, __construct)
{
    long table_size;
    double conflict_proportion = SW_TABLE_CONFLICT_PROPORTION;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|d", &table_size, &conflict_proportion) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swTable_new(table_size, conflict_proportion);
    if (table == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "global memory allocation failure.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), table);
}

PHP_METHOD(swoole_table, column)
{
    char *name;
    zend_size_t len;
    long type;
    long size = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|l", &name, &len, &type, &size) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (type == SW_TABLE_STRING && size < 1)
    {
        swoole_php_fatal_error(E_WARNING, "the length of string type values has to be more than zero.");
        RETURN_FALSE;
    }
    //default int32
    if (type == SW_TABLE_INT && size < 1)
    {
        size = 4;
    }
    swTable *table = swoole_get_object(getThis());
    if (table->memory)
    {
        swoole_php_fatal_error(E_WARNING, "can't add column after the creation of swoole table.");
        RETURN_FALSE;
    }
    swTableColumn_add(table, name, len, type, size);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, create)
{
    swTable *table = swoole_get_object(getThis());
    if (table->memory)
    {
        swoole_php_fatal_error(E_WARNING, "the swoole table has been created already.");
        RETURN_FALSE;
    }
    if (swTable_create(table) < 0)
    {
        swoole_php_fatal_error(E_ERROR, "unable to allocate memory.");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("size"), table->size TSRMLS_CC);
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("memorySize"), table->memory_size TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, destroy)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTable_free(table);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, set)
{
    zval *array;
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &keylen, &array) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTableRow *row = swTableRow_set(table, key, keylen, &_rowlock);
    if (!row)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_error(E_WARNING, "unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *col;
    zval *v;
    char *k;
    uint32_t klen;
    int ktype;
    HashTable *_ht = Z_ARRVAL_P(array);

    SW_HASHTABLE_FOREACH_START2(_ht, k, klen, ktype, v)
    {
        col = swTableColumn_get(table, k, klen);
        if (k == NULL || col == NULL)
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
    }
    (void) ktype;
    SW_HASHTABLE_FOREACH_END();
    swTableRow_unlock(_rowlock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, offsetSet)
{
    ZEND_MN(swoole_table_set)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_table, incr)
{
    char *key;
    zend_size_t key_len;
    char *col;
    zend_size_t col_len;
    zval* incrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &incrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock);
    if (!row)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *column;
    column = swTableColumn_get(table, col, col_len);
    if (column == NULL)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "column[%s] does not exist.", col);
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_STRING)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "can't execute 'incr' on a string type column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value = 0;
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
        RETVAL_DOUBLE(set_value);
    }
    else
    {
        int64_t set_value = 0;
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
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, decr)
{
    char *key;
    zend_size_t key_len;
    char *col;
    zend_size_t col_len;
    zval *decrby = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &key, &key_len, &col, &col_len, &decrby) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock);
    if (!row)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *column;
    column = swTableColumn_get(table, col, col_len);
    if (column == NULL)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "column[%s] does not exist.", col);
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_STRING)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_fatal_error(E_WARNING, "can't execute 'decr' on a string type column.");
        RETURN_FALSE;
    }
    else if (column->type == SW_TABLE_FLOAT)
    {
        double set_value = 0;
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
        RETVAL_DOUBLE(set_value);
    }
    else
    {
        int64_t set_value = 0;
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
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, get)
{
    char *key;
    zend_size_t keylen;

    char *field = NULL;
    zend_size_t field_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &keylen, &field, &field_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    if (!row)
    {
        RETVAL_FALSE;
    }
    else if (field && field_len > 0)
    {
        php_swoole_table_get_field_value(table, row, return_value, field, (uint16_t) field_len);
    }
    else
    {
        php_swoole_table_row2array(table, row, return_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, offsetGet)
{
    char *key;
    zend_size_t keylen;

    char *field = NULL;
    zend_size_t field_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &keylen, &field, &field_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "Must create table first.");
        RETURN_FALSE;
    }

    zval *value;
    SW_MAKE_STD_ZVAL(value);

    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    if (!row)
    {
        array_init(value);
    }
    else
    {
        php_swoole_table_row2array(table, row, value);
    }
    swTableRow_unlock(_rowlock);

    object_init_ex(return_value, swoole_table_row_class_entry_ptr);
    zend_update_property(swoole_table_row_class_entry_ptr, return_value, ZEND_STRL("value"), value TSRMLS_CC);
    zend_update_property_stringl(swoole_table_row_class_entry_ptr, return_value, ZEND_STRL("key"), key, keylen TSRMLS_CC);
    sw_zval_ptr_dtor(&value);
    swoole_set_object(return_value, table);
}

static PHP_METHOD(swoole_table, exist)
{
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    swTableRow *_rowlock = NULL;
    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    swTableRow_unlock(_rowlock);
    if (!row)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_table, offsetExists)
{
    ZEND_MN(swoole_table_exist)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_table, del)
{
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swTableRow_del(table, key, keylen));
}

static PHP_METHOD(swoole_table, offsetUnset)
{
    ZEND_MN(swoole_table_del)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
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
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }

    if (mode == COUNT_NORMAL)
    {
        RETURN_LONG(table->row_num);
    }
    else
    {
        RETURN_LONG(table->row_num * table->column_num);
    }
}

static PHP_METHOD(swoole_table, getMemorySize)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        RETURN_LONG(swTable_get_memory_size(table));
    }
    else
    {
        RETURN_LONG(table->memory_size);
    }
}

#ifdef HAVE_PCRE
static PHP_METHOD(swoole_table, rewind)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTable_iterator_rewind(table);
    swTable_iterator_forward(table);
}

static PHP_METHOD(swoole_table, current)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    swTableRow_lock(row);
    php_swoole_table_row2array(table, row, return_value);
    swTableRow_unlock(row);
}

static PHP_METHOD(swoole_table, key)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    swTableRow_lock(row);
    SW_RETVAL_STRING(row->key, 1);
    swTableRow_unlock(row);
}

static PHP_METHOD(swoole_table, next)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTable_iterator_forward(table);
}

static PHP_METHOD(swoole_table, valid)
{
    swTable *table = swoole_get_object(getThis());
    if (!table->memory)
    {
        swoole_php_fatal_error(E_ERROR, "the swoole table does not exist.");
        RETURN_FALSE;
    }
    swTableRow *row = swTable_iterator_current(table);
    RETURN_BOOL(row != NULL);
}
#endif

static PHP_METHOD(swoole_table_row, offsetExists)
{
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    zval *value = sw_zend_read_property(swoole_table_row_class_entry_ptr, getThis(), SW_STRL("value")-1, 0 TSRMLS_CC);
    RETURN_BOOL(zend_hash_str_exists(Z_ARRVAL_P(value), key, keylen) == SUCCESS);
}

static PHP_METHOD(swoole_table_row, offsetGet)
{
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    zval *value = sw_zend_read_property(swoole_table_row_class_entry_ptr, getThis(), SW_STRL("value")-1, 0 TSRMLS_CC);
    zval *zvalue;
    if (sw_zend_hash_find(Z_ARRVAL_P(value), key, keylen + 1, (void **) &zvalue) == FAILURE)
    {
        RETURN_FALSE;
    }
    RETURN_ZVAL(zvalue, 1, 0);
}

static PHP_METHOD(swoole_table_row, offsetSet)
{
    zval *value;
    char *key;
    zend_size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &key, &keylen, &value) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTable *table = swoole_get_object(getThis());
    if (table == NULL || table->memory == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Must create table first.");
        RETURN_FALSE;
    }

    zval *prop_key = sw_zend_read_property(swoole_table_row_class_entry_ptr, getThis(), SW_STRL("key")-1, 0 TSRMLS_CC);

    swTableRow *_rowlock = NULL;
    swTableRow *row = swTableRow_set(table, Z_STRVAL_P(prop_key), Z_STRLEN_P(prop_key), &_rowlock);
    if (!row)
    {
        swTableRow_unlock(_rowlock);
        swoole_php_error(E_WARNING, "Unable to allocate memory.");
        RETURN_FALSE;
    }

    swTableColumn *col;
    col = swTableColumn_get(table, key, keylen);
    if (col->type == SW_TABLE_STRING)
    {
        convert_to_string(value);
        swTableRow_set_value(row, col, Z_STRVAL_P(value), Z_STRLEN_P(value));
    }
    else if (col->type == SW_TABLE_FLOAT)
    {
        convert_to_double(value);
        swTableRow_set_value(row, col, &Z_DVAL_P(value), 0);
    }
    else
    {
        convert_to_long(value);
        swTableRow_set_value(row, col, &Z_LVAL_P(value), 0);
    }
    swTableRow_unlock(_rowlock);

    zval *prop_value = sw_zend_read_property(swoole_table_row_class_entry_ptr, getThis(), SW_STRL("value")-1, 0 TSRMLS_CC);
    sw_zend_hash_update(Z_ARRVAL_P(prop_value), key, keylen, value, sizeof(zval *), NULL);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table_row, offsetUnset)
{
    swoole_php_fatal_error(E_WARNING, "not supported.");
    RETURN_FALSE;
}

static PHP_METHOD(swoole_table_row, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swoole_set_object(getThis(), NULL);
}
