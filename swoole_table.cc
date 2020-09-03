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

#include "php_swoole_cxx.h"

#include "swoole_table.h"

static inline void php_swoole_table_row2array(swTable *table, swTableRow *row, zval *return_value) {
    array_init(return_value);

    swTable_string_length_t vlen = 0;
    double dval = 0;
    long lval = 0;

    for (auto i = table->column_list->begin(); i != table->column_list->end(); i++) {
        swTableColumn *col = *i;
        if (col->type == SW_TABLE_STRING) {
            memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
            add_assoc_stringl_ex(return_value,
                                 col->name.c_str(),
                                 col->name.length(),
                                 row->data + col->index + sizeof(swTable_string_length_t),
                                 vlen);
        } else if (col->type == SW_TABLE_FLOAT) {
            memcpy(&dval, row->data + col->index, sizeof(dval));
            add_assoc_double_ex(return_value, col->name.c_str(), col->name.length(), dval);
        } else if (col->type == SW_TABLE_INT) {
            memcpy(&lval, row->data + col->index, sizeof(lval));
            add_assoc_long_ex(return_value, col->name.c_str(), col->name.length(), lval);
        } else {
            abort();
        }
    }
}

static inline void php_swoole_table_get_field_value(
    swTable *table, swTableRow *row, zval *return_value, char *field, uint16_t field_len) {
    swTable_string_length_t vlen = 0;
    double dval = 0;
    long lval = 0;

    swTableColumn *col = swTableColumn_get(table, std::string(field, field_len));
    if (!col) {
        ZVAL_FALSE(return_value);
        return;
    }
    if (col->type == SW_TABLE_STRING) {
        memcpy(&vlen, row->data + col->index, sizeof(swTable_string_length_t));
        ZVAL_STRINGL(return_value, row->data + col->index + sizeof(swTable_string_length_t), vlen);
    } else if (col->type == SW_TABLE_FLOAT) {
        memcpy(&dval, row->data + col->index, sizeof(dval));
        ZVAL_DOUBLE(return_value, dval);
    } else if (col->type == SW_TABLE_INT) {
        memcpy(&lval, row->data + col->index, sizeof(lval));
        ZVAL_LONG(return_value, lval);
    } else {
        abort();
    }
}

static zend_class_entry *swoole_table_ce;
static zend_object_handlers swoole_table_handlers;

static zend_class_entry *swoole_table_row_ce;
static zend_object_handlers swoole_table_row_handlers;

struct TableObject {
    swTable *ptr;
    zend_object std;
};

static inline TableObject *php_swoole_table_fetch_object(zend_object *obj) {
    return (TableObject *) ((char *) obj - swoole_table_handlers.offset);
}

static inline swTable *php_swoole_table_get_ptr(zval *zobject) {
    return php_swoole_table_fetch_object(Z_OBJ_P(zobject))->ptr;
}

static inline swTable *php_swoole_table_get_and_check_ptr(zval *zobject) {
    swTable *table = php_swoole_table_get_ptr(zobject);
    if (!table) {
        php_swoole_fatal_error(E_ERROR, "you must call Table constructor first");
    }
    return table;
}

static inline swTable *php_swoole_table_get_and_check_ptr2(zval *zobject) {
    swTable *table = php_swoole_table_get_and_check_ptr(zobject);
    if (!table->memory) {
        php_swoole_fatal_error(E_ERROR, "the swoole table does not exist");
    }
    return table;
}

static void inline php_swoole_table_set_ptr(zval *zobject, swTable *ptr) {
    php_swoole_table_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static inline void php_swoole_table_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static inline zend_object *php_swoole_table_create_object(zend_class_entry *ce) {
    TableObject *table = (TableObject *) zend_object_alloc(sizeof(TableObject), ce);
    zend_object_std_init(&table->std, ce);
    object_properties_init(&table->std, ce);
    table->std.handlers = &swoole_table_handlers;
    return &table->std;
}

typedef struct {
    swTable *ptr;
    zend_object std;
} table_row_t;

static inline table_row_t *php_swoole_table_row_fetch_object(zend_object *obj) {
    return (table_row_t *) ((char *) obj - swoole_table_row_handlers.offset);
}

static inline swTable *php_swoole_table_row_get_ptr(zval *zobject) {
    return php_swoole_table_row_fetch_object(Z_OBJ_P(zobject))->ptr;
}

static inline swTable *php_swoole_table_row_get_and_check_ptr(zval *zobject) {
    swTable *table_row = php_swoole_table_row_get_ptr(zobject);
    if (!table_row) {
        php_swoole_fatal_error(E_ERROR, "you can only get Table\\Row from Table");
    }
    return table_row;
}

static inline void php_swoole_table_row_set_ptr(zval *zobject, swTable *ptr) {
    php_swoole_table_row_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static inline void php_swoole_table_row_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static inline zend_object *php_swoole_table_row_create_object(zend_class_entry *ce) {
    table_row_t *table_row = (table_row_t *) zend_object_alloc(sizeof(table_row_t), ce);
    zend_object_std_init(&table_row->std, ce);
    object_properties_init(&table_row->std, ce);
    table_row->std.handlers = &swoole_table_row_handlers;
    return &table_row->std;
}

// clang-format off
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
// clang-format on

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_table, __construct);
static PHP_METHOD(swoole_table, column);
static PHP_METHOD(swoole_table, create);
static PHP_METHOD(swoole_table, set);
static PHP_METHOD(swoole_table, get);
static PHP_METHOD(swoole_table, del);
static PHP_METHOD(swoole_table, exists);
static PHP_METHOD(swoole_table, incr);
static PHP_METHOD(swoole_table, decr);
static PHP_METHOD(swoole_table, count);
static PHP_METHOD(swoole_table, destroy);
static PHP_METHOD(swoole_table, getMemorySize);
static PHP_METHOD(swoole_table, offsetExists);
static PHP_METHOD(swoole_table, offsetGet);
static PHP_METHOD(swoole_table, offsetSet);
static PHP_METHOD(swoole_table, offsetUnset);

static PHP_METHOD(swoole_table, rewind);
static PHP_METHOD(swoole_table, next);
static PHP_METHOD(swoole_table, current);
static PHP_METHOD(swoole_table, key);
static PHP_METHOD(swoole_table, valid);

static PHP_METHOD(swoole_table_row, offsetExists);
static PHP_METHOD(swoole_table_row, offsetGet);
static PHP_METHOD(swoole_table_row, offsetSet);
static PHP_METHOD(swoole_table_row, offsetUnset);
static PHP_METHOD(swoole_table_row, __destruct);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_table_methods[] =
{
    PHP_ME(swoole_table, __construct, arginfo_swoole_table_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, column,      arginfo_swoole_table_column, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, create,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, destroy,     arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, set,         arginfo_swoole_table_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, get,         arginfo_swoole_table_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, count,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, del,         arginfo_swoole_table_del, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, exists,      arginfo_swoole_table_exists, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_table, exist, exists, arginfo_swoole_table_exists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, incr,        arginfo_swoole_table_incr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, decr,        arginfo_swoole_table_decr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, getMemorySize,    arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetExists,     arginfo_swoole_table_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetGet,        arginfo_swoole_table_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetSet,        arginfo_swoole_table_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, offsetUnset,      arginfo_swoole_table_offsetUnset, ZEND_ACC_PUBLIC)

    PHP_ME(swoole_table, rewind,      arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, next,        arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, current,     arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, key,         arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, valid,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_table_row_methods[] =
{
    PHP_ME(swoole_table_row, offsetExists,     arginfo_swoole_table_offsetExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetGet,        arginfo_swoole_table_offsetGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetSet,        arginfo_swoole_table_offsetSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, offsetUnset,      arginfo_swoole_table_offsetUnset, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table_row, __destruct,       arginfo_swoole_table_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_table_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_table, "Swoole\\Table", "swoole_table", nullptr, swoole_table_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_table, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_table, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_table, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_table, php_swoole_table_create_object, php_swoole_table_free_object, TableObject, std);
    zend_class_implements(swoole_table_ce, 2, zend_ce_iterator, zend_ce_arrayaccess);
#ifdef SW_HAVE_COUNTABLE
    zend_class_implements(swoole_table_ce, 1, zend_ce_countable);
#endif

    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_INT"), SW_TABLE_INT);
    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_STRING"), SW_TABLE_STRING);
    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_FLOAT"), SW_TABLE_FLOAT);

    SW_INIT_CLASS_ENTRY(swoole_table_row, "Swoole\\Table\\Row", "swoole_table_row", nullptr, swoole_table_row_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_table_row, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_table_row, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_table_row, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_table_row, php_swoole_table_row_create_object, php_swoole_table_row_free_object, table_row_t, std);
    zend_class_implements(swoole_table_row_ce, 1, zend_ce_arrayaccess);

    zend_declare_property_null(swoole_table_row_ce, ZEND_STRL("key"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_table_row_ce, ZEND_STRL("value"), ZEND_ACC_PUBLIC);
}

PHP_METHOD(swoole_table, __construct) {
    swTable *table = php_swoole_table_get_ptr(ZEND_THIS);
    if (table) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    zend_long table_size;
    double conflict_proportion = SW_TABLE_CONFLICT_PROPORTION;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_LONG(table_size)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(conflict_proportion)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    table = swTable_new(table_size, conflict_proportion);
    if (table == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }
    table->hash_func = [](const char *key, size_t len) -> uint64_t {
        return zend_string_hash_val(sw_get_zend_string((void *) key));
    };
    php_swoole_table_set_ptr(ZEND_THIS, table);
}

PHP_METHOD(swoole_table, column) {
    swTable *table = php_swoole_table_get_and_check_ptr(ZEND_THIS);
    char *name;
    size_t len;
    long type;
    long size = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl|l", &name, &len, &type, &size) == FAILURE) {
        RETURN_FALSE;
    }
    if (type == SW_TABLE_STRING) {
        if (size < 1) {
            php_swoole_fatal_error(E_WARNING, "the length of string type values has to be more than zero");
            RETURN_FALSE;
        }
        size = SW_MEM_ALIGNED_SIZE(size);
    }
    if (table->memory) {
        php_swoole_fatal_error(E_WARNING, "unable to add column after table has been created");
        RETURN_FALSE;
    }
    RETURN_BOOL(swTableColumn_add(table, std::string(name, len), (enum swTableColumn_type) type, size));
}

static PHP_METHOD(swoole_table, create) {
    swTable *table = php_swoole_table_get_and_check_ptr(ZEND_THIS);

    if (swTable_create(table) < 0) {
        php_swoole_fatal_error(E_ERROR, "unable to allocate memory");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_table_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("size"), table->size);
    zend_update_property_long(swoole_table_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("memorySize"), table->memory_size);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, destroy) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);

    swTable_free(table);
    php_swoole_table_set_ptr(ZEND_THIS, nullptr);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, set) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    zval *array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!table->memory) {
        php_swoole_fatal_error(E_ERROR, "the table object does not exist");
        RETURN_FALSE;
    }

    if (keylen >= SW_TABLE_KEY_SIZE) {
        php_swoole_fatal_error(E_WARNING, "key[%s] is too long", key);
    }

    int out_flags;
    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_set(table, key, keylen, &_rowlock, &out_flags);
    if (!row) {
        swTableRow_unlock(_rowlock);
        php_swoole_error(E_WARNING, "failed to set('%*s'), unable to allocate memory", (int) keylen, key);
        RETURN_FALSE;
    }

    HashTable *ht = Z_ARRVAL_P(array);

    if (out_flags & SW_TABLE_FLAG_NEW_ROW) {
        for (auto i = table->column_list->begin(); i != table->column_list->end(); i++) {
            swTableColumn *col = *i;
            zval *zv = zend_hash_str_find(ht, col->name.c_str(), col->name.length());
            if (zv == nullptr || ZVAL_IS_NULL(zv)) {
                if (col->type == SW_TABLE_STRING) {
                     swTableRow_set_value(row, col, nullptr, 0);
                 } else if (col->type == SW_TABLE_FLOAT) {
                     double _value = 0;
                     swTableRow_set_value(row, col, &_value, 0);
                 } else {
                     long _value = zval_get_long(zv);
                     swTableRow_set_value(row, col, &_value, 0);
                 }
            } else {
                if (col->type == SW_TABLE_STRING) {
                    zend_string *str = zval_get_string(zv);
                    swTableRow_set_value(row, col, ZSTR_VAL(str), ZSTR_LEN(str));
                    zend_string_release(str);
                } else if (col->type == SW_TABLE_FLOAT) {
                    double _value = zval_get_double(zv);
                    swTableRow_set_value(row, col, &_value, 0);
                } else {
                    long _value = zval_get_long(zv);
                    swTableRow_set_value(row, col, &_value, 0);
                }
            }
        }
    } else {
        const char *k;
        uint32_t klen;
        int ktype;
        zval *zv;
        SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, zv) {
            swTableColumn *col = swTableColumn_get(table, std::string(k, klen));
            if (k == nullptr || col == nullptr) {
                continue;
            } else if (col->type == SW_TABLE_STRING) {
                zend_string *str = zval_get_string(zv);
                swTableRow_set_value(row, col, ZSTR_VAL(str), ZSTR_LEN(str));
                zend_string_release(str);
            } else if (col->type == SW_TABLE_FLOAT) {
                double _value = zval_get_double(zv);
                swTableRow_set_value(row, col, &_value, 0);
            } else {
                long _value = zval_get_long(zv);
                swTableRow_set_value(row, col, &_value, 0);
            }
        }
        (void) ktype;
        SW_HASHTABLE_FOREACH_END();
    }
    swTableRow_unlock(_rowlock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, offsetSet) {
    ZEND_MN(swoole_table_set)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_table, incr) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t key_len;
    char *col;
    size_t col_len;
    zval *incrby = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &key, &key_len, &col, &col_len, &incrby) == FAILURE) {
        RETURN_FALSE;
    }

    int out_flags;
    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock, &out_flags);
    if (!row) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "unable to allocate memory");
        RETURN_FALSE;
    }

    swTableColumn *column = swTableColumn_get(table, std::string(col, col_len));
    if (column == nullptr) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "column[%s] does not exist", col);
        RETURN_FALSE;
    } else if (column->type == SW_TABLE_STRING) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "can't execute 'incr' on a string type column");
        RETURN_FALSE;
    } else if (column->type == SW_TABLE_FLOAT) {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (incrby) {
            set_value += zval_get_double(incrby);
        } else {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    } else {
        long set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (incrby) {
            set_value += zval_get_long(incrby);
        } else {
            set_value += 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, decr) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t key_len;
    char *col;
    size_t col_len;
    zval *decrby = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &key, &key_len, &col, &col_len, &decrby) == FAILURE) {
        RETURN_FALSE;
    }

    int out_flags;
    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_set(table, key, key_len, &_rowlock, &out_flags);
    if (!row) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "unable to allocate memory");
        RETURN_FALSE;
    }

    swTableColumn *column = swTableColumn_get(table, std::string(col, col_len));
    if (column == nullptr) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "column[%s] does not exist", col);
        RETURN_FALSE;
    } else if (column->type == SW_TABLE_STRING) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "can't execute 'decr' on a string type column");
        RETURN_FALSE;
    } else if (column->type == SW_TABLE_FLOAT) {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (decrby) {
            set_value -= zval_get_double(decrby);
        } else {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    } else {
        long set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        if (decrby) {
            set_value -= zval_get_long(decrby);
        } else {
            set_value -= 1;
        }
        swTableRow_set_value(row, column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, get) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t keylen;
    char *field = nullptr;
    size_t field_len = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(field, field_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    if (!row) {
        RETVAL_FALSE;
    } else if (field && field_len > 0) {
        php_swoole_table_get_field_value(table, row, return_value, field, (uint16_t) field_len);
    } else {
        php_swoole_table_row2array(table, row, return_value);
    }
    swTableRow_unlock(_rowlock);
}

static PHP_METHOD(swoole_table, offsetGet) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t keylen;
    char *field = nullptr;
    size_t field_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|s", &key, &keylen, &field, &field_len) == FAILURE) {
        RETURN_FALSE;
    }

    zval value;
    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    if (!row) {
        array_init(&value);
    } else {
        php_swoole_table_row2array(table, row, &value);
    }
    swTableRow_unlock(_rowlock);

    object_init_ex(return_value, swoole_table_row_ce);
    zend_update_property(swoole_table_row_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("value"), &value);
    zend_update_property_stringl(swoole_table_row_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("key"), key, keylen);
    zval_ptr_dtor(&value);
    php_swoole_table_row_set_ptr(return_value, table);
}

static PHP_METHOD(swoole_table, exists) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE) {
        RETURN_FALSE;
    }

    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_get(table, key, keylen, &_rowlock);
    swTableRow_unlock(_rowlock);
    if (!row) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_table, offsetExists) {
    ZEND_MN(swoole_table_exists)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_table, del) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_STRING(key, keylen)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(swTableRow_del(table, key, keylen));
}

static PHP_METHOD(swoole_table, offsetUnset) {
    ZEND_MN(swoole_table_del)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_table, count) {
#define COUNT_NORMAL 0
#define COUNT_RECURSIVE 1

    swTable *table = php_swoole_table_get_ptr(ZEND_THIS);
    if (!table) {
        RETURN_LONG(0);
    }

    zend_long mode = COUNT_NORMAL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &mode) == FAILURE) {
        RETURN_FALSE;
    }

    if (mode == COUNT_NORMAL) {
        RETURN_LONG(table->row_num);
    } else {
        RETURN_LONG(table->row_num * table->column_list->size());
    }
}

static PHP_METHOD(swoole_table, getMemorySize) {
    swTable *table = php_swoole_table_get_ptr(ZEND_THIS);

    if (!table) {
        RETURN_LONG(0);
    } else if (!table->memory) {
        RETURN_LONG(swTable_get_memory_size(table));
    } else {
        RETURN_LONG(table->memory_size);
    }
}

static PHP_METHOD(swoole_table, rewind) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    swTable_iterator_rewind(table);
    swTable_iterator_forward(table);
}

static PHP_METHOD(swoole_table, current) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    swTableRow *row = swTable_iterator_current(table);
    if (row) {
        swTableRow_lock(row);
        php_swoole_table_row2array(table, row, return_value);
        swTableRow_unlock(row);
    } else {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_table, key) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    swTableRow *row = swTable_iterator_current(table);
    if (row) {
        swTableRow_lock(row);
        RETVAL_STRING(row->key);
        swTableRow_unlock(row);
    } else {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_table, next) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    swTable_iterator_forward(table);
}

static PHP_METHOD(swoole_table, valid) {
    swTable *table = php_swoole_table_get_and_check_ptr2(ZEND_THIS);
    swTableRow *row = swTable_iterator_current(table);
    RETURN_BOOL(row != nullptr);
}

static PHP_METHOD(swoole_table_row, offsetExists) {
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE) {
        RETURN_FALSE;
    }

    zval *zprop_value = sw_zend_read_property_ex(swoole_table_row_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_VALUE), 0);
    RETURN_BOOL(zend_hash_str_exists(Z_ARRVAL_P(zprop_value), key, keylen));
}

static PHP_METHOD(swoole_table_row, offsetGet) {
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE) {
        RETURN_FALSE;
    }

    zval *zprop_value = sw_zend_read_property_ex(swoole_table_row_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_VALUE), 0);
    zval *retval = nullptr;
    if (!(retval = zend_hash_str_find(Z_ARRVAL_P(zprop_value), key, keylen))) {
        RETURN_FALSE;
    }
    RETURN_ZVAL(retval, 1, 0);
}

static PHP_METHOD(swoole_table_row, offsetSet) {
    swTable *table = php_swoole_table_row_get_and_check_ptr(ZEND_THIS);
    zval *value;
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &key, &keylen, &value) == FAILURE) {
        RETURN_FALSE;
    }

    zval *zprop_key = sw_zend_read_property_ex(swoole_table_row_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_KEY), 0);

    int out_flags;
    swTableRow *_rowlock = nullptr;
    swTableRow *row = swTableRow_set(table, Z_STRVAL_P(zprop_key), Z_STRLEN_P(zprop_key), &_rowlock, &out_flags);
    if (!row) {
        swTableRow_unlock(_rowlock);
        php_swoole_error(E_WARNING, "Unable to allocate memory");
        RETURN_FALSE;
    }

    swTableColumn *col = swTableColumn_get(table, std::string(key, keylen));
    if (col == nullptr) {
        swTableRow_unlock(_rowlock);
        php_swoole_fatal_error(E_WARNING, "column[%s] does not exist", key);
        RETURN_FALSE;
    }
    if (col->type == SW_TABLE_STRING) {
        zend_string *str = zval_get_string(value);
        swTableRow_set_value(row, col, ZSTR_VAL(str), ZSTR_LEN(str));
        zend_string_release(str);
    } else if (col->type == SW_TABLE_FLOAT) {
        double _value = zval_get_double(value);
        swTableRow_set_value(row, col, &_value, 0);
    } else {
        long _value = zval_get_long(value);
        swTableRow_set_value(row, col, &_value, 0);
    }
    swTableRow_unlock(_rowlock);

    zval *zprop_value = sw_zend_read_property_ex(swoole_table_row_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_VALUE), 0);
    Z_TRY_ADDREF_P(value);
    add_assoc_zval_ex(zprop_value, key, keylen, value);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_table_row, offsetUnset) {
    php_swoole_fatal_error(E_WARNING, "not supported");
    RETURN_FALSE;
}

static PHP_METHOD(swoole_table_row, __destruct) {}
