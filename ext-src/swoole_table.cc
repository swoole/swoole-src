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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"

#include "swoole_table.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_table_arginfo.h"
END_EXTERN_C()

using swoole::Table;
using swoole::TableColumn;
using swoole::TableRow;
using swoole::TableStringLength;
using swoole::TableValues;

static inline void table_data2value(const TableColumn *col, const char *data, zval *return_value) {
    if (col->type == TableColumn::TYPE_STRING) {
        TableStringLength len = 0;
        memcpy(&len, data, sizeof(len));
        ZVAL_STRINGL(return_value, data + sizeof(len), len);
    } else if (col->type == TableColumn::TYPE_FLOAT) {
        double dval = 0;
        memcpy(&dval, data, sizeof(dval));
        ZVAL_DOUBLE(return_value, dval);
    } else if (col->type == TableColumn::TYPE_INT) {
        long lval = 0;
        memcpy(&lval, data, sizeof(lval));
        ZVAL_LONG(return_value, lval);
    } else {
        php_swoole_fatal_error(E_WARNING, "unknown table column type[%d]", col->type);
        ZVAL_FALSE(return_value);
    }
}

static inline void table_data2array(const Table *table, const char *data, zval *return_value) {
    array_init(return_value);

    for (const auto col : *table->column_list) {
        zval value;
        table_data2value(col, data + col->index, &value);
        add_assoc_zval_ex(return_value, col->name.c_str(), col->name.length(), &value);
    }
}

static zend_class_entry *swoole_table_ce;
static zend_object_handlers swoole_table_handlers;

struct TableObject {
    Table *ptr;
    uint32_t value_conversion_depth;
    zend_object std;
};

static TableObject *table_fetch_object(zend_object *obj) {
    return reinterpret_cast<TableObject *>(reinterpret_cast<char *>(obj) - swoole_table_handlers.offset);
}

static Table *table_get_ptr(const zval *zobject) {
    return table_fetch_object(Z_OBJ_P(zobject))->ptr;
}

static Table *table_get_and_check_ptr(const zval *zobject) {
    Table *table = table_get_ptr(zobject);
    if (UNEXPECTED(!table)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return table;
}

static Table *table_get_and_check_ptr2(const zval *zobject) {
    Table *table = table_get_and_check_ptr(zobject);
    if (!table->ready()) {
        php_swoole_fatal_error(E_ERROR, "table is not created or has been destroyed");
    }
    return table;
}

static inline bool table_check_key_length(size_t keylen) {
    if (keylen == 0) {
        php_swoole_fatal_error(E_WARNING, "key must not be empty");
        return false;
    }
    if (keylen >= SW_TABLE_KEY_SIZE) {
        php_swoole_fatal_error(E_WARNING, "key length exceeds the limit of %d bytes", SW_TABLE_KEY_SIZE - 1);
        return false;
    }
    return true;
}

enum TableValueMode {
    TABLE_VALUE_EXPECTED,
    TABLE_VALUE_WRITE,
};

static bool table_marshal_values(const zval *zobject,
                                 Table *table,
                                 HashTable *ht,
                                 const char *key,
                                 size_t keylen,
                                 TableValueMode mode,
                                 TableValues *values) {
    values->clear();
    values->reserve(zend_hash_num_elements(ht));

    const char *name;
    uint32_t name_length;
    int key_type;
    zval *value;
    if (mode == TABLE_VALUE_EXPECTED) {
        if (zend_hash_num_elements(ht) == 0) {
            php_swoole_fatal_error(E_WARNING, "expected values must not be empty");
            return false;
        }

        // Reject the complete condition before conversions can execute user code.
        SW_HASHTABLE_FOREACH_START2(ht, name, name_length, key_type, value) {
            if (name == nullptr) {
                php_swoole_fatal_error(E_WARNING, "expected values must use column names");
                return false;
            }
            if (table->get_column(std::string(name, name_length)) == nullptr) {
                php_swoole_fatal_error(E_WARNING, "column[%.*s] does not exist", (int) name_length, name);
                return false;
            }
        }
        (void) key_type;
        SW_HASHTABLE_FOREACH_END();
    }

    // Keep the table schema alive while conversions may execute user code.
    TableObject *object = table_fetch_object(Z_OBJ_P(zobject));
    object->value_conversion_depth++;
    ON_SCOPE_EXIT {
        object->value_conversion_depth--;
    };

    SW_HASHTABLE_FOREACH_START2(ht, name, name_length, key_type, value) {
        if (name == nullptr) {
            continue;
        }

        TableColumn *column = table->get_column(std::string(name, name_length));
        if (column == nullptr) {
            continue;
        }

        if (column->type == TableColumn::TYPE_STRING) {
            zend_string *string = zval_get_string(value);
            if (UNEXPECTED(EG(exception))) {
                if (string) {
                    zend_string_release(string);
                }
                return false;
            }

            size_t length = ZSTR_LEN(string);
            const size_t capacity = column->size - sizeof(TableStringLength);
            if (mode == TABLE_VALUE_WRITE && length > capacity) {
                swoole_warning("[key=%.*s,field=%s]string value is too long", (int) keylen, key, column->name.c_str());
                length = capacity;
            }
            values->emplace_back(column, ZSTR_VAL(string), length);
            zend_string_release(string);
        } else if (column->type == TableColumn::TYPE_FLOAT) {
            double number = zval_get_double(value);
            if (UNEXPECTED(EG(exception))) {
                return false;
            }
            values->emplace_back(column, &number, sizeof(number));
        } else {
            long number = zval_get_long(value);
            if (UNEXPECTED(EG(exception))) {
                return false;
            }
            values->emplace_back(column, &number, sizeof(number));
        }
    }
    (void) key_type;
    SW_HASHTABLE_FOREACH_END();

    return true;
}

static void table_set_ptr(const zval *zobject, Table *ptr) {
    table_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static void table_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static zend_object *table_create_object(zend_class_entry *ce) {
    auto *table = static_cast<TableObject *>(zend_object_alloc(sizeof(TableObject), ce));
    zend_object_std_init(&table->std, ce);
    object_properties_init(&table->std, ce);
    table->std.handlers = &swoole_table_handlers;
    return &table->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_table, __construct);
static PHP_METHOD(swoole_table, column);
static PHP_METHOD(swoole_table, create);
static PHP_METHOD(swoole_table, set);
static PHP_METHOD(swoole_table, add);
static PHP_METHOD(swoole_table, update);
static PHP_METHOD(swoole_table, cmpset);
static PHP_METHOD(swoole_table, get);
static PHP_METHOD(swoole_table, getdel);
static PHP_METHOD(swoole_table, del);
static PHP_METHOD(swoole_table, cmpdel);
static PHP_METHOD(swoole_table, exists);
static PHP_METHOD(swoole_table, incr);
static PHP_METHOD(swoole_table, decr);
static PHP_METHOD(swoole_table, count);
static PHP_METHOD(swoole_table, destroy);
static PHP_METHOD(swoole_table, getSize);
static PHP_METHOD(swoole_table, getMemorySize);
static PHP_METHOD(swoole_table, stats);

static PHP_METHOD(swoole_table, rewind);
static PHP_METHOD(swoole_table, next);
static PHP_METHOD(swoole_table, current);
static PHP_METHOD(swoole_table, key);
static PHP_METHOD(swoole_table, valid);

SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_table_methods[] =
{
    PHP_ME(swoole_table, __construct,       arginfo_class_Swoole_Table___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, column,            arginfo_class_Swoole_Table_column,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, create,            arginfo_class_Swoole_Table_create,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, destroy,           arginfo_class_Swoole_Table_destroy,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, set,               arginfo_class_Swoole_Table_set,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, add,               arginfo_class_Swoole_Table_add,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, update,            arginfo_class_Swoole_Table_update,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, cmpset,            arginfo_class_Swoole_Table_cmpset,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, get,               arginfo_class_Swoole_Table_get,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, getdel,            arginfo_class_Swoole_Table_getdel,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, count,             arginfo_class_Swoole_Table_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, del,               arginfo_class_Swoole_Table_del,           ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_table, delete, del,   arginfo_class_Swoole_Table_del,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, cmpdel,            arginfo_class_Swoole_Table_cmpdel,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, exists,            arginfo_class_Swoole_Table_exists,        ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_table, exist, exists, arginfo_class_Swoole_Table_exists,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, incr,              arginfo_class_Swoole_Table_incr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, decr,              arginfo_class_Swoole_Table_decr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, getSize,           arginfo_class_Swoole_Table_getSize,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, getMemorySize,     arginfo_class_Swoole_Table_getMemorySize, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, stats,             arginfo_class_Swoole_Table_stats,         ZEND_ACC_PUBLIC)
    // implement Iterator
    PHP_ME(swoole_table, rewind,            arginfo_class_Swoole_Table_rewind,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, valid,             arginfo_class_Swoole_Table_valid,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, next,              arginfo_class_Swoole_Table_next,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, current,           arginfo_class_Swoole_Table_current,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, key,               arginfo_class_Swoole_Table_key,           ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_table_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_table, "Swoole\\Table", nullptr, swoole_table_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_table);
    SW_SET_CLASS_CLONEABLE(swoole_table, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_table, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_table, table_create_object, table_free_object, TableObject, std);
    zend_class_implements(swoole_table_ce, 1, zend_ce_iterator);
    zend_class_implements(swoole_table_ce, 1, zend_ce_countable);

    zend_declare_property_null(swoole_table_ce, ZEND_STRL("size"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_table_ce, ZEND_STRL("memorySize"), ZEND_ACC_PUBLIC);

    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_INT"), TableColumn::TYPE_INT);
    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_STRING"), TableColumn::TYPE_STRING);
    zend_declare_class_constant_long(swoole_table_ce, ZEND_STRL("TYPE_FLOAT"), TableColumn::TYPE_FLOAT);
}

PHP_METHOD(swoole_table, __construct) {
    Table *table = table_get_ptr(ZEND_THIS);
    if (table) {
        zend_throw_error(nullptr, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long table_size;
    double conflict_proportion = SW_TABLE_CONFLICT_PROPORTION;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_LONG(table_size)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(conflict_proportion)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    table = Table::make(table_size, static_cast<float>(conflict_proportion));
    if (table == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }
    table->set_hash_func([](const char *key, size_t len) -> uint64_t {
        return zend_string_hash_val(zend::fetch_zend_string_by_val((void *) key));
    });
    table_set_ptr(ZEND_THIS, table);
}

PHP_METHOD(swoole_table, column) {
    char *name;
    size_t len;
    long type;
    long size = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl|l", &name, &len, &type, &size) == FAILURE) {
        RETURN_FALSE;
    }

    Table *table = table_get_and_check_ptr(ZEND_THIS);
    if (type == TableColumn::TYPE_STRING) {
        if (size < 1) {
            php_swoole_fatal_error(E_WARNING, "the length of string type values has to be more than zero");
            RETURN_FALSE;
        }
        size = SW_MEM_ALIGNED_SIZE(size);
    }
    if (table->ready()) {
        php_swoole_fatal_error(E_WARNING, "unable to add column after table has been created");
        RETURN_FALSE;
    }
    RETURN_BOOL(table->add_column(std::string(name, len), static_cast<TableColumn::Type>(type), size));
}

static PHP_METHOD(swoole_table, create) {
    Table *table = table_get_and_check_ptr(ZEND_THIS);

    if (!table->create()) {
        php_swoole_fatal_error(E_ERROR, "unable to allocate memory");
        RETURN_FALSE;
    }
    zend_update_property_long(
        swoole_table_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("size"), (zend_long) table->get_size());
    zend_update_property_long(
        swoole_table_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("memorySize"), (zend_long) table->get_memory_size());
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, destroy) {
    TableObject *object = table_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (UNEXPECTED(object->value_conversion_depth != 0)) {
        zend_throw_error(nullptr, "Cannot destroy %s during value conversion", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    Table *table = table_get_and_check_ptr2(ZEND_THIS);

    table->destroy();
    table_set_ptr(ZEND_THIS, nullptr);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, set) {
    zval *array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableValues values;
    if (!table_marshal_values(ZEND_THIS, table, Z_ARRVAL_P(array), key, keylen, TABLE_VALUE_WRITE, &values)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    bool out_of_space = false;
    if (!table->set(key, keylen, values, &out_of_space)) {
        if (out_of_space) {
            php_swoole_error(E_WARNING, "failed to set('%*s'), unable to allocate memory", (int) keylen, key);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_table, add) {
    zval *array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableValues values;
    if (!table_marshal_values(ZEND_THIS, table, Z_ARRVAL_P(array), key, keylen, TABLE_VALUE_WRITE, &values)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    bool out_of_space = false;
    bool result = table->add(key, keylen, values, &out_of_space);
    if (!result && out_of_space) {
        php_swoole_error(E_WARNING, "failed to add('%*s'), unable to allocate memory", (int) keylen, key);
    }
    RETURN_BOOL(result);
}

static PHP_METHOD(swoole_table, update) {
    zval *array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableValues values;
    if (!table_marshal_values(ZEND_THIS, table, Z_ARRVAL_P(array), key, keylen, TABLE_VALUE_WRITE, &values)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    RETURN_BOOL(table->update(key, keylen, values));
}

static PHP_METHOD(swoole_table, cmpset) {
    zval *expected_array;
    zval *values_array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(expected_array)
    Z_PARAM_ARRAY(values_array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableValues expected;
    if (!table_marshal_values(
            ZEND_THIS, table, Z_ARRVAL_P(expected_array), key, keylen, TABLE_VALUE_EXPECTED, &expected)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    TableValues values;
    if (!table_marshal_values(ZEND_THIS, table, Z_ARRVAL_P(values_array), key, keylen, TABLE_VALUE_WRITE, &values)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    RETURN_BOOL(table->cmpset(key, keylen, expected, values));
}

static PHP_METHOD(swoole_table, incr) {
    char *key;
    size_t key_len;
    char *col;
    size_t col_len;
    zval *incrby = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &key, &key_len, &col, &col_len, &incrby) == FAILURE) {
        RETURN_FALSE;
    }

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(key_len)) {
        RETURN_FALSE;
    }

    TableColumn *column = table->get_column(std::string(col, col_len));
    if (column == nullptr) {
        php_swoole_fatal_error(E_WARNING, "column[%s] does not exist", col);
        RETURN_FALSE;
    }
    if (column->type == TableColumn::TYPE_STRING) {
        php_swoole_fatal_error(E_WARNING, "can't execute 'incr' on a string type column");
        RETURN_FALSE;
    }

    double double_value = 1;
    long long_value = 1;
    if (incrby) {
        // Convert before acquiring the bucket lock because conversion can execute user code.
        {
            TableObject *object = table_fetch_object(Z_OBJ_P(ZEND_THIS));
            object->value_conversion_depth++;
            ON_SCOPE_EXIT {
                object->value_conversion_depth--;
            };

            if (column->type == TableColumn::TYPE_FLOAT) {
                double_value = zval_get_double(incrby);
            } else {
                long_value = zval_get_long(incrby);
            }
        }

        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
    }

    int out_flags;
    TableRow *_rowlock = nullptr;
    TableRow *row = table->set(key, key_len, &_rowlock, &out_flags);
    if (!row) {
        if (_rowlock) {
            _rowlock->unlock();
        }
        php_swoole_fatal_error(E_WARNING, "unable to allocate memory");
        RETURN_FALSE;
    }

    if (out_flags & SW_TABLE_FLAG_NEW_ROW) {
        table->clear_row(row);
    }

    if (column->type == TableColumn::TYPE_FLOAT) {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        set_value += double_value;
        row->set_value(column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    } else {
        long set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        set_value += long_value;
        row->set_value(column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    _rowlock->unlock();
}

static PHP_METHOD(swoole_table, decr) {
    char *key;
    size_t key_len;
    char *col;
    size_t col_len;
    zval *decrby = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &key, &key_len, &col, &col_len, &decrby) == FAILURE) {
        RETURN_FALSE;
    }

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(key_len)) {
        RETURN_FALSE;
    }

    TableColumn *column = table->get_column(std::string(col, col_len));
    if (column == nullptr) {
        php_swoole_fatal_error(E_WARNING, "column[%s] does not exist", col);
        RETURN_FALSE;
    }
    if (column->type == TableColumn::TYPE_STRING) {
        php_swoole_fatal_error(E_WARNING, "can't execute 'decr' on a string type column");
        RETURN_FALSE;
    }

    double double_value = 1;
    long long_value = 1;
    if (decrby) {
        // Convert before acquiring the bucket lock because conversion can execute user code.
        {
            TableObject *object = table_fetch_object(Z_OBJ_P(ZEND_THIS));
            object->value_conversion_depth++;
            ON_SCOPE_EXIT {
                object->value_conversion_depth--;
            };

            if (column->type == TableColumn::TYPE_FLOAT) {
                double_value = zval_get_double(decrby);
            } else {
                long_value = zval_get_long(decrby);
            }
        }

        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
    }

    int out_flags;
    TableRow *_rowlock = nullptr;
    TableRow *row = table->set(key, key_len, &_rowlock, &out_flags);
    if (!row) {
        if (_rowlock) {
            _rowlock->unlock();
        }
        php_swoole_fatal_error(E_WARNING, "unable to allocate memory");
        RETURN_FALSE;
    }

    if (out_flags & SW_TABLE_FLAG_NEW_ROW) {
        table->clear_row(row);
    }

    if (column->type == TableColumn::TYPE_FLOAT) {
        double set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        set_value -= double_value;
        row->set_value(column, &set_value, 0);
        RETVAL_DOUBLE(set_value);
    } else {
        long set_value = 0;
        memcpy(&set_value, row->data + column->index, sizeof(set_value));
        set_value -= long_value;
        row->set_value(column, &set_value, 0);
        RETVAL_LONG(set_value);
    }
    _rowlock->unlock();
}

static PHP_METHOD(swoole_table, get) {
    char *key;
    size_t keylen;
    zend_string *field = nullptr;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_OR_NULL(field)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableRow *_rowlock = nullptr;
    TableRow *row = table->get(key, keylen, &_rowlock);
    if (!row) {
        RETVAL_FALSE;
    } else if (field) {
        TableColumn *column = table->get_column(std::string(ZSTR_VAL(field), ZSTR_LEN(field)));
        if (column) {
            table_data2value(column, row->data + column->index, return_value);
        } else {
            RETVAL_FALSE;
        }
    } else {
        table_data2array(table, row->data, return_value);
    }
    if (_rowlock) {
        _rowlock->unlock();
    }
}

static PHP_METHOD(swoole_table, getdel) {
    char *key;
    size_t keylen;
    zend_string *field = nullptr;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR_OR_NULL(field)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableColumn *column = nullptr;
    if (field) {
        column = table->get_column(std::string(ZSTR_VAL(field), ZSTR_LEN(field)));
        if (column == nullptr) {
            RETURN_FALSE;
        }
    }

    std::string data;
    if (!table->getdel(key, keylen, column, &data)) {
        RETURN_FALSE;
    }

    if (column) {
        table_data2value(column, data.data(), return_value);
    } else {
        table_data2array(table, data.data(), return_value);
    }
}

static PHP_METHOD(swoole_table, exists) {
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE) {
        RETURN_FALSE;
    }

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }
    RETURN_BOOL(table->exists(key, keylen));
}

static PHP_METHOD(swoole_table, del) {
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_STRING(key, keylen)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }
    RETURN_BOOL(table->del(key, keylen));
}

static PHP_METHOD(swoole_table, cmpdel) {
    zval *expected_array;
    char *key;
    size_t keylen;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(key, keylen)
    Z_PARAM_ARRAY(expected_array)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    if (!table_check_key_length(keylen)) {
        RETURN_FALSE;
    }

    TableValues expected;
    if (!table_marshal_values(
            ZEND_THIS, table, Z_ARRVAL_P(expected_array), key, keylen, TABLE_VALUE_EXPECTED, &expected)) {
        if (UNEXPECTED(EG(exception))) {
            RETURN_THROWS();
        }
        RETURN_FALSE;
    }

    RETURN_BOOL(table->cmpdel(key, keylen, expected));
}

static PHP_METHOD(swoole_table, count) {
#define COUNT_NORMAL 0
#define COUNT_RECURSIVE 1
    Table *table = table_get_ptr(ZEND_THIS);
    if (!table) {
        RETURN_LONG(0);
    }

    zend_long mode = COUNT_NORMAL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &mode) == FAILURE) {
        RETURN_FALSE;
    }

    if (mode == COUNT_NORMAL) {
        RETURN_LONG(table->count());
    } else {
        RETURN_LONG(table->count() * table->column_list->size());
    }
}

static PHP_METHOD(swoole_table, getMemorySize) {
    Table *table = table_get_ptr(ZEND_THIS);
    if (!table) {
        RETURN_LONG(0);
    } else {
        RETURN_LONG(table->get_memory_size());
    }
}

static PHP_METHOD(swoole_table, getSize) {
    Table *table = table_get_ptr(ZEND_THIS);
    if (!table) {
        RETURN_LONG(0);
    } else {
        RETURN_LONG(table->get_size());
    }
}

static PHP_METHOD(swoole_table, stats) {
    Table *table = table_get_ptr(ZEND_THIS);
    if (!table || !table->ready()) {
        RETURN_FALSE;
    }
    array_init(return_value);
    add_assoc_long(return_value, "num", table->count());
    add_assoc_long(return_value, "conflict_count", table->conflict_count);
    add_assoc_long(return_value, "conflict_max_level", table->conflict_max_level);
    add_assoc_long(return_value, "insert_count", (zend_long) table->insert_count);
    add_assoc_long(return_value, "update_count", (zend_long) table->update_count);
    add_assoc_long(return_value, "delete_count", (zend_long) table->delete_count);
    add_assoc_long(return_value, "available_slice_num", table->get_available_slice_num());
    add_assoc_long(return_value, "total_slice_num", table->get_total_slice_num());
}

static PHP_METHOD(swoole_table, rewind) {
    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    table->rewind();
    table->forward();
}

static PHP_METHOD(swoole_table, valid) {
    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    auto key = table->current();
    RETURN_BOOL(key->key_len != 0);
}

static PHP_METHOD(swoole_table, current) {
    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    auto row = table->current();
    if (row->key_len == 0) {
        RETURN_NULL();
    }
    table_data2array(table, row->data, return_value);
}

static PHP_METHOD(swoole_table, key) {
    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    auto row = table->current();
    if (row->key_len == 0) {
        RETURN_NULL();
    }
    RETVAL_STRINGL(row->key, row->key_len);
}

static PHP_METHOD(swoole_table, next) {
    Table *table = table_get_and_check_ptr2(ZEND_THIS);
    table->forward();
}
