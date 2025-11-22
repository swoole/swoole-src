#include "php_swoole_cxx.h"

//----------------------------------known string------------------------------------

static const char *sw_known_strings[] = {
#define _SW_ZEND_STR_DSC(id, str) str,
    SW_ZEND_KNOWN_STRINGS(_SW_ZEND_STR_DSC)
#undef _SW_ZEND_STR_DSC
        nullptr};

SW_API zend_string **sw_zend_known_strings = nullptr;

SW_API zend_refcounted *sw_refcount_ptr;

zend_refcounted *sw_get_refcount_ptr(zval *value) {
    return (sw_refcount_ptr = value->value.counted);
}

//----------------------------------known string------------------------------------
namespace zend {
void known_strings_init() {
    sw_zend_known_strings = static_cast<zend_string **>(
        pemalloc(sizeof(zend_string *) * ((sizeof(sw_known_strings) / sizeof(sw_known_strings[0]) - 1)), 1));
    for (unsigned int i = 0; i < (sizeof(sw_known_strings) / sizeof(sw_known_strings[0])) - 1; i++) {
        zend_string *str = zend_string_init(sw_known_strings[i], strlen(sw_known_strings[i]), true);
        sw_zend_known_strings[i] = zend_new_interned_string(str);
    }
}

void known_strings_dtor() {
    pefree(sw_zend_known_strings, 1);
    sw_zend_known_strings = nullptr;
}

zend_function *get_function(const zend_array *function_table, const char *name, size_t name_len) {
    return static_cast<zend_function *>(zend_hash_str_find_ptr(function_table, name, name_len));
}

zend_function *get_function(const char *fname, size_t fname_len) {
    return get_function(EG(function_table), fname, fname_len);
}

zend_function *get_function(const std::string &fname) {
    return get_function(fname.c_str(), fname.length());
}

zend_function *get_function(const zend_string *fname) {
    return get_function(ZSTR_VAL(fname), ZSTR_LEN(fname));
}

static zend_always_inline zval *sw_zend_symtable_str_add(
    HashTable *ht, const char *str, size_t len, zend_ulong idx, bool numeric_key, zval *pData) {
    if (numeric_key) {
        return zend_hash_index_add(ht, idx, pData);
    } else {
        return zend_hash_str_add(ht, str, len, pData);
    }
}

static zend_always_inline zval *sw_zend_symtable_str_find(
    HashTable *ht, const char *str, size_t len, zend_ulong idx, bool numeric_key) {
    if (numeric_key) {
        return zend_hash_index_find(ht, idx);
    } else {
        return zend_hash_str_find(ht, str, len);
    }
}

static zend_always_inline zval *sw_zend_symtable_str_update(
    HashTable *ht, const char *str, size_t len, zend_ulong idx, bool numeric_key, zval *pData) {
    if (numeric_key) {
        return zend_hash_index_update(ht, idx, pData);
    } else {
        return zend_hash_str_update(ht, str, len, pData);
    }
}

void array_add_or_merge(zval *zarray, const char *key, size_t key_len, zval *new_element) {
    zend_ulong idx;
    bool numeric_key = ZEND_HANDLE_NUMERIC_STR(key, key_len, idx);

    zend_array *array = Z_ARRVAL_P(zarray);
    zval *zresult = sw_zend_symtable_str_add(array, key, key_len, idx, numeric_key, new_element);
    // Adding element failed, indicating that this key already exists and must be converted to an array
    if (!zresult) {
        zval *current_elements = sw_zend_symtable_str_find(array, key, key_len, idx, numeric_key);
        if (ZVAL_IS_ARRAY(current_elements)) {
            add_next_index_zval(current_elements, new_element);
        } else {
            zval zvalue_array;
            array_init_size(&zvalue_array, 2);
            Z_ADDREF_P(current_elements);
            add_next_index_zval(&zvalue_array, current_elements);
            add_next_index_zval(&zvalue_array, new_element);
            sw_zend_symtable_str_update(array, key, key_len, idx, numeric_key, &zvalue_array);
        }
    }
}

namespace function {

bool call(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *retval, const bool enable_coroutine) {
    bool success;
    if (enable_coroutine) {
        if (retval) {
            /* the coroutine has no return value */
            ZVAL_NULL(retval);
        }
        success = swoole::PHPCoroutine::create(fci_cache, argc, argv, nullptr) >= 0;
    } else {
        success = sw_zend_call_function_ex(nullptr, fci_cache, argc, argv, retval) == SUCCESS;
    }
    /* we have no chance to return to ZendVM to check the exception  */
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return success;
}

Variable call(const std::string &func_name, int argc, zval *argv) {
    zval function_name;
    ZVAL_STRINGL(&function_name, func_name.c_str(), func_name.length());
    Variable retval;
    if (call_user_function(EG(function_table), nullptr, &function_name, &retval.value, argc, argv) != SUCCESS) {
        ZVAL_NULL(&retval.value);
    }
    zval_dtor(&function_name);
    /* we have no chance to return to ZendVM to check the exception  */
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return retval;
}

}  // namespace function

Callable::Callable(zval *_zfn) {
    ZVAL_UNDEF(&zfn);
    if (!zval_is_true(_zfn)) {
        php_swoole_fatal_error(E_WARNING, "illegal callback function");
        return;
    }
    if (!sw_zend_is_callable_ex(_zfn, nullptr, 0, &fn_name, nullptr, &fcc, nullptr)) {
        php_swoole_fatal_error(E_WARNING, "function '%s' is not callable", fn_name);
        return;
    }
    zfn = *_zfn;
    zval_add_ref(&zfn);
}

Callable::~Callable() {
    if (!ZVAL_IS_UNDEF(&zfn)) {
        zval_ptr_dtor(&zfn);
    }
    if (fn_name) {
        efree(fn_name);
    }
}

uint32_t Callable::refcount() const {
    return zval_refcount_p(&zfn);
}
}  // namespace zend
