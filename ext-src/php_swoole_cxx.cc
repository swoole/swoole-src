#include "php_swoole_cxx.h"

//----------------------------------Swoole known string------------------------------------

static const char *sw_known_strings[] = {
#define _SW_ZEND_STR_DSC(id, str) str,
    SW_ZEND_KNOWN_STRINGS(_SW_ZEND_STR_DSC)
#undef _SW_ZEND_STR_DSC
        nullptr};

SW_API zend_string **sw_zend_known_strings = nullptr;

//----------------------------------Swoole known string------------------------------------

#if PHP_VERSION_ID < 80000
typedef zval zend_source_string_t;
#else
typedef zend_string zend_source_string_t;
#endif

static zend_op_array *swoole_compile_string(zend_source_string_t *source_string, ZEND_STR_CONST char *filename);

// for compatibly with dis_eval
static zend_op_array *(*old_compile_string)(zend_source_string_t *source_string, ZEND_STR_CONST char *filename);

static zend_op_array *swoole_compile_string(zend_source_string_t *source_string, ZEND_STR_CONST char *filename) {
    zend_op_array *opa = old_compile_string(source_string, filename);
    opa->type = ZEND_USER_FUNCTION;
    return opa;
}

namespace zend {
bool include(const std::string &file) {
    zend_file_handle file_handle;
    int ret = php_stream_open_for_zend_ex(file.c_str(), &file_handle, USE_PATH | STREAM_OPEN_FOR_INCLUDE);
    if (ret != SUCCESS) {
        return false;
    }

    zend_string *opened_path;
    if (!file_handle.opened_path) {
        file_handle.opened_path = zend_string_init(file.c_str(), file.length(), 0);
    }
    opened_path = zend_string_copy(file_handle.opened_path);
    zval dummy;

    zval retval;
    zend_op_array *new_op_array;
    ZVAL_NULL(&dummy);
    if (zend_hash_add(&EG(included_files), opened_path, &dummy)) {
        new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE);
        zend_destroy_file_handle(&file_handle);
    } else {
        new_op_array = nullptr;
        zend_file_handle_dtor(&file_handle);
    }
    zend_string_release(opened_path);
    if (!new_op_array) {
        return false;
    }

    zend_execute(new_op_array, &retval);

    destroy_op_array(new_op_array);
    efree(new_op_array);
    return Z_TYPE(retval) == IS_TRUE;
}

bool eval(const std::string &code, std::string const &filename) {
    if (!old_compile_string) {
        old_compile_string = zend_compile_string;
    }
    // overwrite
    zend_compile_string = swoole_compile_string;
    int ret = (zend_eval_stringl((char *) code.c_str(), code.length(), nullptr, (char *) filename.c_str()) == SUCCESS);
    // recover
    zend_compile_string = old_compile_string;
    return ret;
}

void known_strings_init(void) {
    zend_string *str;
    sw_zend_known_strings = nullptr;

    /* known strings */
    sw_zend_known_strings = (zend_string **) pemalloc(
        sizeof(zend_string *) * ((sizeof(sw_known_strings) / sizeof(sw_known_strings[0]) - 1)), 1);
    for (unsigned int i = 0; i < (sizeof(sw_known_strings) / sizeof(sw_known_strings[0])) - 1; i++) {
        str = zend_string_init(sw_known_strings[i], strlen(sw_known_strings[i]), 1);
        sw_zend_known_strings[i] = zend_new_interned_string(str);
    }
}

void known_strings_dtor(void) {
    pefree(sw_zend_known_strings, 1);
    sw_zend_known_strings = nullptr;
}

zend_string *fetch_zend_string_by_val(char *val) {
    return (zend_string *) (val - XtOffsetOf(zend_string, val));
}

namespace function {

bool call(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *retval, const bool enable_coroutine) {
    bool success;
    if (enable_coroutine) {
        if (retval) {
            /* the coroutine has no return value */
            ZVAL_NULL(retval);
        }
        success = swoole::PHPCoroutine::create(fci_cache, argc, argv) >= 0;
    } else {
        success = sw_zend_call_function_ex(nullptr, fci_cache, argc, argv, retval) == SUCCESS;
    }
    /* we have no chance to return to ZendVM to check the exception  */
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return success;
}

ReturnValue call(const std::string &func_name, int argc, zval *argv) {
    zval function_name;
    ZVAL_STRINGL(&function_name, func_name.c_str(), func_name.length());
    ReturnValue retval;
    if (call_user_function(EG(function_table), NULL, &function_name, &retval.value, argc, argv) != SUCCESS) {
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
}  // namespace zend
