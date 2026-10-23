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

#include "php_swoole_sendfile.h"

SW_EXTERN_C_BEGIN
#include "stubs/php_swoole_sendfile_arginfo.h"
static PHP_METHOD(swoole_sendfile, __construct);
SW_EXTERN_C_END

zend_class_entry *swoole_sendfile_ce;
static zend_object_handlers swoole_sendfile_handlers;

struct SendFileObject {
    bool constructed;
    bool submitted;
    zend_object std;
};

static SendFileObject *sendfile_fetch_object(zend_object *object) {
    return reinterpret_cast<SendFileObject *>(reinterpret_cast<char *>(object) - swoole_sendfile_handlers.offset);
}

static zend_object *sendfile_create_object(zend_class_entry *ce) {
    auto *object = static_cast<SendFileObject *>(zend_object_alloc(sizeof(SendFileObject), ce));
    zend_object_std_init(&object->std, ce);
    object_properties_init(&object->std, ce);
    object->std.handlers = &swoole_sendfile_handlers;
    return &object->std;
}

static void sendfile_free_object(zend_object *object) {
    // This is a descriptor, not a file owner. Only an accepted native send may delete the file.
    zend_object_std_dtor(object);
}

// clang-format off
static const zend_function_entry swoole_sendfile_methods[] = {
    PHP_ME(swoole_sendfile, __construct, arginfo_class_Swoole_SendFile___construct, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_sendfile_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_sendfile, "Swoole\\SendFile", nullptr, swoole_sendfile_methods);
    swoole_sendfile_ce->ce_flags |= ZEND_ACC_FINAL;
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_sendfile);
    SW_SET_CLASS_CLONEABLE(swoole_sendfile, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_sendfile, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_sendfile, sendfile_create_object, sendfile_free_object, SendFileObject, std);

    auto declare_property = [](const char *name, size_t length, zval *value, int flags, zend_type type) {
        zend_string *property = zend_string_init(name, length, true);
        zend_declare_typed_property(swoole_sendfile_ce, property, value, flags, nullptr, type);
        zend_string_release(property);
    };
    zval value;
    ZVAL_UNDEF(&value);
    declare_property(
        ZEND_STRL("filename"), &value, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY, ZEND_TYPE_INIT_CODE(IS_STRING, 0, 0));
    ZVAL_LONG(&value, 0);
    declare_property(ZEND_STRL("offset"), &value, ZEND_ACC_PUBLIC, ZEND_TYPE_INIT_CODE(IS_LONG, 0, 0));
    declare_property(ZEND_STRL("length"), &value, ZEND_ACC_PUBLIC, ZEND_TYPE_INIT_CODE(IS_LONG, 0, 0));
    ZVAL_FALSE(&value);
    declare_property(ZEND_STRL("deleteAfterSend"), &value, ZEND_ACC_PUBLIC, ZEND_TYPE_INIT_CODE(_IS_BOOL, 0, 0));
}

static PHP_METHOD(swoole_sendfile, __construct) {
    zend_string *filename;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_PATH_STR(filename)
    ZEND_PARSE_PARAMETERS_END();

    auto *object = sendfile_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (object->constructed) {
        zend_throw_error(nullptr, "Constructor of Swoole\\SendFile can only be called once");
        RETURN_THROWS();
    }
    if (ZSTR_LEN(filename) == 0) {
        zend_argument_value_error(1, "must not be empty");
        RETURN_THROWS();
    }
    zend_update_property_str(swoole_sendfile_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("filename"), filename);
    object->constructed = true;
}

bool php_swoole_sendfile_get_options(
    zend_object *object, zend_string **filename, zend_long *offset, zend_long *length, bool *delete_file) {
    auto *descriptor = sendfile_fetch_object(object);
    if (!descriptor->constructed || descriptor->submitted) {
        zend_throw_error(nullptr,
                         descriptor->submitted ? "Swoole\\SendFile has already transferred file cleanup ownership"
                                               : "Swoole\\SendFile constructor must be called first");
        return false;
    }
    // The class is final and its declared properties cannot be unset; only offset/length/bool may be references.
    zval rv;
    *filename = Z_STR_P(zend_read_property(swoole_sendfile_ce, object, ZEND_STRL("filename"), true, &rv));
    *offset = zval_get_long(zend_read_property(swoole_sendfile_ce, object, ZEND_STRL("offset"), true, &rv));
    *length = zval_get_long(zend_read_property(swoole_sendfile_ce, object, ZEND_STRL("length"), true, &rv));
    *delete_file =
        zend_is_true(zend_read_property(swoole_sendfile_ce, object, ZEND_STRL("deleteAfterSend"), true, &rv));
    if (*offset < 0 || *length < 0) {
        zend_value_error("Swoole\\SendFile::$%s must be greater than or equal to 0", *offset < 0 ? "offset" : "length");
        return false;
    }
    return true;
}

bool php_swoole_sendfile_acquire(zend_object *object) {
    if (object) {
        auto *descriptor = sendfile_fetch_object(object);
        if (descriptor->submitted) {
            zend_throw_error(nullptr, "Swoole\\SendFile has already transferred file cleanup ownership");
            return false;
        }
        descriptor->submitted = true;
    }
    return true;
}

void php_swoole_sendfile_release(zend_object *object) {
    if (object) {
        sendfile_fetch_object(object)->submitted = false;
    }
}
