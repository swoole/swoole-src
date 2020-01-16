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

zend_class_entry *swoole_buffer_ce;
static zend_object_handlers swoole_buffer_handlers;

typedef struct
{
    swString *ptr;
    zend_object std;
} buffer_t;

static sw_inline buffer_t* php_swoole_buffer_fetch_object(zend_object *obj)
{
    return (buffer_t *) ((char *) obj - swoole_buffer_handlers.offset);
}

static swString* php_swoole_buffer_get_ptr(zval *zobject)
{
    return (swString*) php_swoole_buffer_fetch_object(Z_OBJ_P(zobject))->ptr;
}

static swString * php_swoole_buffer_get_and_check_ptr(zval *zobject)
{
    swString *buffer = php_swoole_buffer_get_ptr(zobject);
    if (!buffer)
    {
        php_swoole_fatal_error(E_ERROR, "you must call Buffer constructor first");
    }
    return buffer;
}

void php_swoole_buffer_set_ptr(zval *zobject, swString *ptr)
{
    php_swoole_buffer_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static void php_swoole_buffer_free_object(zend_object *object)
{
    buffer_t *buffer = php_swoole_buffer_fetch_object(object);
    if (buffer->ptr)
    {
        swString_free(buffer->ptr);
    }
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_buffer_create_object(zend_class_entry *ce)
{
    buffer_t *buffer = (buffer_t *) ecalloc(1, sizeof(buffer_t) + zend_object_properties_size(ce));
    zend_object_std_init(&buffer->std, ce);
    object_properties_init(&buffer->std, ce);
    buffer->std.handlers = &swoole_buffer_handlers;
    return &buffer->std;
}

static PHP_METHOD(swoole_buffer, __construct);
static PHP_METHOD(swoole_buffer, __destruct);
static PHP_METHOD(swoole_buffer, __toString);
static PHP_METHOD(swoole_buffer, append);
static PHP_METHOD(swoole_buffer, substr);
static PHP_METHOD(swoole_buffer, read);
static PHP_METHOD(swoole_buffer, write);
static PHP_METHOD(swoole_buffer, expand);
static PHP_METHOD(swoole_buffer, recycle);
static PHP_METHOD(swoole_buffer, clear);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_expand, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_substr, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, remove)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_write, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_read, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_append, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_buffer_methods[] =
{
    PHP_ME(swoole_buffer, __construct, arginfo_swoole_buffer_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, __destruct, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, __toString, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, substr, arginfo_swoole_buffer_substr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, write, arginfo_swoole_buffer_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, read, arginfo_swoole_buffer_read, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, append, arginfo_swoole_buffer_append, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, expand, arginfo_swoole_buffer_expand, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, recycle, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, clear, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void php_swoole_buffer_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_buffer, "Swoole\\Buffer", "swoole_buffer", NULL, swoole_buffer_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_buffer, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_buffer, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_buffer, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_buffer, php_swoole_buffer_create_object, php_swoole_buffer_free_object, buffer_t, std);

    zend_declare_property_long(swoole_buffer_ce, ZEND_STRL("capacity"), SW_STRING_BUFFER_DEFAULT, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_buffer_ce, ZEND_STRL("length"), 0, ZEND_ACC_PUBLIC);
}

static void swoole_buffer_recycle(swString *buffer)
{
    if (buffer->offset == 0)
    {
        return;
    }
    swString_pop_front(buffer, buffer->offset);
}

static PHP_METHOD(swoole_buffer, __construct)
{
    php_swoole_fatal_error(
        E_DEPRECATED, "Class %s is deprecated, it will be removed in v4.5.0",
        ZSTR_VAL(swoole_buffer_ce->name)
    );

    swString *buffer = php_swoole_buffer_get_ptr(ZEND_THIS);
    if (buffer)
    {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    zend_long size = SW_STRING_BUFFER_DEFAULT;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(size)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (size < 1)
    {
        zend_throw_exception(swoole_exception_ce, "buffer size can't be less than 0", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }
    else if (size > SW_STRING_BUFFER_MAXLEN)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    buffer = swString_new(size);
    if (buffer == NULL)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "malloc(" ZEND_LONG_FMT ") failed", size);
        RETURN_FALSE;
    }

    php_swoole_buffer_set_ptr(ZEND_THIS, buffer);
    zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("capacity"), size);
    zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"), 0);
}

static PHP_METHOD(swoole_buffer, __destruct) { }

static PHP_METHOD(swoole_buffer, append)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    swString str = {};

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (str.length < 1)
    {
        php_error_docref(NULL, E_WARNING, "string empty");
        RETURN_FALSE;
    }

    if ((str.length + buffer->length) > buffer->size && (str.length + buffer->length) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL, E_WARNING, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    if (swString_append(buffer, &str) == SW_OK)
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("capacity"), buffer->size);
        }
        zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"),
                buffer->length - buffer->offset);
        RETURN_LONG(buffer->length - buffer->offset);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, substr)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    zend_long offset;
    zend_long length = -1;
    zend_bool remove = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|lb", &offset, &length, &remove) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (remove && !(offset == 0 && length <= (zend_long) buffer->length))
    {
        remove = 0;
    }
    if (offset < 0)
    {
        offset = buffer->length + offset;
    }
    offset += buffer->offset;
    if (length < 0)
    {
        length = buffer->length - offset;
    }
    if (length + offset > (zend_long) buffer->length)
    {
        php_swoole_error(E_WARNING, "offset(" ZEND_LONG_FMT ", " ZEND_LONG_FMT ") is out of bounds", offset, length);
        RETURN_FALSE;
    }
    if (remove)
    {
        buffer->offset += length;
        zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"), buffer->length - buffer->offset);

        if (buffer->offset > SW_STRING_BUFFER_GARBAGE_MIN && buffer->offset * SW_STRING_BUFFER_GARBAGE_RATIO > (zend_long) buffer->size)
        {
            swoole_buffer_recycle(buffer);
        }
    }
    RETURN_STRINGL(buffer->str + offset, length);
}

static PHP_METHOD(swoole_buffer, __toString)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    RETURN_STRINGL(buffer->str + buffer->offset, buffer->length - buffer->offset);
}

static PHP_METHOD(swoole_buffer, write)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    zend_long offset;
    swString str = {};

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls", &offset, &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (str.length < 1)
    {
        php_error_docref(NULL, E_WARNING, "string to write is empty");
        RETURN_FALSE;
    }

    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }
    if (offset < 0)
    {
        php_error_docref(NULL, E_WARNING, "offset(" ZEND_LONG_FMT ") is out of bounds", offset);
        RETURN_FALSE;
    }

    offset += buffer->offset;

    if ((str.length + offset) > buffer->size && (str.length + offset) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL, E_WARNING, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    if (swString_write(buffer, offset, &str) == SW_OK)
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("capacity"), buffer->size);
        }
        zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"),
                buffer->length - buffer->offset);
        RETURN_LONG(buffer->length - buffer->offset);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, read)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    zend_long offset;
    zend_long length;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }
    if (offset < 0)
    {
        php_error_docref(NULL, E_WARNING, "offset(" ZEND_LONG_FMT ") is out of bounds", offset);
        RETURN_FALSE;
    }

    offset += buffer->offset;

    if (length > (zend_long) buffer->length - offset)
    {
        RETURN_FALSE;
    }

    RETURN_STRINGL(buffer->str + offset, length);
}

static PHP_METHOD(swoole_buffer, expand)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);
    zend_long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (size <= (zend_long) buffer->size)
    {
        php_error_docref(NULL, E_WARNING, "new size must be more than %ld", buffer->size);
        RETURN_FALSE;
    }

    if (swString_extend(buffer, size) == SW_OK)
    {
        zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("capacity"), size);
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, recycle)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);

    swoole_buffer_recycle(buffer);
    zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"), buffer->length);
}

static PHP_METHOD(swoole_buffer, clear)
{
    swString *buffer = php_swoole_buffer_get_and_check_ptr(ZEND_THIS);

    buffer->length = 0;
    buffer->offset = 0;
    zend_update_property_long(swoole_buffer_ce, ZEND_THIS, ZEND_STRL("length"), 0);
}
