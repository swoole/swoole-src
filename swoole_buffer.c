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
    ZEND_ARG_INFO(0, seek)
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
    PHP_ME(swoole_buffer, __construct, arginfo_swoole_buffer_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_buffer, __destruct, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
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

zend_class_entry swoole_buffer_ce;
zend_class_entry *swoole_buffer_class_entry_ptr;

void swoole_buffer_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_buffer_ce, "swoole_buffer", "Swoole\\Buffer", swoole_buffer_methods);
    swoole_buffer_class_entry_ptr = zend_register_internal_class(&swoole_buffer_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_buffer, "Swoole\\Buffer");
}

void swoole_buffer_recycle(swString *buffer)
{
    long length;

    if (buffer->offset == 0) {
        return;
    }

    length = buffer->length - buffer->offset;

    if (length > 0) {
        memcpy(buffer->str, buffer->str + buffer->offset, length);
    }

    buffer->offset = 0;
    buffer->length = length;
}

static PHP_METHOD(swoole_buffer, __construct)
{
    long size = SW_STRING_BUFFER_DEFAULT;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (size < 1)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "buffer size cannot be less than 0.", SW_ERROR_INVALID_PARAMS TSRMLS_CC);
        RETURN_FALSE;
    }
    else if (size > SW_STRING_BUFFER_MAXLEN)
    {
        zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "buffer size must not exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(size);
    if (buffer == NULL)
    {
        zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "malloc(%ld) failed.", size);
        RETURN_FALSE;
    }

    swoole_set_object(getThis(), buffer);
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"), 0 TSRMLS_CC);
}

static PHP_METHOD(swoole_buffer, __destruct)
{
    swString *buffer = swoole_get_object(getThis());
    if (buffer)
    {
        swString_free(buffer);
    }
}

static PHP_METHOD(swoole_buffer, append)
{
    swString str;
    bzero(&str, sizeof(str));

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (str.length < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string empty.");
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());

    if ((str.length + buffer->length) > buffer->size && (str.length + buffer->length) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "buffer size must not exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    if (swString_append(buffer, &str) == SW_OK)
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), buffer->size TSRMLS_CC);
        }
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"),
                buffer->length - buffer->offset TSRMLS_CC);
        RETURN_LONG(buffer->length - buffer->offset);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, substr)
{
    long offset;
    long length = -1;
    zend_bool remove = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|lb", &offset, &length, &remove) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());

    if (remove && !(offset == 0 && length < buffer->length))
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
    if (offset + length > buffer->length)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "offset(%ld,%ld) out of bounds.", offset, length);
        RETURN_FALSE;
    }
    if (remove)
    {
        buffer->offset += length;
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"),
                buffer->length - buffer->offset TSRMLS_CC);

        if (buffer->offset > SW_STRING_BUFFER_GARBAGE_MIN && buffer->offset * SW_STRING_BUFFER_GARBAGE_RATIO > buffer->size) {
            // Do recycle when the garbage is to large.
            swoole_buffer_recycle(buffer);
        }
    }
    SW_RETURN_STRINGL(buffer->str + offset, length, 1);
}

static PHP_METHOD(swoole_buffer, __toString)
{
    swString *buffer = swoole_get_object(getThis());
    SW_RETURN_STRINGL(buffer->str + buffer->offset, buffer->length - buffer->offset, 1);
}

static PHP_METHOD(swoole_buffer, write)
{
    long offset;
    swString str;

    bzero(&str, sizeof(str));

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &offset, &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (str.length < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string empty.");
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }
    if (offset < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "offset(%ld) out of bounds.", offset);
        RETURN_FALSE;
    }

    offset += buffer->offset;

    if ((str.length + offset) > buffer->size && (str.length + offset) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "buffer size must not exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    if (swString_write(buffer, offset, &str) == SW_OK)
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), buffer->size TSRMLS_CC);
        }
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"),
                buffer->length - buffer->offset TSRMLS_CC);
        RETURN_LONG(buffer->length - buffer->offset);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, read)
{
    long offset;
    long length;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }
    if (offset < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "offset(%ld) out of bounds.", offset);
        RETURN_FALSE;
    }

    offset += buffer->offset;

    if (length > buffer->length - offset)
    {
        RETURN_FALSE;
    }

    SW_RETURN_STRINGL(buffer->str + offset, length, 1);
}

static PHP_METHOD(swoole_buffer, expand)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    if (size <= buffer->size)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "new size must more than %ld", buffer->size);
        RETURN_FALSE;
    }

    if (swString_extend(buffer, size) == SW_OK)
    {
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, recycle)
{
    swString *buffer = swoole_get_object(getThis());

    swoole_buffer_recycle(buffer);

    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"), buffer->length TSRMLS_CC);
}

static PHP_METHOD(swoole_buffer, clear)
{
    swString *buffer = swoole_get_object(getThis());
    buffer->length = 0;
    buffer->offset = 0;
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"), 0 TSRMLS_CC);
}
