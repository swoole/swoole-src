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
static PHP_METHOD(swoole_buffer, append);
static PHP_METHOD(swoole_buffer, substr);
static PHP_METHOD(swoole_buffer, write);
static PHP_METHOD(swoole_buffer, expand);
static PHP_METHOD(swoole_buffer, clear);

static const zend_function_entry swoole_buffer_methods[] =
{
    PHP_ME(swoole_buffer, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_buffer, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_buffer, substr, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_buffer, read, substr, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, write, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, append, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, expand, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, clear, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

zend_class_entry swoole_buffer_ce;
zend_class_entry *swoole_buffer_class_entry_ptr;

void swoole_buffer_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_buffer_ce, "swoole_buffer", swoole_buffer_methods);
    swoole_buffer_class_entry_ptr = zend_register_internal_class(&swoole_buffer_ce TSRMLS_CC);
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
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "buffer size cannot be less than 0");
        RETURN_FALSE;
    }
    else if (size > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "buffer size must not exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(size);
    if (buffer == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "malloc(%ld) failed.", size);
        RETURN_FALSE;
    }

    swoole_set_object(getThis(), buffer);
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
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

    if ((str.length + buffer->size) > SW_STRING_BUFFER_MAXLEN)
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
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"), buffer->length TSRMLS_CC);
        RETURN_LONG(buffer->length);
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
    zend_bool seek = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|lb", &offset, &length, &seek) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());

    if (seek && !(offset == 0 && length < buffer->length))
    {
        seek = 0;
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
    if (seek)
    {
        buffer->offset += length;
        zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"),
                buffer->length - buffer->offset TSRMLS_CC);
    }
    SW_RETURN_STRINGL(buffer->str + offset, length, 1);
}

static PHP_METHOD(swoole_buffer, write)
{
    long offset;
    char *new_str;
    zend_size_t length;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &offset, &new_str, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());
    if (offset < 0)
    {
        offset = buffer->length + offset;
    }
    offset += buffer->offset;
    if (length > buffer->size - offset)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string is too long.");
        RETURN_FALSE;
    }
    memcpy(buffer->str + offset, new_str, length);
    RETURN_TRUE;
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
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
    SW_CHECK_RETURN(swString_extend(buffer, size));
}

static PHP_METHOD(swoole_buffer, clear)
{
    swString *buffer = swoole_get_object(getThis());
    buffer->length = 0;
    buffer->offset = 0;
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("length"), 0 TSRMLS_CC);
}
