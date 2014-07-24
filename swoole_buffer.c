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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

static sw_inline swString* php_swoole_buffer_get(zval *object)
{
    zval **zres;
    swString *str = NULL;
    if (zend_hash_find(Z_OBJPROP_P(object), SW_STRL("_memory"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE_NO_RETURN(str, swString*, zres, -1, SW_RES_BUFFER_NAME, le_swoole_buffer);
    }
    assert(str != NULL);
    return str;
}

void swoole_destory_buffer(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
    swString *str = (swString *) rsrc->ptr;
    if (str)
    {
        swString_free(str);
    }
}

PHP_METHOD(swoole_buffer, __construct)
{
    long size = SW_STRING_BUFFER_DEFAULT;

#ifdef ZTS
    if (sw_thread_ctx == NULL)
    {
        TSRMLS_SET_CTX(sw_thread_ctx);
    }
#endif

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

    zval *zres;
    MAKE_STD_ZVAL(zres);

    swString *buffer = swString_new(size);
    if (buffer == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "malloc(%ld) failed.", size);
        RETURN_FALSE;
    }

    ZEND_REGISTER_RESOURCE(zres, buffer, le_swoole_buffer);
    zend_update_property(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("_memory"), zres TSRMLS_CC);
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
    zval_ptr_dtor(&zres);
}

PHP_METHOD(swoole_buffer, append)
{
    swString str;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (str.length < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string empty.");
        RETURN_FALSE;
    }
    swString *buffer = php_swoole_buffer_get(getThis());
    if (!buffer)
    {
        RETURN_FALSE;
    }
    if (str.length + buffer->size > SW_STRING_BUFFER_MAXLEN)
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

PHP_METHOD(swoole_buffer, substr)
{
    long offset;
    long length = -1;
    zend_bool copy = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|lb", &offset, &length, &copy) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = php_swoole_buffer_get(getThis());
    if (!buffer)
    {
        RETURN_FALSE;
    }
    if (offset < 0)
    {
        offset = buffer->length + offset;
    }
    if (length < 0)
    {
        length = buffer->length - offset;
    }
    RETURN_STRINGL(buffer->str + offset, length, copy);
}

PHP_METHOD(swoole_buffer, copy)
{
    long offset;
    char *new_str;
    int length;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &offset, &new_str, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = php_swoole_buffer_get(getThis());
    if (!buffer)
    {
        RETURN_FALSE;
    }
    if (offset < 0)
    {
        offset = buffer->length + offset;
    }
    if (length < 0)
    {
        length = buffer->length - offset;
    }
    if (length > buffer->length - offset)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "string is too long.");
        RETURN_FALSE;
    }
    memcpy(buffer->str + offset, new_str, length);
    RETURN_TRUE;
}

PHP_METHOD(swoole_buffer, expand)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = php_swoole_buffer_get(getThis());
    if (!buffer)
    {
        RETURN_FALSE;
    }
    if (size <= buffer->size)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "new size must more than %ld", buffer->size);
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_buffer_class_entry_ptr, getThis(), ZEND_STRL("capacity"), size TSRMLS_CC);
    SW_CHECK_RETURN(swString_extend(buffer, size));
}
