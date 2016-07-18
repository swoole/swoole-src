#include "php_swoole.h"
#include "swoole_coroutine.h"
#include "ext/standard/basic_functions.h"

static PHP_METHOD(swoole_multi, recv);
static PHP_METHOD(swoole_multi, add);
static PHP_METHOD(swoole_multi, del);
static PHP_METHOD(swoole_multi, __destruct);

static const zend_function_entry swoole_multi_methods[] =
{
    PHP_ME(swoole_multi, recv, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_multi, add, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_multi, del, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_multi, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

zend_class_entry swoole_multi_ce;
zend_class_entry *swoole_multi_class_entry_ptr;
zend_class_entry *swoole_client_multi_class_entry_ptr;

void swoole_multi_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_multi_ce, "swoole_multi", "Swoole\\Coroutine\\Multi", swoole_multi_methods);
    swoole_multi_class_entry_ptr = zend_register_internal_class(&swoole_multi_ce TSRMLS_CC);

    zend_declare_property_null(swoole_multi_class_entry_ptr, SW_STRL("result_array")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(swoole_multi_class_entry_ptr, SW_STRL("client_map")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_long(swoole_multi_class_entry_ptr, SW_STRL("count")-1, 0, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_bool(swoole_multi_class_entry_ptr, SW_STRL("is_recv_ready")-1, 0, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_bool(swoole_multi_class_entry_ptr, SW_STRL("is_recv_done")-1, 0, ZEND_ACC_PRIVATE TSRMLS_CC);
}

void swoole_multi_recv(zval *swoole_multi, zval *response, long obj_handle)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
	zval *result_array = zend_read_property(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("result_array")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(result_array) == IS_NULL)
	{
		SW_MAKE_STD_ZVAL(result_array);
		array_init(result_array);
		zend_update_property(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("result_array")-1, result_array TSRMLS_CC);
		sw_zval_ptr_dtor(&result_array);
	}
	zval *client_map = zend_read_property(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("client_map")-1, 0 TSRMLS_CC);
	zval **value;
	if (sw_zend_hash_index_find(Z_ARRVAL_P(client_map), obj_handle, (void **)&value) == SUCCESS)
	{
		if (SW_Z_TYPE_PP(value) == IS_STRING)
		{
			add_assoc_zval(result_array, Z_STRVAL_PP(value), response);
		}
		else
		{
			add_index_zval(result_array, Z_LVAL_PP(value), response);
		}
	}
	else
	{
		sw_zval_ptr_dtor(&response);
		return;
	}
	zval *count = zend_read_property(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("count")-1, 0 TSRMLS_CC);
	long c = Z_LVAL_P(count);
	zend_update_property_long(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("count")-1, --c TSRMLS_CC);
	zval *is_recv_ready = zend_read_property(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("is_recv_ready")-1, 0 TSRMLS_CC);
	if (c == 0)
	{
		if (Z_BVAL_P(is_recv_ready))
		{
			zend_update_property_long(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("count")-1, zend_hash_num_elements(Z_ARRVAL_P(client_map)) TSRMLS_CC);
			zend_update_property_bool(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("is_recv_ready")-1, 0 TSRMLS_CC);
			sw_zval_add_ref(&result_array);
			zend_update_property_null(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("result_array")-1 TSRMLS_CC);
			zval *retval = NULL;
			php_context *sw_current_context = swoole_get_property(swoole_multi, 0);
			int ret = coro_resume(sw_current_context, result_array, &retval);
			sw_zval_ptr_dtor(&result_array);
			if (ret == CORO_END && retval)
			{
				sw_zval_ptr_dtor(&retval);
			}
		}
		else
		{
			zend_update_property_bool(swoole_multi_class_entry_ptr, swoole_multi, SW_STRL("is_recv_done")-1, 1 TSRMLS_CC);
		}
	}
}

int swoole_multi_is_multi_mode(zval *cli_obj)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
	zval *swoole_multi = zend_read_property(swoole_client_multi_class_entry_ptr, cli_obj, SW_STRL("swoole_multi")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(swoole_multi) != IS_NULL)
	{
		return CORO_MULTI;
	}

	return CORO_SAVE;
}

int swoole_multi_resume(zval *cli_obj, zval *response)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
	zval *swoole_multi = zend_read_property(swoole_client_multi_class_entry_ptr, cli_obj, SW_STRL("swoole_multi")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(swoole_multi) != IS_NULL)
	{
#if PHP_MAJOR_VERSION < 7
		zend_object_handle handle = Z_OBJ_HANDLE_P(cli_obj);
#else
		int handle = (int) Z_OBJ_HANDLE(*cli_obj);
#endif
		swoole_multi_recv(swoole_multi, response, (long)handle);
		return CORO_MULTI;
	}

	return CORO_RESUME;
}

static PHP_METHOD(swoole_multi, recv)
{
	zval *client_map = zend_read_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("client_map")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(client_map) == IS_NULL || zend_hash_num_elements(Z_ARRVAL_P(client_map)) == 0)
	{
		RETURN_FALSE;
	}
	zval *is_recv_done = zend_read_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("is_recv_done")-1, 0 TSRMLS_CC);
	if (Z_BVAL_P(is_recv_done))
	{
		zend_update_property_long(swoole_multi_class_entry_ptr, getThis(), SW_STRL("count")-1, zend_hash_num_elements(Z_ARRVAL_P(client_map)) TSRMLS_CC);
		zend_update_property_bool(swoole_multi_class_entry_ptr, getThis(), SW_STRL("is_recv_done")-1, 0 TSRMLS_CC);
		zval *result_array = zend_read_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("result_array")-1, 0 TSRMLS_CC);
		sw_zval_add_ref(&result_array);
		zend_update_property_null(swoole_multi_class_entry_ptr, getThis(), SW_STRL("result_array")-1 TSRMLS_CC);
		RETURN_ZVAL(result_array, 0, 1);
		return;
	}
	zend_update_property_bool(swoole_multi_class_entry_ptr, getThis(), SW_STRL("is_recv_ready")-1, 1 TSRMLS_CC);
    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 0, context);
    }
	coro_save(return_value, return_value_ptr, context);
	coro_yield();
}

static PHP_METHOD(swoole_multi, __destruct)
{
    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
		return;
    }
	efree(context);
    swoole_set_property(getThis(), 0, NULL);
}

static PHP_METHOD(swoole_multi, add)
{
	zval *zmap, *client_map;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &zmap) == FAILURE)
    {
        return;
    }
	client_map = zend_read_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("client_map")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(client_map) != IS_ARRAY)
	{
		SW_MAKE_STD_ZVAL(client_map);
		array_init(client_map);
		zend_update_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("client_map")-1, client_map TSRMLS_CC);
		sw_zval_ptr_dtor(&client_map);
	}

	long num = 0;
	zval *value;
	char *key;
	int keytype;
	uint32_t keylen;
	SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zmap), key, keylen, keytype, value)
		if (SW_Z_TYPE_P(value) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(value), swoole_client_multi_class_entry_ptr TSRMLS_CC))
		{
			continue;
		}
#if PHP_MAJOR_VERSION < 7
		zend_object_handle handle = Z_OBJ_HANDLE_P(value);
#else
		int handle = (int) Z_OBJ_HANDLE(*value);
#endif
		if (zend_hash_index_exists(Z_ARRVAL_P(client_map), handle) == 0)
		{
			zend_update_property_long(swoole_multi_class_entry_ptr, getThis(), SW_STRL("count")-1, zend_hash_num_elements(Z_ARRVAL_P(client_map)) + 1 TSRMLS_CC);
			zend_update_property(swoole_client_multi_class_entry_ptr, value, SW_STRL("swoole_multi")-1, getThis() TSRMLS_CC);
		}
		if (keytype == HASH_KEY_IS_STRING)
		{
			add_index_stringl(client_map, handle, key, keylen, 1);
		}
		else
		{
			add_index_long(client_map, handle, idx);
		}
		num++;
	SW_HASHTABLE_FOREACH_END();

	RETURN_LONG(num);
}

static PHP_METHOD(swoole_multi, del)
{
	zval *cli_obj, *client_map;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &cli_obj, swoole_client_multi_class_entry_ptr) == FAILURE)
    {
        return;
    }
	client_map = zend_read_property(swoole_multi_class_entry_ptr, getThis(), SW_STRL("client_map")-1, 0 TSRMLS_CC);
	if (SW_Z_TYPE_P(client_map) != IS_ARRAY)
	{
		RETURN_LONG(0);
	}
#if PHP_MAJOR_VERSION < 7
		zend_object_handle handle = Z_OBJ_HANDLE_P(cli_obj);
#else
		int handle = (int) Z_OBJ_HANDLE(*cli_obj);
#endif
	if (zend_hash_index_exists(Z_ARRVAL_P(client_map), handle))
	{
		zend_hash_index_del(Z_ARRVAL_P(client_map), handle);
		zend_update_property_long(swoole_multi_class_entry_ptr, getThis(), SW_STRL("count")-1, zend_hash_num_elements(Z_ARRVAL_P(client_map)) TSRMLS_CC);
		zend_update_property_null(swoole_client_multi_class_entry_ptr, cli_obj, SW_STRL("swoole_multi")-1 TSRMLS_CC);

		RETURN_LONG(1);
	}

	RETURN_LONG(0);
}

