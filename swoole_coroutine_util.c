#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"

static PHP_METHOD(swoole_coroutine_util, coroYield);
static PHP_METHOD(swoole_coroutine_util, coroResume);

static swHashMap *defer_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    PHP_ME(swoole_coroutine_util, coroYield, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, coroResume, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_coroutine_util_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine_util", "Swoole\\Coroutine\\Util", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce TSRMLS_CC);

    defer_coros = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
}

static void swoole_coroutine_util_resume(void *data)
{
	php_context *context = (php_context *)data;
	zval *retval = NULL;
	zval *result;
	SW_MAKE_STD_ZVAL(result);
	ZVAL_BOOL(result, 1);
	int ret = coro_resume(context, result, &retval);
	if (ret == CORO_END && retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
	sw_zval_ptr_dtor(&result);
	efree(context);
}

static PHP_METHOD(swoole_coroutine_util, coroYield)
{
	char *id;
	int id_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",&id, &id_len) == FAILURE)
	{
		return;
	}

    swLinkedList *coros_list = swHashMap_find(defer_coros, id, id_len);
	if (coros_list == NULL)
	{
		coros_list = swLinkedList_new(2, NULL);
		if (coros_list == NULL)
		{
			RETURN_FALSE;
		}
		if (swHashMap_add(defer_coros, id, id_len, coros_list) == SW_ERR)
		{
			swLinkedList_free(coros_list);
			RETURN_FALSE;
		}
	}

    php_context *context = emalloc(sizeof(php_context));
	coro_save(return_value, return_value_ptr, context);
	swLinkedList_append(coros_list, (void *)context);
	coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, coroResume)
{
	char *id;
	int id_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &id, &id_len) == FAILURE)
	{
		return;
	}

    swLinkedList *coros_list = swHashMap_find(defer_coros, id, id_len);
	if (coros_list == NULL)
	{
        swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
		RETURN_FALSE;
	}

	php_context *context = swLinkedList_shift(coros_list);
	if (context == NULL)
	{
        swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
		RETURN_FALSE;
	}

	SwooleG.main_reactor->defer(SwooleG.main_reactor, swoole_coroutine_util_resume, context);

	RETURN_TRUE;
}
#endif
