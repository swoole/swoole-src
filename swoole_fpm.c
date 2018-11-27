/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 |     |
 +----------------------------------------------------------------------+
 | Author: chenlehui  <763414242@qq.com>                        |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#include "swoole_fpm.h"
#include "php_variables.h"
#include "zend_globals_macros.h"
#include "zend_extensions.h"

zend_class_entry swoole_fpm_server_ce;
zend_class_entry *swoole_fpm_server_class_entry_ptr;

static PHP_METHOD(swoole_fpm_server, run);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_fpm_server_run, 0, 0, 2)
ZEND_END_ARG_INFO()


const zend_function_entry swoole_fpm_server_methods[] =
{
    PHP_ME(swoole_fpm_server, run,         arginfo_swoole_fpm_server_run, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};


void swoole_fpm_server_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_fpm_server_ce, "swoole_fpm_server", "Swoole\\Fpm\\Server", swoole_fpm_server_methods);
    //swoole_fpm_server_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_fpm_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);
    swoole_fpm_server_class_entry_ptr = zend_register_internal_class(&swoole_fpm_server_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_fpm_server, "Swoole\\Fpm\\Server");

}

static PHP_METHOD(swoole_fpm_server, run)
{
    php_printf("execute_file, 11111111111\n");

    zend_file_handle file_handle;

    char *filename = "/var/www/my_index.php";

    if (zend_stream_open(filename, &file_handle) == FAILURE) {
        php_printf("execute_file, eeeeeeeeeeee\n");
    }

    php_printf("execute_file, 6666, %s, %s\n", file_handle.filename, ZSTR_VAL(file_handle.opened_path));

    php_execute_script(&file_handle);

    php_printf("execute_file, 99999999999\n");

    //php_request_shutdown((void *) 0);

	/* 2. Call all possible __destruct() functions */
	zend_try {
		//zend_call_destructors();
	} zend_end_try();


	/* 10. Shutdown scanner/executor/compiler and restore ini entries */
	//zend_deactivate();
    EG(current_execute_data) = NULL;
    //shutdown_scanner();

	/* 11. Call all extensions post-RSHUTDOWN functions */
	zend_try {
		//zend_post_deactivate_modules();
	} zend_end_try();

	zend_try {

/* Removed because this can not be safely done, e.g. in this situation:
   Object 1 creates object 2
   Object 3 holds reference to object 2.
   Now when 1 and 2 are destroyed, 3 can still access 2 in its destructor, with
   very problematic results */
/* 		zend_objects_store_call_destructors(&EG(objects_store)); */

/* Moved after symbol table cleaners, because  some of the cleaners can call
   destructors, which would use EG(symtable_cache_ptr) and thus leave leaks */
/*		while (EG(symtable_cache_ptr)>=EG(symtable_cache)) {
			zend_hash_destroy(*EG(symtable_cache_ptr));
			efree(*EG(symtable_cache_ptr));
			EG(symtable_cache_ptr)--;
		}
*/
		zend_llist_apply(&zend_extensions, (llist_apply_func_t) zend_extension_deactivator);

		if (CG(unclean_shutdown)) {
			EG(symbol_table).pDestructor = zend_unclean_zval_ptr_dtor;
		}
		zend_hash_graceful_reverse_destroy(&EG(symbol_table));
	} zend_end_try();
	EG(valid_symbol_table) = 0;

	zend_try {
		/* Cleanup static data for functions and arrays.
		 * We need a separate cleanup stage because of the following problem:
		 * Suppose we destroy class X, which destroys the class's function table,
		 * and in the function table we have function foo() that has static $bar.
		 * Now if an object of class X is assigned to $bar, its destructor will be
		 * called and will fail since X's function table is in mid-destruction.
		 * So we want first of all to clean up all data and then move to tables destruction.
		 * Note that only run-time accessed data need to be cleaned up, pre-defined data can
		 * not contain objects and thus are not probelmatic */
        zend_function *func;
	    zend_class_entry *ce;

		if (EG(full_tables_cleanup)) {
			ZEND_HASH_FOREACH_PTR(EG(function_table), func) {
				if (func->type == ZEND_USER_FUNCTION) {
					zend_cleanup_op_array_data((zend_op_array *) func);
				}
			} ZEND_HASH_FOREACH_END();
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(class_table), ce) {
				if (ce->type == ZEND_USER_CLASS) {
					zend_cleanup_user_class_data(ce);
				} else {
					zend_cleanup_internal_class_data(ce);
				}
			} ZEND_HASH_FOREACH_END();
		} else {
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(function_table), func) {
				if (func->type != ZEND_USER_FUNCTION) {
					break;
				}
				zend_cleanup_op_array_data((zend_op_array *) func);
			} ZEND_HASH_FOREACH_END();
			ZEND_HASH_REVERSE_FOREACH_PTR(EG(class_table), ce) {
				if (ce->type != ZEND_USER_CLASS) {
					break;
				}
				zend_cleanup_user_class_data(ce);
			} ZEND_HASH_FOREACH_END();
			zend_cleanup_internal_classes();
		}
	} zend_end_try();

	zend_try {
	//	zend_objects_store_free_object_storage(&EG(objects_store));

		zend_vm_stack_destroy();

		/* Destroy all op arrays */
		if (EG(full_tables_cleanup)) {
			zend_hash_reverse_apply(EG(function_table), clean_non_persistent_function_full);
			zend_hash_reverse_apply(EG(class_table), clean_non_persistent_class_full);
		} else {
			zend_hash_reverse_apply(EG(function_table), clean_non_persistent_function);
			zend_hash_reverse_apply(EG(class_table), clean_non_persistent_class);
		}

		while (EG(symtable_cache_ptr)>=EG(symtable_cache)) {
			zend_hash_destroy(*EG(symtable_cache_ptr));
			FREE_HASHTABLE(*EG(symtable_cache_ptr));
			EG(symtable_cache_ptr)--;
		}
	} zend_end_try();

    RETURN_TRUE
}

