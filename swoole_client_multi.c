#include "php_swoole.h"
#include "ext/standard/basic_functions.h"

zend_class_entry swoole_client_multi_ce;
zend_class_entry *swoole_client_multi_class_entry_ptr;
extern zend_class_entry *swoole_multi_class_entry_ptr;

void swoole_client_multi_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_client_multi_ce, "swoole_client_multi", "Swoole\\ClientMulti", NULL);
    swoole_client_multi_class_entry_ptr = zend_register_internal_class(&swoole_client_multi_ce TSRMLS_CC);

    zend_declare_property_null(swoole_client_multi_class_entry_ptr, SW_STRL("swoole_multi")-1, ZEND_ACC_PROTECTED TSRMLS_CC);
}
