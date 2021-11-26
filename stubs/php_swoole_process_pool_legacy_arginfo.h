ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, worker_num)
    ZEND_ARG_INFO(0, ipc_type)
    ZEND_ARG_INFO(0, msgqueue_key)
    ZEND_ARG_INFO(0, enable_coroutine)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_getProcess, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_listen, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, backlog)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Process_Pool___construct arginfo_swoole_process_pool_construct
#define arginfo_class_Swoole_Process_Pool___destruct  arginfo_swoole_process_pool_void
#define arginfo_class_Swoole_Process_Pool_set         arginfo_swoole_process_pool_set
#define arginfo_class_Swoole_Process_Pool_on          arginfo_swoole_process_pool_on
#define arginfo_class_Swoole_Process_Pool_getProcess  arginfo_swoole_process_pool_getProcess
#define arginfo_class_Swoole_Process_Pool_listen      arginfo_swoole_process_pool_listen
#define arginfo_class_Swoole_Process_Pool_write       arginfo_swoole_process_pool_write
#define arginfo_class_Swoole_Process_Pool_detach      arginfo_swoole_process_pool_void
#define arginfo_class_Swoole_Process_Pool_start       arginfo_swoole_process_pool_void
#define arginfo_class_Swoole_Process_Pool_stop        arginfo_swoole_process_pool_void
#define arginfo_class_Swoole_Process_Pool_shutdown    arginfo_swoole_process_pool_void
