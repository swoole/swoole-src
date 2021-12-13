ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_construct, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
    ZEND_ARG_INFO(0, redirect_stdin_and_stdout)
    ZEND_ARG_INFO(0, pipe_type)
    ZEND_ARG_INFO(0, enable_coroutine)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, blocking)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_signal, 0, 0, 2)
    ZEND_ARG_INFO(0, signal_no)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_alarm, 0, 0, 1)
    ZEND_ARG_INFO(0, usec)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_kill, 0, 0, 1)
    ZEND_ARG_INFO(0, pid)
    ZEND_ARG_INFO(0, signal_no)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_daemon, 0, 0, 0)
    ZEND_ARG_INFO(0, nochdir)
    ZEND_ARG_INFO(0, noclose)
    ZEND_ARG_INFO(0, pipes)
ZEND_END_ARG_INFO()

#ifdef HAVE_CPU_AFFINITY
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setAffinity, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cpu_settings, 0)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setPriority, 0, 0, 2)
    ZEND_ARG_INFO(0, which)
    ZEND_ARG_INFO(0, priority)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_getPriority, 0, 0, 1)
    ZEND_ARG_INFO(0, which)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setTimeout, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setBlocking, 0, 0, 1)
    ZEND_ARG_INFO(0, blocking)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_useQueue, 0, 0, 0)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, capacity)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_read, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exit, 0, 0, 0)
    ZEND_ARG_INFO(0, exit_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exec, 0, 0, 2)
    ZEND_ARG_INFO(0, exec_file)
    ZEND_ARG_INFO(0, args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_name, 0, 0, 1)
    ZEND_ARG_INFO(0, process_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_close, 0, 0, 1)
    ZEND_ARG_INFO(0, which)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Process___construct arginfo_swoole_process_construct
#define arginfo_class_Swoole_Process___destruct  arginfo_swoole_process_void
#define arginfo_class_Swoole_Process_wait        arginfo_swoole_process_wait
#define arginfo_class_Swoole_Process_signal      arginfo_swoole_process_signal
#define arginfo_class_Swoole_Process_alarm       arginfo_swoole_process_alarm
#define arginfo_class_Swoole_Process_kill        arginfo_swoole_process_kill
#define arginfo_class_Swoole_Process_daemon      arginfo_swoole_process_daemon

#ifdef HAVE_CPU_AFFINITY
#define arginfo_class_Swoole_Process_setAffinity arginfo_swoole_process_setAffinity
#endif

#define arginfo_class_Swoole_Process_setPriority  arginfo_swoole_process_setPriority
#define arginfo_class_Swoole_Process_getPriority  arginfo_swoole_process_getPriority
#define arginfo_class_Swoole_Process_set          arginfo_swoole_process_set
#define arginfo_class_Swoole_Process_setTimeout   arginfo_swoole_process_setTimeout
#define arginfo_class_Swoole_Process_setBlocking  arginfo_swoole_process_setBlocking
#define arginfo_class_Swoole_Process_useQueue     arginfo_swoole_process_useQueue
#define arginfo_class_Swoole_Process_statQueue    arginfo_swoole_process_void
#define arginfo_class_Swoole_Process_freeQueue    arginfo_swoole_process_void
#define arginfo_class_Swoole_Process_start        arginfo_swoole_process_void
#define arginfo_class_Swoole_Process_write        arginfo_swoole_process_write
#define arginfo_class_Swoole_Process_close        arginfo_swoole_process_close
#define arginfo_class_Swoole_Process_read         arginfo_swoole_process_read
#define arginfo_class_Swoole_Process_push         arginfo_swoole_process_push
#define arginfo_class_Swoole_Process_pop          arginfo_swoole_process_pop
#define arginfo_class_Swoole_Process_exit         arginfo_swoole_process_exit
#define arginfo_class_Swoole_Process_exec         arginfo_swoole_process_exec
#define arginfo_class_Swoole_Process_exportSocket arginfo_swoole_process_void
#define arginfo_class_Swoole_Process_name         arginfo_swoole_process_name
