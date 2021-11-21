ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, get_error_stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_sleep, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fread, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fgets, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fwrite, 0, 0, 2)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_gethostbyname, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_dnsLookup, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_getaddrinfo, 0, 0, 1)
    ZEND_ARG_INFO(0, hostname)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, socktype)
    ZEND_ARG_INFO(0, protocol)
    ZEND_ARG_INFO(0, service)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_readFile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_writeFile, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_statvfs, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_waitPid, 0, 0, 1)
    ZEND_ARG_INFO(0, pid)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_waitSignal, 0, 0, 1)
    ZEND_ARG_INFO(0, signo)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_waitEvent, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, events)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_System_gethostbyname arginfo_swoole_coroutine_system_gethostbyname
#define arginfo_class_Swoole_Coroutine_System_dnsLookup     arginfo_swoole_coroutine_system_dnsLookup
#define arginfo_class_Swoole_Coroutine_System_exec          arginfo_swoole_coroutine_system_exec
#define arginfo_class_Swoole_Coroutine_System_sleep         arginfo_swoole_coroutine_system_sleep
#define arginfo_class_Swoole_Coroutine_System_getaddrinfo   arginfo_swoole_coroutine_system_getaddrinfo
#define arginfo_class_Swoole_Coroutine_System_statvfs       arginfo_swoole_coroutine_system_statvfs
#define arginfo_class_Swoole_Coroutine_System_readFile      arginfo_swoole_coroutine_system_readFile
#define arginfo_class_Swoole_Coroutine_System_writeFile     arginfo_swoole_coroutine_system_writeFile
#define arginfo_class_Swoole_Coroutine_System_wait          arginfo_swoole_coroutine_system_wait
#define arginfo_class_Swoole_Coroutine_System_waitPid       arginfo_swoole_coroutine_system_waitPid
#define arginfo_class_Swoole_Coroutine_System_waitSignal    arginfo_swoole_coroutine_system_waitSignal
#define arginfo_class_Swoole_Coroutine_System_waitEvent     arginfo_swoole_coroutine_system_waitEvent
#define arginfo_class_Swoole_Coroutine_System_fread         arginfo_swoole_coroutine_system_fread
#define arginfo_class_Swoole_Coroutine_System_fwrite        arginfo_swoole_coroutine_system_fwrite
#define arginfo_class_Swoole_Coroutine_System_fgets         arginfo_swoole_coroutine_system_fgets
