ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Channel___construct arginfo_swoole_channel_coro_construct
#define arginfo_class_Swoole_Coroutine_Channel_push        arginfo_swoole_channel_coro_push
#define arginfo_class_Swoole_Coroutine_Channel_pop         arginfo_swoole_channel_coro_pop
#define arginfo_class_Swoole_Coroutine_Channel_isEmpty     arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Channel_isEmpty     arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Channel_isFull      arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Channel_close       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Channel_stats       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Channel_length      arginfo_swoole_void
