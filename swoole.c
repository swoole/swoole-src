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

/* $Id: swoole.c 2013-12-24 10:31:55Z tianfeng $ */

#include "php_swoole.h"
#include "zend_variables.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#ifdef HAVE_PCRE
#include <ext/spl/spl_iterators.h>
#endif

ZEND_DECLARE_MODULE_GLOBALS(swoole)

extern sapi_module_struct sapi_module;

// arginfo server
// *_oo : for object style

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_create, 0, 0, 2)
    ZEND_ARG_INFO(0, serv_host)
    ZEND_ARG_INFO(0, serv_port)
    ZEND_ARG_INFO(0, serv_mode)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, zset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, zset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_start, 0, 0, 1)
       ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

//for object style

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendwait, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_exist, 0, 0, 1)
    ZEND_ARG_INFO(0, conn_fd)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendto_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, send_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_handler, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_handler_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addlisten, 0, 0, 4)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addlisten_oo, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addtimer, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addtimer_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

//function style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

//object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

//function style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload_oo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_shutdown, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_bind, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_info, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_info_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_list, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_list_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

//arginfo event
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_add, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_write, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_del, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

//arginfo timer
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_add, 0, 0, 2)
    ZEND_ARG_INFO(0, interval)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_del, 0, 0, 1)
    ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

//arginfo end

#ifdef SW_ASYNC_MYSQL
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqli/mysqli_mysqlnd.h"
#include "ext/mysqli/php_mysqli_structs.h"
#endif

#include "zend_exceptions.h"

const zend_function_entry swoole_functions[] =
{
    PHP_FE(swoole_version, NULL)
    PHP_FE(swoole_cpu_num, NULL)
    /*------swoole_server-----*/
    PHP_FE(swoole_server_create, arginfo_swoole_server_create)
    PHP_FE(swoole_server_set, arginfo_swoole_server_set)
    PHP_FE(swoole_server_start, arginfo_swoole_server_start)
    PHP_FE(swoole_server_send, arginfo_swoole_server_send)
    PHP_FE(swoole_server_sendfile, arginfo_swoole_server_sendfile)
    PHP_FE(swoole_server_close, arginfo_swoole_server_close)
    PHP_FE(swoole_server_handler, arginfo_swoole_server_handler)
    PHP_FE(swoole_server_on, arginfo_swoole_server_on)
    PHP_FE(swoole_server_addlisten, arginfo_swoole_server_addlisten)
    PHP_FE(swoole_server_addtimer, arginfo_swoole_server_addtimer)
    PHP_FE(swoole_server_gettimer, NULL)
    PHP_FE(swoole_server_task, arginfo_swoole_server_task)
    PHP_FE(swoole_server_taskwait, arginfo_swoole_server_taskwait)
    PHP_FE(swoole_server_finish, arginfo_swoole_server_finish)
    PHP_FE(swoole_server_reload, arginfo_swoole_server_reload)
    PHP_FE(swoole_server_shutdown, arginfo_swoole_server_shutdown)
    PHP_FE(swoole_server_heartbeat, arginfo_swoole_server_heartbeat)
    PHP_FE(swoole_connection_info, arginfo_swoole_connection_info)
    PHP_FE(swoole_connection_list, arginfo_swoole_connection_list)
    /*------swoole_event-----*/
    PHP_FE(swoole_event_add, arginfo_swoole_event_add)
    PHP_FE(swoole_event_set, NULL)
    PHP_FE(swoole_event_del, arginfo_swoole_event_del)
    PHP_FE(swoole_event_exit, arginfo_swoole_void)
    PHP_FE(swoole_event_wait, arginfo_swoole_void)
    PHP_FE(swoole_event_write, arginfo_swoole_event_write)
    /*------swoole_timer-----*/
    PHP_FE(swoole_timer_add, arginfo_swoole_timer_add)
    PHP_FE(swoole_timer_del, arginfo_swoole_timer_del)
    PHP_FE(swoole_timer_after, NULL)
    PHP_FE(swoole_timer_tick, NULL)
    PHP_FE(swoole_timer_clear, NULL)
    /*------swoole_async_io------*/
    PHP_FE(swoole_async_set, NULL)
    PHP_FE(swoole_async_read, NULL)
    PHP_FE(swoole_async_write, NULL)
    PHP_FE(swoole_async_readfile, NULL)
    PHP_FE(swoole_async_writefile, NULL)
    PHP_FE(swoole_async_dns_lookup, NULL)
    /*------other-----*/
    PHP_FE(swoole_client_select, NULL)
    PHP_FE(swoole_set_process_name, NULL)
    PHP_FE(swoole_get_local_ip, NULL)
    PHP_FE(swoole_strerror, NULL)
    PHP_FE(swoole_errno, NULL)
    /*------async mysql-----*/
#ifdef SW_ASYNC_MYSQL
    PHP_FE(swoole_get_mysqli_sock, NULL)
#endif
    PHP_FE_END /* Must be the last line in swoole_functions[] */
};

static zend_function_entry swoole_server_methods[] = {
    PHP_FALIAS(__construct, swoole_server_create, arginfo_swoole_server_create)
    PHP_FALIAS(set, swoole_server_set, arginfo_swoole_server_set_oo)
    PHP_FALIAS(start, swoole_server_start, arginfo_swoole_void)
    PHP_FALIAS(send, swoole_server_send, arginfo_swoole_server_send_oo)
    PHP_ME(swoole_server, sendto, arginfo_swoole_server_sendto_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendwait, arginfo_swoole_server_sendwait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, exist, arginfo_swoole_server_exist, ZEND_ACC_PUBLIC)
    PHP_FALIAS(sendfile, swoole_server_sendfile, arginfo_swoole_server_sendfile_oo)
    PHP_FALIAS(close, swoole_server_close, arginfo_swoole_server_close_oo)
    PHP_FALIAS(task, swoole_server_task, arginfo_swoole_server_task_oo)
    PHP_FALIAS(taskwait, swoole_server_taskwait, arginfo_swoole_server_taskwait_oo)
    PHP_FALIAS(finish, swoole_server_finish, arginfo_swoole_server_finish_oo)
    PHP_FALIAS(addlistener, swoole_server_addlisten, arginfo_swoole_server_addlisten_oo)
    PHP_FALIAS(reload, swoole_server_reload, arginfo_swoole_server_reload_oo)
    PHP_FALIAS(shutdown, swoole_server_shutdown, arginfo_swoole_void)
    PHP_FALIAS(hbcheck, swoole_server_heartbeat, arginfo_swoole_server_heartbeat_oo)
    PHP_FALIAS(heartbeat, swoole_server_heartbeat, arginfo_swoole_server_heartbeat_oo)
    PHP_FALIAS(handler, swoole_server_handler, arginfo_swoole_server_handler_oo)
    PHP_FALIAS(on, swoole_server_on, arginfo_swoole_server_on_oo)
    PHP_FALIAS(connection_info, swoole_connection_info, arginfo_swoole_connection_info_oo)
    PHP_FALIAS(connection_list, swoole_connection_list, arginfo_swoole_connection_list_oo)
    //timer
    PHP_FALIAS(addtimer, swoole_server_addtimer, arginfo_swoole_server_addtimer_oo)
    PHP_FALIAS(deltimer, swoole_timer_del, arginfo_swoole_timer_del)
    PHP_FALIAS(gettimer, swoole_server_gettimer, NULL)
    PHP_FALIAS(after, swoole_timer_after, NULL)
    PHP_FALIAS(tick, swoole_timer_tick, NULL)
    PHP_FALIAS(clearTimer, swoole_timer_clear, NULL)
    //process
    PHP_ME(swoole_server, sendmessage, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, addprocess, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stats, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, bind, arginfo_swoole_server_bind, ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};

#ifdef HAVE_PCRE
static const zend_function_entry swoole_connection_iterator_methods[] =
{
    PHP_ME(swoole_connection_iterator, rewind,      arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, next,        arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, current,     arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, key,         arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, valid,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, count,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
#endif

#if PHP_MEMORY_DEBUG
php_vmstat_t php_vmstat;
#endif

zend_class_entry swoole_server_ce;
zend_class_entry *swoole_server_class_entry_ptr;

zend_class_entry swoole_connection_iterator_ce;
zend_class_entry *swoole_connection_iterator_class_entry_ptr;

zend_module_entry swoole_module_entry =
{
#if ZEND_MODULE_API_NO >= 20050922
    STANDARD_MODULE_HEADER_EX,
    NULL,
    NULL,
#else
    STANDARD_MODULE_HEADER,
#endif
    "swoole",
    swoole_functions,
    PHP_MINIT(swoole),
    PHP_MSHUTDOWN(swoole),
    PHP_RINIT(swoole), //RINIT
    PHP_RSHUTDOWN(swoole), //RSHUTDOWN
    PHP_MINFO(swoole),
    PHP_SWOOLE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SWOOLE
ZEND_GET_MODULE(swoole)
#endif

/* {{{ PHP_INI
 */

PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("swoole.aio_thread_num", "2", PHP_INI_ALL, OnUpdateLong, aio_thread_num, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("swoole.display_errors", "On", PHP_INI_ALL, OnUpdateBool, display_errors, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("swoole.message_queue_key", "0", PHP_INI_ALL, OnUpdateString, message_queue_key, zend_swoole_globals, swoole_globals)
/**
 * Unix socket buffer size
 */
STD_PHP_INI_ENTRY("swoole.unixsock_buffer_size", "8388608", PHP_INI_ALL, OnUpdateLong, socket_buffer_size, zend_swoole_globals, swoole_globals)
PHP_INI_END()

static void php_swoole_init_globals(zend_swoole_globals *swoole_globals)
{
    swoole_globals->message_queue_key = 0;
    swoole_globals->aio_thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    swoole_globals->socket_buffer_size = SW_SOCKET_BUFFER_SIZE;
    swoole_globals->display_errors = 1;
}

void swoole_set_object(zval *object, void *ptr)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    assert(handle < SWOOLE_OBJECT_MAX);
    if (handle >= swoole_objects.size)
    {
        uint32_t old_size = swoole_objects.size;
        uint32_t new_size = old_size * 2;

        void *old_ptr = swoole_objects.array;
        void *new_ptr = NULL;

        if (new_size > SWOOLE_OBJECT_MAX)
        {
            new_size = SWOOLE_OBJECT_MAX;
        }
        new_ptr = erealloc(old_ptr, sizeof(void*) * new_size);
        if (!new_ptr)
        {
            return;
        }
        bzero(new_ptr + (old_size * sizeof(void*)), (new_size - old_size) * sizeof(void*));
        swoole_objects.array = new_ptr;
        swoole_objects.size = new_size;
    }
    swoole_objects.array[handle] = ptr;
}

void swoole_set_property(zval *object, int property_id, void *ptr)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    assert(handle < SWOOLE_OBJECT_MAX);

    if (handle >= swoole_objects.property_size[property_id])
    {
        uint32_t old_size = swoole_objects.property_size[property_id];
        uint32_t new_size = 0;

        void *old_ptr = NULL;
        void *new_ptr = NULL;

        if (old_size == 0)
        {
            new_size = 65536;
            new_ptr = ecalloc(new_size, sizeof(void *));
        }
        else
        {
            new_size = old_size * 2;
            if (new_size > SWOOLE_OBJECT_MAX)
            {
                new_size = SWOOLE_OBJECT_MAX;
            }
            old_ptr = swoole_objects.property[property_id];
            new_ptr = erealloc(old_ptr, new_size * sizeof(void *));
        }
        if (new_ptr == NULL)
        {
            return;
        }
        if (old_size > 0)
        {
            bzero(new_ptr + old_size * sizeof(void*), (new_size - old_size) * sizeof(void*));
        }
        swoole_objects.property_size[property_id] = new_size;
        swoole_objects.property[property_id] = new_ptr;
    }
    swoole_objects.property[property_id][handle] = ptr;
}

#ifdef ZTS
__thread swoole_object_array swoole_objects;
void ***sw_thread_ctx;
#else
swoole_object_array swoole_objects;
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(swoole)
{
    ZEND_INIT_MODULE_GLOBALS(swoole, php_swoole_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    /**
     * mode type
     */
    REGISTER_LONG_CONSTANT("SWOOLE_BASE", SW_MODE_SINGLE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_THREAD", SW_MODE_THREAD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", SW_MODE_PROCESS, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_PACKET", SW_MODE_PACKET, CONST_CS | CONST_PERSISTENT);

    /**
     * ipc mode
     */
    REGISTER_LONG_CONSTANT("SWOOLE_IPC_UNSOCK", SW_IPC_UNSOCK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_IPC_MSGQUEUE", SW_IPC_MSGQUEUE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_IPC_CHANNEL", SW_IPC_CHANNEL, CONST_CS | CONST_PERSISTENT);

    /**
     * socket type
     */
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_STREAM", SW_SOCK_UNIX_STREAM, CONST_CS | CONST_PERSISTENT);

    /**
     * simple api
     */
    REGISTER_LONG_CONSTANT("SWOOLE_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UNIX_STREAM", SW_SOCK_UNIX_STREAM, CONST_CS | CONST_PERSISTENT);

    /**
     * simple api
     */
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_SYNC", SW_SOCK_SYNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_ASYNC", SW_SOCK_ASYNC, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("SWOOLE_SYNC", SW_FLAG_SYNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_ASYNC", SW_FLAG_ASYNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_KEEP", SW_FLAG_KEEP, CONST_CS | CONST_PERSISTENT);

#ifdef SW_USE_OPENSSL
    REGISTER_LONG_CONSTANT("SWOOLE_SSL", SW_SOCK_SSL, CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("SWOOLE_EVENT_READ", SW_EVENT_READ, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_EVENT_WRITE", SW_EVENT_WRITE, CONST_CS | CONST_PERSISTENT);

    REGISTER_STRINGL_CONSTANT("SWOOLE_VERSION", PHP_SWOOLE_VERSION, sizeof(PHP_SWOOLE_VERSION) - 1, CONST_CS | CONST_PERSISTENT);

    INIT_CLASS_ENTRY(swoole_server_ce, "swoole_server", swoole_server_methods);
    swoole_server_class_entry_ptr = zend_register_internal_class(&swoole_server_ce TSRMLS_CC);

#ifdef HAVE_PCRE
    INIT_CLASS_ENTRY(swoole_connection_iterator_ce, "swoole_connection_iterator", swoole_connection_iterator_methods);
    swoole_connection_iterator_class_entry_ptr = zend_register_internal_class(&swoole_connection_iterator_ce TSRMLS_CC);
    zend_class_implements(swoole_connection_iterator_class_entry_ptr TSRMLS_CC, 2, spl_ce_Iterator, spl_ce_Countable);
#endif

    //swoole init
    swoole_init();

    swoole_client_init(module_number TSRMLS_CC);
    swoole_async_init(module_number TSRMLS_CC);
    swoole_process_init(module_number TSRMLS_CC);
    swoole_table_init(module_number TSRMLS_CC);
    swoole_lock_init(module_number TSRMLS_CC);
    swoole_atomic_init(module_number TSRMLS_CC);
    swoole_http_init(module_number TSRMLS_CC);
    swoole_buffer_init(module_number TSRMLS_CC);
    swoole_websocket_init(module_number TSRMLS_CC);

    if (SWOOLE_G(socket_buffer_size) > 0)
    {
        SwooleG.socket_buffer_size = SWOOLE_G(socket_buffer_size);
    }
    if (SWOOLE_G(aio_thread_num) > 0)
    {
        if (SWOOLE_G(aio_thread_num) > SW_AIO_THREAD_NUM_MAX)
        {
            SWOOLE_G(aio_thread_num) = SW_AIO_THREAD_NUM_MAX;
        }
        SwooleAIO.thread_num = SWOOLE_G(aio_thread_num);
    }
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(swoole)
{
    if (SwooleWG.in_client && SwooleG.main_reactor)
    {
        sw_free(SwooleG.main_reactor);
    }
    if (SwooleG.serv)
    {
        sw_free(SwooleG.serv);
    }
    swoole_clean();
    return SUCCESS;
}
/* }}} */


/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(swoole)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "swoole support", "enabled");
    php_info_print_table_row(2, "Version", PHP_SWOOLE_VERSION);
    php_info_print_table_row(2, "Author", "tianfeng.han[email: mikan.tenny@gmail.com]");

#ifdef HAVE_EPOLL
    php_info_print_table_row(2, "epoll", "enabled");
#endif
#ifdef HAVE_EVENTFD
    php_info_print_table_row(2, "eventfd", "enabled");
#endif
#ifdef HAVE_KQUEUE
    php_info_print_table_row(2, "kqueue", "enabled");
#endif
#ifdef HAVE_TIMERFD
    php_info_print_table_row(2, "timerfd", "enabled");
#endif
#ifdef HAVE_SIGNALFD
    php_info_print_table_row(2, "signalfd", "enabled");
#endif
#ifdef SW_USE_ACCEPT4
    php_info_print_table_row(2, "accept4", "enabled");
#endif
#ifdef HAVE_CPU_AFFINITY
    php_info_print_table_row(2, "cpu affinity", "enabled");
#endif
#ifdef HAVE_SPINLOCK
    php_info_print_table_row(2, "spinlock", "enabled");
#endif
#ifdef HAVE_RWLOCK
    php_info_print_table_row(2, "rwlock", "enabled");
#endif
#ifdef SW_ASYNC_MYSQL
    php_info_print_table_row(2, "async mysql", "enabled");
#endif
#ifdef SW_SOCKETS
    php_info_print_table_row(2, "sockets", "enabled");
#endif
#ifdef SW_USE_OPENSSL
    php_info_print_table_row(2, "openssl", "enabled");
#endif
#ifdef SW_USE_RINGBUFFER
    php_info_print_table_row(2, "ringbuffer", "enabled");
#endif
#ifdef HAVE_LINUX_AIO
    php_info_print_table_row(2, "Linux Native AIO", "enabled");
#endif
#ifdef HAVE_GCC_AIO
    php_info_print_table_row(2, "Gcc AIO", "enabled");
#endif
#ifdef HAVE_PCRE
    php_info_print_table_row(2, "pcre", "enabled");
#endif
#ifdef SW_HAVE_ZLIB
    php_info_print_table_row(2, "zlib", "enabled");
#endif
#ifdef HAVE_MUTEX_TIMEDLOCK
    php_info_print_table_row(2, "mutex_timedlock", "enabled");
#endif
#ifdef HAVE_PTHREAD_BARRIER
    php_info_print_table_row(2, "pthread_barrier", "enabled");
#endif

    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */

PHP_RINIT_FUNCTION(swoole)
{
    //running
    SwooleG.running = 1;

#ifdef ZTS
    if (sw_thread_ctx == NULL)
    {
        TSRMLS_SET_CTX(sw_thread_ctx);
    }
#endif

    if (strcasecmp("cli", sapi_module.name) == 0)
    {
        SWOOLE_G(cli) = 1;
    }

    swoole_objects.size = 65536;
    swoole_objects.array = ecalloc(swoole_objects.size, sizeof(void*));

#ifdef SW_DEBUG_REMOTE_OPEN
    swoole_open_remote_debug();
#endif

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(swoole)
{
    int i;
    for (i = 0; i < PHP_SERVER_CALLBACK_NUM; i++)
    {
        if (php_sw_callback[i] != NULL)
        {
            zval_dtor(php_sw_callback[i]);
            efree(php_sw_callback[i]);
        }
    }

    //clear pipe buffer
    if (swIsWorker())
    {
        swWorker_clean();
    }

    if (SwooleGS->start > 0 && SwooleG.running > 0)
    {
        if (PG(last_error_message))
        {
            switch(PG(last_error_type))
            {
            case E_ERROR:
            case E_CORE_ERROR:
            case E_USER_ERROR:
            case E_COMPILE_ERROR:
                swWarn("Fatal error: %s in %s on line %d.", PG(last_error_message),
                        PG(last_error_file)?PG(last_error_file):"-", PG(last_error_lineno));
                break;
            default:
                break;
            }
        }
        else
        {
            swWarn("worker process is terminated by exit()/die().");
        }
    }

    for(i = 0; i< SWOOLE_PROPERTY_MAX; i ++)
    {
        if (swoole_objects.property[i])
        {
            efree(swoole_objects.property[i]);
        }
    }

    efree(swoole_objects.array);
    bzero(&swoole_objects, sizeof(swoole_objects));

    SwooleWG.reactor_wait_onexit = 0;

    return SUCCESS;
}

PHP_FUNCTION(swoole_version)
{
    char swoole_version[32] = {0};
    snprintf(swoole_version, sizeof(PHP_SWOOLE_VERSION), "%s", PHP_SWOOLE_VERSION);
    SW_RETURN_STRING(swoole_version, 1);
}

PHP_FUNCTION(swoole_cpu_num)
{
    long cpu_num = 1;
    cpu_num = sysconf(_SC_NPROCESSORS_CONF);
    if(cpu_num < 1)
    {
        cpu_num = 1;
    }
    RETURN_LONG(cpu_num);
}

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock)
{
    MY_MYSQL *mysql;
    zval *mysql_link;
    php_stream *stream;
    int sock;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &mysql_link) == FAILURE)
    {
        return;
    }

#if PHP_MAJOR_VERSION > 5
    MYSQLI_FETCH_RESOURCE_CONN(mysql, mysql_link, MYSQLI_STATUS_VALID);
    stream = mysql->mysql->data->net->data->m.get_stream(mysql->mysql->data->net TSRMLS_CC);
#elif PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 4
    MYSQLI_FETCH_RESOURCE_CONN(mysql, &mysql_link, MYSQLI_STATUS_VALID);
    stream = mysql->mysql->data->net->data->m.get_stream(mysql->mysql->data->net TSRMLS_CC);
#else
    stream = mysql->mysql->data->net->stream;
#endif

    if (SUCCESS != php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&sock, 1)
            && sock >= 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(sock);
    }
}
#endif

PHP_FUNCTION(swoole_strerror)
{
    int swoole_errno = 0;
    char error_msg[256] = {0};

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &swoole_errno) == FAILURE)
    {
        return;
    }
    snprintf(error_msg, sizeof(error_msg) - 1, "%s", strerror(swoole_errno));
    SW_RETURN_STRING(error_msg, 1);
}

PHP_FUNCTION(swoole_errno)
{
    RETURN_LONG(errno);
}

PHP_FUNCTION(swoole_set_process_name)
{
    zval *name;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &name) == FAILURE)
    {
        return;
    }

    if (Z_STRLEN_P(name) == 0)
    {
        return;
    }
    else if (Z_STRLEN_P(name) > 127)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "process name is too long,the max len is 127");
    }

#if PHP_MAJOR_VERSION >= 7 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 4)
    zval *retval;
    zval **args[1];
    args[0] = &name;

    zval *function;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function, "cli_set_process_title", 1);

    if (sw_call_user_function_ex(EG(function_table), NULL, function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        return;
    }

    sw_zval_ptr_dtor(&function);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
#else
    bzero(sapi_module.executable_location, 127);
    memcpy(sapi_module.executable_location, Z_STRVAL_P(name), Z_STRLEN_P(name));
#endif

}

PHP_FUNCTION(swoole_get_local_ip)
{
    struct sockaddr_in *s4;
    struct ifaddrs *ipaddrs, *ifa;
    void *in_addr;
    char ip[64];

    if (getifaddrs(&ipaddrs) != 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "getifaddrs() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    array_init(return_value);
    for (ifa = ipaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP))
        {
            continue;
        }

        switch (ifa->ifa_addr->sa_family)
        {
            case AF_INET:
                s4 = (struct sockaddr_in *)ifa->ifa_addr;
                in_addr = &s4->sin_addr;
                break;
            case AF_INET6:
                //struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                //in_addr = &s6->sin6_addr;
                continue;
            default:
                continue;
        }
        if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, ip, sizeof(ip)))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s: inet_ntop failed.", ifa->ifa_name);
        }
        else
        {
            //if (ifa->ifa_addr->sa_family == AF_INET && ntohl(((struct in_addr *) in_addr)->s_addr) == INADDR_LOOPBACK)
            if (strcmp(ip, "127.0.0.1") == 0)
            {
                continue;
            }
            sw_add_assoc_string(return_value, ifa->ifa_name, ip, 1);
        }
    }
    freeifaddrs(ipaddrs);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
