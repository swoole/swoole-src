ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server__construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, server_socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendwait, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_protect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, is_protected)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, server_socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_pause, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

#ifdef SWOOLE_SOCKETS_SUPPORT
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getSocket, 0, 0, 0)
    ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getCallback, 0, 0, 1)
    ZEND_ARG_INFO(0, event_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_listen, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, worker_id)
    ZEND_ARG_CALLABLE_INFO(0, finish_callback, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskCo, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, tasks, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskWaitMulti, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, tasks, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task_pack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload, 0, 0, 0)
    ZEND_ARG_INFO(0, only_reload_taskworker)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat, 0, 0, 1)
    ZEND_ARG_INFO(0, ifCloseConnection)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_stop, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
    ZEND_ARG_INFO(0, waitEvent)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_bind, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendMessage, 0, 0, 2)
    ZEND_ARG_INFO(0, message)
    ZEND_ARG_INFO(0, dst_worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_command, 0, 0, 4)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, process_id)
    ZEND_ARG_INFO(0, process_type)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, json_encode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addProcess, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, process, swoole_process, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addCommand, 0, 0, 3)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, accepted_process_types)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientInfo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reactor_id)
    ZEND_ARG_INFO(0, ignoreError)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getWorkerStatus, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getWorkerPid, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientList, 0, 0, 1)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

//arginfo connection_iterator
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_rewind, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_next, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_current, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_key, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_valid, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetExists, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetGet, 0, 1, IS_MIXED, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetUnset, 0, 1, IS_VOID, 0)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_connection_iterator_offsetSet, 0, 2, IS_VOID, 0)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Server___construct arginfo_swoole_server__construct
#define arginfo_class_Swoole_Server___destruct arginfo_swoole_void
#define arginfo_class_Swoole_Server_listen arginfo_swoole_server_listen
#define arginfo_class_Swoole_Server_on arginfo_swoole_server_on
#define arginfo_class_Swoole_Server_getCallback arginfo_swoole_server_getCallback
#define arginfo_class_Swoole_Server_set arginfo_swoole_server_set
#define arginfo_class_Swoole_Server_start arginfo_swoole_void
#define arginfo_class_Swoole_Server_send arginfo_swoole_server_send
#define arginfo_class_Swoole_Server_sendto arginfo_swoole_server_sendto
#define arginfo_class_Swoole_Server_sendwait arginfo_swoole_server_sendwait
#define arginfo_class_Swoole_Server_exists arginfo_swoole_server_exists
#define arginfo_class_Swoole_Server_protect arginfo_swoole_server_protect
#define arginfo_class_Swoole_Server_sendfile arginfo_swoole_server_sendfile
#define arginfo_class_Swoole_Server_close arginfo_swoole_server_close
#define arginfo_class_Swoole_Server_resume arginfo_swoole_server_resume
#define arginfo_class_Swoole_Server_pause arginfo_swoole_server_pause
#define arginfo_class_Swoole_Server_task arginfo_swoole_server_task
#define arginfo_class_Swoole_Server_taskwait arginfo_swoole_server_taskwait
#define arginfo_class_Swoole_Server_taskWaitMulti arginfo_swoole_server_taskWaitMulti
#define arginfo_class_Swoole_Server_taskCo arginfo_swoole_server_taskCo
#define arginfo_class_Swoole_Server_finish arginfo_swoole_server_finish
#define arginfo_class_Swoole_Server_reload arginfo_swoole_server_reload
#define arginfo_class_Swoole_Server_shutdown arginfo_swoole_void
#define arginfo_class_Swoole_Server_stop arginfo_swoole_server_stop
#define arginfo_class_Swoole_Server_getLastError arginfo_swoole_void
#define arginfo_class_Swoole_Server_heartbeat arginfo_swoole_server_heartbeat
#define arginfo_class_Swoole_Server_getClientInfo arginfo_swoole_server_getClientInfo
#define arginfo_class_Swoole_Server_getClientList arginfo_swoole_server_getClientList
#define arginfo_class_Swoole_Server_getWorkerId arginfo_swoole_void
#define arginfo_class_Swoole_Server_getWorkerPid arginfo_swoole_server_getWorkerPid
#define arginfo_class_Swoole_Server_getWorkerStatus arginfo_swoole_server_getWorkerStatus
#define arginfo_class_Swoole_Server_getManagerPid arginfo_swoole_void
#define arginfo_class_Swoole_Server_getMasterPid arginfo_swoole_void
#define arginfo_class_Swoole_Server_sendMessage arginfo_swoole_server_sendMessage
#define arginfo_class_Swoole_Server_command arginfo_swoole_server_command
#define arginfo_class_Swoole_Server_addCommand arginfo_swoole_server_addCommand
#define arginfo_class_Swoole_Server_addProcess arginfo_swoole_server_addProcess
#define arginfo_class_Swoole_Server_stats arginfo_swoole_void

#ifdef SWOOLE_SOCKETS_SUPPORT
#define arginfo_class_Swoole_Server_getSocket arginfo_swoole_server_getSocket
#endif

#define arginfo_class_Swoole_Server_bind arginfo_swoole_server_bind
#define arginfo_class_Swoole_Connection_Iterator___construct arginfo_swoole_void
#define arginfo_class_Swoole_Connection_Iterator___destruct arginfo_swoole_void
#define arginfo_class_Swoole_Connection_Iterator_rewind arginfo_swoole_connection_iterator_rewind
#define arginfo_class_Swoole_Connection_Iterator_next arginfo_swoole_connection_iterator_next
#define arginfo_class_Swoole_Connection_Iterator_current arginfo_swoole_connection_iterator_current
#define arginfo_class_Swoole_Connection_Iterator_key arginfo_swoole_connection_iterator_key
#define arginfo_class_Swoole_Connection_Iterator_valid arginfo_swoole_connection_iterator_valid
#define arginfo_class_Swoole_Connection_Iterator_count arginfo_swoole_connection_iterator_count
#define arginfo_class_Swoole_Connection_Iterator_offsetExists arginfo_swoole_connection_iterator_offsetExists
#define arginfo_class_Swoole_Connection_Iterator_offsetGet arginfo_swoole_connection_iterator_offsetGet
#define arginfo_class_Swoole_Connection_Iterator_offsetSet arginfo_swoole_connection_iterator_offsetSet
#define arginfo_class_Swoole_Connection_Iterator_offsetUnset arginfo_swoole_connection_iterator_offsetUnset
#define arginfo_class_Swoole_Server_Task_finish arginfo_swoole_server_finish
#define arginfo_class_Swoole_Server_Task_pack arginfo_swoole_server_task_pack
