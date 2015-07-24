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

#include "php_swoole.h"

#include "Connection.h"

#include "ext/standard/php_var.h"
#if PHP_MAJOR_VERSION < 7
#include "ext/standard/php_smart_str.h"
#else
#include "zend_smart_str.h"
#endif

static int php_swoole_task_id;
static int udp_server_socket;
static int dgram_server_socket;

zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

static int php_swoole_task_finish(swServer *serv, zval *data TSRMLS_DC);
static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC);
static int php_swoole_onReceive(swServer *, swEventData *);
static int php_swoole_onPacket(swServer *, swEventData *);
static void php_swoole_onPipeMessage(swServer *serv, swEventData *req);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onConnect(swServer *, int fd, int from_id);
static void php_swoole_onTimer(swServer *serv, int interval);
static void php_swoole_onWorkerStart(swServer *, int worker_id);
static void php_swoole_onWorkerStop(swServer *, int worker_id);
static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker);
static int php_swoole_onTask(swServer *, swEventData *task);
static int php_swoole_onFinish(swServer *, swEventData *task);
static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code);
static void php_swoole_onManagerStart(swServer *serv);
static void php_swoole_onManagerStop(swServer *serv);
static zval* php_swoole_get_task_result(swEventData *task_result TSRMLS_DC);

zval *php_swoole_get_recv_data(zval *zdata, swEventData *req TSRMLS_DC)
{
    char *data_ptr = NULL;
    int data_len;

#ifdef SW_USE_RINGBUFFER
    swPackage package;
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        memcpy(&package, req->data, sizeof (package));

        data_ptr = package.data;
        data_len = package.length;
    }
#else
    if (req->info.type == SW_EVENT_PACKAGE_END)
    {
        data_ptr = SwooleWG.buffer_input[req->info.from_id]->str;
        data_len = SwooleWG.buffer_input[req->info.from_id]->length;
    }
#endif
    else
    {
        data_ptr = req->data;
        data_len = req->info.len;
    }

    //add by andy
    if (SwooleG.serv->packet_mode == 1)
    {
        SW_ZVAL_STRINGL(zdata, data_ptr + 4, data_len - 4, 1);
    }
    else
    {
        SW_ZVAL_STRINGL(zdata, data_ptr, data_len, 1);
    }

#ifdef SW_USE_RINGBUFFER
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        swReactorThread *thread = swServer_get_thread(SwooleG.serv, req->info.from_id);
        thread->buffer_input->free(thread->buffer_input, data_ptr);
    }
#endif
    return zdata;
}

int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC)
{
    int length;

    if (SW_Z_TYPE_P(zdata) == IS_OBJECT)
    {
        if (!instanceof_function(Z_OBJCE_P(zdata), swoole_buffer_class_entry_ptr TSRMLS_CC))
        {
            goto convert;
        }
        swString *str_buffer = swoole_get_object(zdata);
        if (!str_buffer->str)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_buffer object is empty.");
            return SW_ERR;
        }
        length = str_buffer->length - str_buffer->offset;
        *str = str_buffer->str + str_buffer->offset;
    }
    else
    {
        convert:
        convert_to_string(zdata);
        length = Z_STRLEN_P(zdata);
        *str = Z_STRVAL_P(zdata);
    }

    if (length >= SwooleG.serv->buffer_output_size)
    {
        swoole_php_fatal_error(E_WARNING, "send data max_size is %d.", SwooleG.serv->buffer_output_size);
        return SW_ERR;
    }

    return length;
}

static zval* php_swoole_get_task_result(swEventData *task_result TSRMLS_DC)
{
    zval *task_notify_data, *task_notify_unserialized_data;
    char *task_notify_data_str;
    int task_notify_data_len = 0;
    php_unserialize_data_t var_hash;

    /**
     * Large result package
     */
    if (swTask_type(task_result) & SW_TASK_TMPFILE)
    {
        int data_len;
        char *data_str = NULL;
        swTaskWorker_large_unpack(task_result, emalloc, data_str, data_len);
        /**
         * unpack failed
         */
        if (data_len == -1)
        {
            if (data_str)
            {
                efree(data_str);
            }
            return NULL;
        }
        task_notify_data_str = data_str;
        task_notify_data_len = data_len;
    }
    else
    {
        task_notify_data_str = task_result->data;
        task_notify_data_len = task_result->info.len;
    }

    if (swTask_type(task_result) & SW_TASK_SERIALIZE)
    {
        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        SW_ALLOC_INIT_ZVAL(task_notify_unserialized_data);

        if (sw_php_var_unserialize(&task_notify_unserialized_data, (const unsigned char **) &task_notify_data_str,
                (const unsigned char *) (task_notify_data_str + task_notify_data_len), &var_hash TSRMLS_CC))
        {
            task_notify_data = task_notify_unserialized_data;
        }
        else
        {
            SW_MAKE_STD_ZVAL(task_notify_data);
            SW_ZVAL_STRINGL(task_notify_data, task_notify_data_str, task_notify_data_len, 1);
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    }
    else
    {
        SW_MAKE_STD_ZVAL(task_notify_data);
        SW_ZVAL_STRINGL(task_notify_data, task_notify_data_str, task_notify_data_len, 1);
    }
    return task_notify_data;
}

void php_swoole_register_callback(swServer *serv)
{
    /*
     * optional callback
     */
    if (php_sw_callback[SW_SERVER_CB_onStart] != NULL)
    {
        serv->onStart = php_swoole_onStart;
    }
    serv->onShutdown = php_swoole_onShutdown;
    /**
     * require callback, set the master/manager/worker PID
     */
    serv->onWorkerStart = php_swoole_onWorkerStart;

    if (php_sw_callback[SW_SERVER_CB_onWorkerStop] != NULL)
    {
        serv->onWorkerStop = php_swoole_onWorkerStop;
    }
    if (php_sw_callback[SW_SERVER_CB_onTask] != NULL)
    {
        serv->onTask = php_swoole_onTask;
    }
    if (php_sw_callback[SW_SERVER_CB_onFinish] != NULL)
    {
        serv->onFinish = php_swoole_onFinish;
    }
    if (php_sw_callback[SW_SERVER_CB_onWorkerError] != NULL)
    {
        serv->onWorkerError = php_swoole_onWorkerError;
    }
    if (php_sw_callback[SW_SERVER_CB_onManagerStart] != NULL)
    {
        serv->onManagerStart = php_swoole_onManagerStart;
    }
    if (php_sw_callback[SW_SERVER_CB_onManagerStop] != NULL)
    {
        serv->onManagerStop = php_swoole_onManagerStop;
    }
    if (php_sw_callback[SW_SERVER_CB_onPipeMessage] != NULL)
    {
        serv->onPipeMessage = php_swoole_onPipeMessage;
    }
    //-------------------------------------------------------------
    if (php_sw_callback[SW_SERVER_CB_onTimer] != NULL)
    {
        serv->onTimer = php_swoole_onTimer;
    }
    if (php_sw_callback[SW_SERVER_CB_onClose] != NULL)
    {
        serv->onClose = php_swoole_onClose;
    }
    if (php_sw_callback[SW_SERVER_CB_onConnect] != NULL)
    {
        serv->onConnect = php_swoole_onConnect;
    }
    if (php_sw_callback[SW_SERVER_CB_onPacket] != NULL)
    {
        serv->onPacket = php_swoole_onPacket;
    }
}

static int php_swoole_task_finish(swServer *serv, zval *data TSRMLS_DC)
{
    int flags = 0;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;
    char *data_str;
    int data_len = 0;
    int ret;

    //need serialize
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        flags |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
#if PHP_MAJOR_VERSION<7
        data_str = serialized_data.c;
        data_len = serialized_data.len;
#else
        data_str = serialized_data.s->val;
        data_len = serialized_data.s->len;
#endif
    }
    else
    {
        data_str = Z_STRVAL_P(data);
        data_len = Z_STRLEN_P(data);
    }

    ret = swTaskWorker_finish(serv, data_str, data_len, flags);

    smart_str_free(&serialized_data);
    return ret;
}

static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC)
{

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!sw_zend_is_callable(cb, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_ERR;
    }
    efree(func_name);
#endif

    //sw_zval_add_ref(&cb);
    php_sw_callback[key] = emalloc(sizeof (zval));
    if (php_sw_callback[key] == NULL)
    {
        return SW_ERR;
    }

    *(php_sw_callback[key]) = *cb;
    zval_copy_ctor(php_sw_callback[key]);

    return SW_OK;
}

static void php_swoole_onPipeMessage(swServer *serv, swEventData *req)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;
    zval *zdata;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    SW_MAKE_STD_ZVAL(zdata);

    zval **args[3];

    ZVAL_LONG(zworker_id, (long) req->info.from_id);

    if (swTask_type(req) & SW_TASK_TMPFILE)
    {
        int data_len;
        char *buf = NULL;
        swTaskWorker_large_unpack(req, emalloc, buf, data_len);

        /**
         * unpack failed
         */
        if (data_len == -1)
        {
            if (buf)
            {
                efree(buf);
            }
            return;
        }
        SW_ZVAL_STRINGL(zdata, buf, data_len, 0);
    }
    else
    {
        SW_ZVAL_STRINGL(zdata, req->data, req->info.len, 1);
    }

    args[0] = &zserv;
    args[1] = &zworker_id;
    args[2] = &zdata;

    swTrace("PipeMessage: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onPipeMessage], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onPipeMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zworker_id);
    sw_zval_ptr_dtor(&zdata);

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static int php_swoole_onReceive(swServer *serv, swEventData *req)
{
    swFactory *factory = &serv->factory;
    zval *zserv = (zval *) serv->ptr2;
    zval **args[4];

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    //UDP使用from_id作为port,fd做为ip
    php_swoole_udp_t udp_info;

    SW_MAKE_STD_ZVAL(zfd);
    SW_MAKE_STD_ZVAL(zfrom_id);
    SW_MAKE_STD_ZVAL(zdata);

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        udp_info.from_fd = req->info.from_fd;
        udp_info.port = req->info.from_id;
        memcpy(&udp_server_socket, &udp_info, sizeof(udp_server_socket));
        factory->last_from_id = udp_server_socket;
        swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);

        ZVAL_LONG(zfrom_id, (long ) udp_server_socket);
        ZVAL_LONG(zfd, (long ) req->info.fd);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        udp_info.from_fd = req->info.from_fd;
        udp_info.port = req->info.from_id;
        memcpy(&dgram_server_socket, &udp_info, sizeof(udp_server_socket));
        factory->last_from_id = dgram_server_socket;

        swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);

        uint16_t ipv6_addr_offset = req->info.fd;
        ZVAL_LONG(zfrom_id, (long ) dgram_server_socket);
        req->info.len = ipv6_addr_offset;
        char tmp[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, req->data + ipv6_addr_offset, tmp, sizeof(tmp));
        SW_ZVAL_STRING(zfd, tmp, 1);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        uint16_t sun_path_offset = req->info.fd;
        SW_ZVAL_STRING(zfd, req->data + sun_path_offset, 1);
        req->info.len -= (Z_STRLEN_P(zfd) + 1);
        ZVAL_LONG(zfrom_id, (long ) req->info.from_fd);
        dgram_server_socket = req->info.from_fd;
    }
    else
    {
        ZVAL_LONG(zfrom_id, (long ) req->info.from_id);
        ZVAL_LONG(zfd, (long ) req->info.fd);
    }

    zdata = php_swoole_get_recv_data(zdata, req TSRMLS_CC);

    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    //printf("req: fd=%d|len=%d|from_id=%d|data=%s\n", req->fd, req->len, req->from_id, req->data);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onReceive], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onReceive handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_onPacket(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[3];

    zval *zdata;
    zval *zaddr;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    SW_MAKE_STD_ZVAL(zdata);
    SW_MAKE_STD_ZVAL(zaddr);
    array_init(zaddr);

    add_assoc_long(zaddr, "port", (uint16_t) req->info.from_id);
    add_assoc_long(zaddr, "server_socket", req->info.from_fd);

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        struct in_addr sin_addr;
        sin_addr.s_addr = req->info.fd;
        char *address = inet_ntoa(sin_addr);
        sw_add_assoc_string(zaddr, "address", address, 1);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        char tmp[INET6_ADDRSTRLEN];
        uint16_t ipv6_addr_offset = req->info.fd;
        inet_ntop(AF_INET6, req->data + ipv6_addr_offset, tmp, sizeof(tmp));
        req->info.len = ipv6_addr_offset;
        sw_add_assoc_string(zaddr, "address", tmp, 1);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        struct sockaddr_un un_address;
        uint16_t sun_path_offset = req->info.fd;
        int len = strlen(req->data + sun_path_offset);
        memcpy(&un_address.sun_path, req->data + sun_path_offset, len);
        sw_add_assoc_string(zaddr, "address", un_address.sun_path, 1);
        req->info.len -= (len + 1);
    }

    zdata = php_swoole_get_recv_data(zdata, req TSRMLS_CC);

    args[0] = &zserv;
    args[1] = &zdata;
    args[2] = &zaddr;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onPacket], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onPacket handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zaddr);
    sw_zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_onTask(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[4];

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;

    char *zdata_str;
    int zdata_len;
    zval *unserialized_zdata = NULL;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, (long) req->info.fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, (long) req->info.from_id);

    SW_MAKE_STD_ZVAL(zdata);

    if (swTask_type(req) & SW_TASK_TMPFILE)
    {
        int data_len;
        char *buf = NULL;

        swTaskWorker_large_unpack(req, emalloc, buf, data_len);

        /**
         * unpack failed
         */
        if (data_len == -1)
        {
            if (buf)
            {
                efree(buf);
            }
            return SW_OK;
        }
        SW_ZVAL_STRINGL(zdata, buf, data_len, 0);
    }
    else
    {
        SW_ZVAL_STRINGL(zdata, req->data, req->info.len, 1);
    }

    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    //TODO unserialize
    if (swTask_type(req) & SW_TASK_SERIALIZE)
    {
        php_unserialize_data_t var_hash;

        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        zdata_str = Z_STRVAL_P(zdata);
        zdata_len = Z_STRLEN_P(zdata);
        SW_ALLOC_INIT_ZVAL(unserialized_zdata);

        if (sw_php_var_unserialize(&unserialized_zdata, (const unsigned char **) &zdata_str,
                (const unsigned char *) (zdata_str + zdata_len), &var_hash TSRMLS_CC))
        {
            args[3] = &unserialized_zdata;
        }
        else
        {
            args[3] = &zdata;
        }
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    }
    else
    {
        args[3] = &zdata;
    }

    // php_printf("task: fd=%d|len=%d|from_id=%d|data=%s\r\n", req->info.fd, req->info.len, req->info.from_id, req->data);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTask], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTask handler error");
    }

    if (EG(exception))
    {
        sw_atomic_fetch_sub(&SwooleStats->tasking_num, 1);
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_ptr_dtor(&zdata);

    if (unserialized_zdata)
    {
        sw_zval_ptr_dtor(&unserialized_zdata);
    }

    if (retval != NULL && SW_Z_TYPE_P(retval) != IS_NULL)
    {
        php_swoole_task_finish(serv, retval TSRMLS_CC);
        sw_zval_ptr_dtor(&retval);
    }
    sw_atomic_fetch_sub(&SwooleStats->tasking_num, 1);
    return SW_OK;
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[3];

    zval *ztask_id;
    zval *zdata;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    SW_MAKE_STD_ZVAL(ztask_id);
    ZVAL_LONG(ztask_id, (long) req->info.fd);

    zdata = php_swoole_get_task_result(req TSRMLS_CC);

    args[0] = &zserv;
    args[1] = &ztask_id;
    args[2] = &zdata;

    //swTraceLog(60, "req: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onFinish], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onFinish handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&ztask_id);
    sw_zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static void php_swoole_onStart(swServer *serv)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zserv = (zval *) serv->ptr2;
    zval **args[1];
    zval *retval = NULL;

    pid_t manager_pid = serv->factory_mode == SW_MODE_PROCESS ? SwooleGS->manager_pid : 0;

    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), SwooleGS->master_pid TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), manager_pid TSRMLS_CC);

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onManagerStart(swServer *serv)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zserv = (zval *) serv->ptr2;
    zval **args[1];
    zval *retval = NULL;

    pid_t manager_pid = serv->factory_mode == SW_MODE_PROCESS ? SwooleGS->manager_pid : 0;

    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), SwooleGS->master_pid TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), manager_pid TSRMLS_CC);

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onManagerStop(swServer *serv)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zserv = (zval *) serv->ptr2;
    zval **args[1];
    zval *retval = NULL;

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStop], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStop handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onTimer(swServer *serv, int interval)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[2];
    zval *retval = NULL;
    zval *zinterval;

    SW_MAKE_STD_ZVAL(zinterval);
    ZVAL_LONG(zinterval, interval);

    args[0] = &zserv;
    args[1] = &zinterval;
    sw_zval_add_ref(&zserv);

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTimer], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTimer handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zinterval);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onShutdown(swServer *serv)
{
    zval *zserv = (zval *) serv->ptr2;
    zval **args[1];
    zval *retval = NULL;

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (php_sw_callback[SW_SERVER_CB_onShutdown] != NULL)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onShutdown], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onShutdown handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
#ifdef HAVE_PCRE
    zval *connection_iterator_object = sw_zend_read_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("connections"), 0 TSRMLS_CC);
    if (connection_iterator_object && !ZVAL_IS_NULL(connection_iterator_object))
    {
        sw_zval_ptr_dtor(&connection_iterator_object);
    }
#endif
}

static void php_swoole_onWorkerStart(swServer *serv, int worker_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;
    zval **args[2];
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);
    args[1] = &zworker_id;

    /**
     * Manager Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), SwooleGS->manager_pid TSRMLS_CC);

    /**
     * Worker ID
     */
    zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_id"), zworker_id TSRMLS_CC);

    /**
     * Is a task worker?
     */
    if (worker_id >= serv->worker_num)
    {
        zend_update_property_bool(swoole_server_class_entry_ptr, zserv, ZEND_STRL("taskworker"), 1 TSRMLS_CC);
    }
    else
    {
        zend_update_property_bool(swoole_server_class_entry_ptr, zserv, ZEND_STRL("taskworker"), 0 TSRMLS_CC);
    }

    /**
     * Worker Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_pid"), getpid() TSRMLS_CC);

    sw_zval_ptr_dtor(&zworker_id);

    /**
     * Have not set the event callback
     */
    if (php_sw_callback[SW_SERVER_CB_onWorkerStart] == NULL)
    {
        return;
    }

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStart], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onWorkerStop(swServer *serv, int worker_id)
{
    if (SwooleWG.shutdown)
    {
        return;
    }
    SwooleWG.shutdown = 1;

    zval *zobject = (zval *) serv->ptr2;
    zval *zworker_id;
    zval **args[2]; //这里必须与下面的数字对应
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    sw_zval_add_ref(&zobject);

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    args[0] = &zobject;
    args[1] = &zworker_id;
    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStop], &retval, 2, args, 0,
            NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStop handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zworker_id);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *object = worker->ptr;
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("id"), SwooleWG.id TSRMLS_CC);

    php_swoole_process_start(worker, object TSRMLS_CC);
}

static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code)
{
    zval *zobject = (zval *) serv->ptr2;
    zval *zworker_id, *zworker_pid, *zexit_code;
    zval **args[4];
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    SW_MAKE_STD_ZVAL(zworker_pid);
    ZVAL_LONG(zworker_pid, worker_pid);

    SW_MAKE_STD_ZVAL(zexit_code);
    ZVAL_LONG(zexit_code, exit_code);

    sw_zval_add_ref(&zobject);

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    args[0] = &zobject;
    args[1] = &zworker_id;
    args[2] = &zworker_pid;
    args[3] = &zexit_code;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerError], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerError handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zworker_id);
    sw_zval_ptr_dtor(&zworker_pid);
    sw_zval_ptr_dtor(&zexit_code);

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onConnect(swServer *serv, int fd, int from_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval **args[3];
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, from_id);

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);
    args[1] = &zfd;
    args[2] = &zfrom_id;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onConnect], &retval, 3, args, 0,
            NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onConnect handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

void php_swoole_onClose(swServer *serv, int fd, int from_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval **args[3];
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, from_id);

    args[0] = &zserv;
    sw_zval_add_ref(&zserv);
    args[1] = &zfd;
    args[2] = &zfrom_id;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onClose], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onClose handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

PHP_FUNCTION(swoole_server_create)
{
    zend_size_t host_len = 0;
    char *serv_host;
    long sock_type = SW_SOCK_TCP;
    long serv_port;
    long serv_mode = SW_MODE_PROCESS;
    long serv_mode_tmp = serv_mode;
    long packet_mode = 0;

    //only cli env
    if (strcasecmp("cli", sapi_module.name) != 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "swoole_server must run at php_cli environment.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor != NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "eventLoop has been created. Unable to create swoole_server.");
        RETURN_FALSE;
    }

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "server is already running. Unable to create swoole_server.");
        RETURN_FALSE;
    }

    swServer *serv = sw_malloc(sizeof (swServer));
    swServer_init(serv);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|ll", &serv_host, &host_len, &serv_port, &serv_mode_tmp, &sock_type) == FAILURE)
    {
        return;
    }

    serv_mode = serv_mode_tmp & 0x0f;
    packet_mode = (serv_mode_tmp & 0xf0) >> 4;
    serv->packet_mode = packet_mode;

#ifdef __CYGWIN__
    serv->factory_mode = SW_MODE_SINGLE;
#else
    if (serv_mode == SW_MODE_THREAD || serv_mode == SW_MODE_BASE)
    {
        serv_mode = SW_MODE_SINGLE;
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "PHP can not running at multi-threading. Reset mode to SWOOLE_MODE_BASE");
    }
    serv->factory_mode = serv_mode;
#endif

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        serv->worker_num = 1;
        serv->max_request = 0;
    }

    swTrace("Create swoole_server host=%s, port=%d, mode=%d, type=%d", serv_host, (int) serv_port, serv->factory_mode, (int) sock_type);
    bzero(php_sw_callback, sizeof (zval*) * PHP_SERVER_CALLBACK_NUM);

    if (swServer_add_listener(serv, sock_type, serv_host, serv_port) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "add listener failed.");
        return;
    }

    zval *server_object = getThis();
    if (!getThis())
    {
        object_init_ex(return_value, swoole_server_class_entry_ptr);
        server_object = return_value;
    }

#ifdef HAVE_PCRE
    zval *connection_iterator_object;
    SW_MAKE_STD_ZVAL(connection_iterator_object);
    object_init_ex(connection_iterator_object, swoole_connection_iterator_class_entry_ptr);
    zend_update_property(swoole_server_class_entry_ptr, server_object, ZEND_STRL("connections"), connection_iterator_object TSRMLS_CC);
    sw_zval_ptr_dtor(&connection_iterator_object);
#endif
    
    swoole_set_object(server_object, serv);
}

PHP_FUNCTION(swoole_server_set)
{
    zval *zset = NULL;
    zval *zobject = getThis();
    HashTable *vht;

    zval *v;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server_set now.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oa", &zobject, swoole_server_class_entry_ptr, &zset) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &zset) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);

    vht = Z_ARRVAL_P(zset);
    //chroot
    if (sw_zend_hash_find(vht, ZEND_STRS("chroot"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        SwooleG.chroot = sw_strndup(v, 256);
    }
    //user
    if (sw_zend_hash_find(vht, ZEND_STRS("user"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        SwooleG.user = sw_strndup(v, 128);
    }
    //group
    if (sw_zend_hash_find(vht, ZEND_STRS("group"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        SwooleG.group = sw_strndup(v, 128);
    }
    //daemonize
    if (sw_zend_hash_find(vht, ZEND_STRS("daemonize"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->daemonize = Z_BVAL_P(v);
    }
    //backlog
    if (sw_zend_hash_find(vht, ZEND_STRS("backlog"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->backlog = (int) Z_LVAL_P(v);
    }
    //reactor thread num
    if (sw_zend_hash_find(vht, ZEND_STRS("reactor_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->reactor_num = (int) Z_LVAL_P(v);
        if (serv->reactor_num <= 0)
        {
            serv->reactor_num = SwooleG.cpu_num;
        }
    }
    //worker_num
    if (sw_zend_hash_find(vht, ZEND_STRS("worker_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->worker_num = (int) Z_LVAL_P(v);
        if (serv->worker_num <= 0)
        {
            serv->worker_num = SwooleG.cpu_num;
        }
    }
    /**
     * for dispatch_mode = 1/3
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("discard_timeout_request"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->discard_timeout_request = Z_BVAL_P(v);
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("enable_unsafe_event"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->enable_unsafe_event = Z_BVAL_P(v);
    }
    //task_worker_num
    if (sw_zend_hash_find(vht, ZEND_STRS("task_worker_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        SwooleG.task_worker_num = (int) Z_LVAL_P(v);
    }
    //task_worker_max
    if (sw_zend_hash_find(vht, ZEND_STRS("task_worker_max"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        SwooleG.task_worker_max = (int) Z_LVAL_P(v);
    }
    //task ipc mode, 1,2,3
    if (sw_zend_hash_find(vht, ZEND_STRS("task_ipc_mode"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        SwooleG.task_ipc_mode = (int) Z_LVAL_P(v);
    }
    /**
     * Temporary file directory for task_worker
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("task_tmpdir"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        SwooleG.task_tmpdir = emalloc(SW_TASK_TMPDIR_SIZE);
        SwooleG.task_tmpdir_len = snprintf(SwooleG.task_tmpdir, SW_TASK_TMPDIR_SIZE, "%s/task.XXXXXX", Z_STRVAL_P(v)) + 1;

        if (SwooleG.task_tmpdir_len > SW_TASK_TMPDIR_SIZE - 1)
        {
            swoole_php_fatal_error(E_ERROR, "task_tmpdir is too long, max size is %d.", SW_TASK_TMPDIR_SIZE - 1);
            return;
        }
    }
    else
    {
        SwooleG.task_tmpdir = strndup(SW_TASK_TMP_FILE, sizeof (SW_TASK_TMP_FILE));
        SwooleG.task_tmpdir_len = sizeof (SW_TASK_TMP_FILE);
    }
    //max_connection
    if (sw_zend_hash_find(vht, ZEND_STRS("max_connection"), (void **) &v) == SUCCESS ||
            sw_zend_hash_find(vht, ZEND_STRS("max_conn"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->max_connection = (int) Z_LVAL_P(v);
    }
    //max_request
    if (sw_zend_hash_find(vht, ZEND_STRS("max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->max_request = (int) Z_LVAL_P(v);
    }
    //task_max_request
    if (sw_zend_hash_find(vht, ZEND_STRS("task_max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        SwooleG.task_max_request = (int) Z_LVAL_P(v);
    }
    //cpu affinity
    if (sw_zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_cpu_affinity = Z_BVAL_P(v);
    }
    //cpu affinity set
    if (sw_zend_hash_find(vht, ZEND_STRS("cpu_affinity_ignore"), (void **) &v) == SUCCESS)
    {
        int ignore_num = zend_hash_num_elements(Z_ARRVAL_P(v));
        int available_num = SW_CPU_NUM - ignore_num;
        int *available_cpu = (int *) sw_malloc(sizeof(int) * available_num);
        int flag, i, available_i = 0;

        zval *zval_core = NULL;
        for (i = 0; i < SW_CPU_NUM; i++)
        {
            flag = 1;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(v), zval_core)
                int core = (int) Z_LVAL_P(zval_core);
                if (i == core)
                {
                    flag = 0;
                    break;
                }
            SW_HASHTABLE_FOREACH_END();
            if (flag)
            {
                available_cpu[available_i] = i;
                available_i++;
            }
        }
        serv->cpu_affinity_available_num = available_num;
        serv->cpu_affinity_available = available_cpu;
    }
    //tcp_nodelay
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_tcp_nodelay = Z_BVAL_P(v);
    }
    //tcp_defer_accept
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_defer_accept"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->tcp_defer_accept = (uint8_t) Z_LVAL_P(v);
    }
    //tcp_keepalive
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_keepalive"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_tcp_keepalive = Z_BVAL_P(v);
    }
    //buffer: split package with eof
    if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_split"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->protocol.split_by_eof = Z_BVAL_P(v);
        serv->open_eof_check = 1;
    }
    //package eof
    if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &v) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("data_eof"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->protocol.package_eof_len = Z_STRLEN_P(v);
        if (serv->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            RETURN_FALSE;
        }
        bzero(serv->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(serv->protocol.package_eof, Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //buffer: http_protocol
    if (sw_zend_hash_find(vht, ZEND_STRS("open_http_protocol"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_http_protocol = Z_BVAL_P(v);
    }
    //paser x-www-form-urlencoded form data
    if (sw_zend_hash_find(vht, ZEND_STRS("http_parse_post"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->http_parse_post = Z_BVAL_P(v);
    }
    //buffer: mqtt protocol
    if (sw_zend_hash_find(vht, ZEND_STRS("open_mqtt_protocol"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_mqtt_protocol = Z_BVAL_P(v);
    }
    //tcp_keepidle
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepidle"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->tcp_keepidle = (uint16_t) Z_LVAL_P(v);
    }
    //tcp_keepinterval
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepinterval"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->tcp_keepinterval = (uint16_t) Z_LVAL_P(v);
    }
    //tcp_keepcount
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepcount"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->tcp_keepcount = (uint16_t) Z_LVAL_P(v);
    }
    //dispatch_mode
    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_mode"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->dispatch_mode = (int) Z_LVAL_P(v);
    }

    //open_dispatch_key
    if (sw_zend_hash_find(vht, ZEND_STRS("open_dispatch_key"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->open_dispatch_key = (int) Z_LVAL_P(v);
    }

    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_key_type"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->dispatch_key_type = Z_STRVAL_P(v)[0];
        serv->dispatch_key_size = swoole_type_size(serv->dispatch_key_type);

        if (serv->dispatch_key_size == 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow dispatch_key_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }

    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_key_offset"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->dispatch_key_offset = (uint16_t) Z_LVAL_P(v);
    }

    //log_file
    if (sw_zend_hash_find(vht, ZEND_STRS("log_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        if (Z_STRLEN_P(v) > SW_LOG_FILENAME)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "log_file name to long");
            RETURN_FALSE;
        }
        memcpy(serv->log_file, Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //heartbeat_check_interval
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_check_interval"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->heartbeat_check_interval = (int) Z_LVAL_P(v);
    }
    //heartbeat idle time
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_idle_time"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->heartbeat_idle_time = (int) Z_LVAL_P(v);

        if (serv->heartbeat_check_interval > serv->heartbeat_idle_time)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "heartbeat_idle_time must be greater than heartbeat_check_interval.");
            serv->heartbeat_check_interval = serv->heartbeat_idle_time / 2;
        }
    }
    else if (serv->heartbeat_check_interval > 0)
    {
        serv->heartbeat_idle_time = serv->heartbeat_check_interval * 2;
    }
    //heartbeat_ping
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_ping"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->heartbeat_ping_length = Z_STRLEN_P(v);
        if (serv->heartbeat_ping_length > SW_HEARTBEAT_PING_LEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat ping package too long");
            RETURN_FALSE;
        }
        memcpy(serv->heartbeat_ping, Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //heartbeat_pong
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_pong"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->heartbeat_pong_length = Z_STRLEN_P(v);
        if (serv->heartbeat_pong_length > SW_HEARTBEAT_PONG_LEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat pong package too long");
            RETURN_FALSE;
        }
        memcpy(serv->heartbeat_pong, Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //open length check
    if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        serv->open_length_check = Z_BVAL_P(v);
    }
    //package length size
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **)&v) == SUCCESS)
    {
        convert_to_string(v);
        serv->protocol.package_length_type = Z_STRVAL_P(v)[0];
        serv->protocol.package_length_size = swoole_type_size(serv->protocol.package_length_type);

        if (serv->protocol.package_length_size == 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }
    //package length offset
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **)&v) == SUCCESS)
    {
        convert_to_long(v);
        serv->protocol.package_length_offset = (int)Z_LVAL_P(v);
    }
    //package body start
    if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &v) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("package_body_start"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->protocol.package_body_offset = (int) Z_LVAL_P(v);
    }
    /**
     * package max length
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->protocol.package_max_length = (int) Z_LVAL_P(v);
    }

    /**
     * swoole_packet_mode
     */
    if (serv->packet_mode == 1)
    {
        serv->protocol.package_max_length = 64 * 1024 * 1024;
        serv->open_length_check = 1;
        serv->protocol.package_length_offset = 0;
        serv->protocol.package_body_offset = 4;
        serv->protocol.package_length_type = 'N';
        serv->open_eof_check = 0;
    }

    /**
     * buffer input size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_input_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->buffer_input_size = (int) Z_LVAL_P(v);
    }
    /**
     * buffer output size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_output_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->buffer_output_size = (int) Z_LVAL_P(v);
    }
    /**
     * set pipe memory buffer size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("pipe_buffer_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->pipe_buffer_size = (int) Z_LVAL_P(v);
    }
    //message queue key
    if (sw_zend_hash_find(vht, ZEND_STRS("message_queue_key"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        serv->message_queue_key = (int) Z_LVAL_P(v);
    }

#ifdef SW_USE_OPENSSL
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->ssl_cert_file = strdup(Z_STRVAL_P(v));
        if (access(serv->ssl_cert_file, R_OK) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl cert file[%s] not found.", serv->ssl_cert_file);
            return;
        }
        serv->open_ssl = 1;
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        serv->ssl_key_file = strdup(Z_STRVAL_P(v));
        if (access(serv->ssl_key_file, R_OK) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl key file[%s] not found.", serv->ssl_key_file);
            return;
        }
    }
    if (serv->open_ssl && !serv->ssl_key_file)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl require key file.");
        return;
    }
#endif
//    sw_zval_add_ref(&zset);
//    sw_zval_add_ref(&zobject);
    zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_handler)
{
    zval *zobject = getThis();
    char *ha_name = NULL;
    zend_size_t len;
    int i;
    int ret = -1;

    zval *cb;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osz", &zobject, swoole_server_class_entry_ptr, &ha_name, &len, &cb) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &ha_name, &len, &cb) == FAILURE)
        {
            return;
        }
    }

    char *callback[PHP_SERVER_CALLBACK_NUM] = {
        "onStart",
        "onConnect",
        "onReceive",
        "onClose",
        "onShutdown",
        "onTimer",
        "onWorkerStart",
        "onWorkerStop",
        "onMasterConnect",
        "onMasterClose",
        "onTask",
        "onFinish",
        "onWorkerError",
        "onManagerStart",
        "onManagerStop",
        "onPipeMessage",
    };

    for (i = 0; i < PHP_SERVER_CALLBACK_NUM; i++)
    {
        if (strncasecmp(callback[i], ha_name, len) == 0)
        {
            ret = php_swoole_set_callback(i, cb TSRMLS_CC);
            break;
        }
    }
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unknown event types[%s]", ha_name);
    }
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_on)
{
    zval *zobject = getThis();
    char *ha_name = NULL;
    zend_size_t len, i;
    int ret = -1;

    zval *cb;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osz", &zobject, swoole_server_class_entry_ptr, &ha_name, &len, &cb) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &ha_name, &len, &cb) == FAILURE)
        {
            return;
        }
    }

    char *callback[PHP_SERVER_CALLBACK_NUM] = {
        "start",
        "connect",
        "receive",
        "close",
        "shutdown",
        "timer",
        "workerStart",
        "workerStop",
        "masterConnect",
        "masterClose",
        "task",
        "finish",
        "workerError",
        "managerStart",
        "managerStop",
        "pipeMessage",
        "packet",
    };

    for (i = 0; i < PHP_SERVER_CALLBACK_NUM; i++)
    {
        if (strncasecmp(callback[i], ha_name, len) == 0)
        {
            ret = php_swoole_set_callback(i, cb TSRMLS_CC);
            break;
        }
    }
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unknown event types[%s]", ha_name);
    }
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_addlisten)
{
    zval *zobject = getThis();

    char *host;
    zend_size_t host_len;
    long sock_type;
    long port;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. cannot add listener.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osll", &zobject, swoole_server_class_entry_ptr, &host, &host_len, &port, &sock_type) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll", &host, &host_len, &port, &sock_type) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);
    SW_CHECK_RETURN(swServer_add_listener(serv, (int)sock_type, host, (int)port));
}

PHP_METHOD(swoole_server, addprocess)
{
    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. cannot add process.");
        RETURN_FALSE;
    }

    zval *process = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &process) == FAILURE)
    {
        return;
    }

    if (ZVAL_IS_NULL(process))
    {
        swoole_php_fatal_error(E_WARNING, "parameter 1 cannot be empty.");
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(getThis());
    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_class_entry_ptr TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "object is not instanceof swoole_process.");
        RETURN_FALSE;
    }

    if (serv->onUserWorkerStart == NULL)
    {
        serv->onUserWorkerStart = php_swoole_onUserWorkerStart;
    }

#if PHP_MAJOR_VERSION >= 7
    zval *tmp_process = emalloc(sizeof(zval));
    memcpy(tmp_process, process, sizeof(zval));
    process = tmp_process;
#endif

    sw_zval_add_ref(&process);

    swWorker *worker = swoole_get_object(process);
    worker->ptr = process;

    int id = swServer_add_worker(serv, worker);

    if (id < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swServer_add_worker failed.");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("id"), id TSRMLS_CC);
    RETURN_LONG(id);
}

PHP_FUNCTION(swoole_server_start)
{
    zval *zobject = getThis();

    int ret;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
        {
            return;
        }
    }

    swServer *serv = swoole_get_object(zobject);
    php_swoole_register_callback(serv);

    if (php_sw_callback[SW_SERVER_CB_onReceive] == NULL && php_sw_callback[SW_SERVER_CB_onPacket] == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onReceive/onPacket callback");
        RETURN_FALSE;
    }
    //-------------------------------------------------------------
    serv->onReceive = php_swoole_onReceive;
    serv->ptr2 = zobject;

    ret = swServer_create(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "create server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }

    /**
     * Master Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zobject, ZEND_STRL("master_pid"), getpid() TSRMLS_CC);

    zval *zsetting = sw_zend_read_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
    {
        SW_MAKE_STD_ZVAL(zsetting);
        array_init(zsetting);
        zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zsetting TSRMLS_CC);
    }

    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("worker_num")))
    {
        add_assoc_long(zsetting, "worker_num", serv->worker_num);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("task_worker_num")))
    {
        add_assoc_long(zsetting, "task_worker_num", SwooleG.task_worker_num);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("pipe_buffer_size")))
    {
        add_assoc_long(zsetting, "pipe_buffer_size", serv->pipe_buffer_size);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("buffer_output_size")))
    {
        add_assoc_long(zsetting, "buffer_output_size", serv->buffer_output_size);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("max_connection")))
    {
        add_assoc_long(zsetting, "max_connection", serv->max_connection);
    }

    ret = swServer_start(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "start server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_send)
{
    zval *zobject = getThis();

    int ret;

    zval *zfd;
    zval *zdata;
    long server_socket = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ozz|l", &zobject, swoole_server_class_entry_ptr, &zfd, &zdata, &server_socket) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &zfd, &zdata, &server_socket) == FAILURE)
        {
            return;
        }
    }

    char *data;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);

    if (length < 0)
    {
        RETURN_FALSE;
    }
    else if (length == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

   swServer *serv = swoole_get_object(zobject);

    if (serv->have_udp_sock && SW_Z_TYPE_P(zfd) == IS_STRING)
    {
        if (server_socket == -1)
        {
            server_socket = dgram_server_socket;
        }
        //UDP IPv6
        if (strchr(Z_STRVAL_P(zfd), ':'))
        {
            php_swoole_udp_t udp_info;
            memcpy(&udp_info, &server_socket, sizeof(udp_info));
            ret = swSocket_udp_sendto6(udp_info.from_fd, Z_STRVAL_P(zfd), udp_info.port, data, length);
        }
        //UNIX DGRAM
        else if (Z_STRVAL_P(zfd)[0] == '/')
        {
            struct sockaddr_un addr_un;
            memcpy(addr_un.sun_path, Z_STRVAL_P(zfd), Z_STRLEN_P(zfd));
            addr_un.sun_family = AF_UNIX;
            addr_un.sun_path[Z_STRLEN_P(zfd)] = 0;
            ret = swSocket_sendto_blocking(server_socket, data, length, 0, (struct sockaddr *) &addr_un, sizeof(addr_un));
        }
        else
        {
            goto convert;
        }
        SW_CHECK_RETURN(ret);
    }

    convert: convert_to_long(zfd);
    uint32_t fd = (uint32_t) Z_LVAL_P(zfd);
    //UDP
    if (swServer_is_udp(fd))
    {
        if (server_socket == -1)
        {
            server_socket = udp_server_socket;
        }

        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &server_socket, sizeof(udp_info));

        struct sockaddr_in addr_in;
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(udp_info.port);
        addr_in.sin_addr.s_addr = fd;
        ret = swSocket_sendto_blocking(udp_info.from_fd, data, length, 0, (struct sockaddr *) &addr_in, sizeof(addr_in));
        SW_CHECK_RETURN(ret);
    }
    //TCP
    else
    {
        if (serv->factory_mode == SW_MODE_SINGLE && swIsTaskWorker())
        {
            swoole_php_error(E_WARNING, "cannot send to client in task worker with SWOOLE_BASE mode.");
            RETURN_FALSE;
        }
        if (serv->packet_mode == 1)
        {
            uint32_t len_tmp= htonl(length);
            swServer_tcp_send(serv, fd, &len_tmp, 4);
        }
        SW_CHECK_RETURN(swServer_tcp_send(serv, fd, data, length));
    }
}

PHP_METHOD(swoole_server, sendto)
{
    zval *zobject = getThis();

    char *ip;
    char *data;
    zend_size_t len, ip_len;

    long port;
    long sock = -1;
    zend_bool ipv6 = 0;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls|l", &ip, &ip_len, &port, &data, &len, &sock) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(zobject);

    if (strchr(ip, ':'))
    {
        ipv6 = 1;
    }

    if (ipv6 == 0 && serv->udp_socket_ipv4 <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must add an UDP listener to server before using sendto.");
        RETURN_FALSE;
    }
    else if (ipv6 == 1 && serv->udp_socket_ipv6 <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must add an UDP6 listener to server before using sendto.");
        RETURN_FALSE;
    }

    if (sock < 0)
    {
        sock = ipv6 ?  serv->udp_socket_ipv6 : serv->udp_socket_ipv4;
    }

    int ret;
    if (ipv6)
    {
        ret = swSocket_udp_sendto6(sock, ip, port, data, len);
    }
    else
    {
        ret = swSocket_udp_sendto(sock, ip, port, data, len);
    }
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_sendfile)
{
    zval *zobject = getThis();
    zend_size_t len;
    swSendData send_data;

    char buffer[SW_BUFFER_SIZE];
    char *filename;
    long conn_fd;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

#ifdef __CYGWIN__
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot use swoole_server->sendfile() in cygwin.");
    RETURN_FALSE;;
#endif

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ols", &zobject, swoole_server_class_entry_ptr, &conn_fd, &filename, &len) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &conn_fd, &filename, &len) == FAILURE)
        {
            return;
        }
    }

    //check fd
    if (conn_fd <= 0 || conn_fd > SW_MAX_SOCKET_ID)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid fd[%ld] error.", conn_fd);
        RETURN_FALSE;
    }
    send_data.info.len = len;
    //file name size
    if (send_data.info.len > SW_BUFFER_SIZE - 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "sendfile name too long. [MAX_LENGTH=%d]", (int) SW_BUFFER_SIZE - 1);
        RETURN_FALSE;
    }
    //check file exists
    if (access(filename, R_OK) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "file[%s] not found.", filename);
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(zobject);

    send_data.info.fd = (int) conn_fd;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, filename, send_data.info.len);
    buffer[send_data.info.len] = 0;
    send_data.info.len++;
    send_data.length = 0;

    send_data.data = buffer;
    SW_CHECK_RETURN(serv->factory.finish(&serv->factory, &send_data));
}

PHP_FUNCTION(swoole_server_close)
{
    zval *zobject = getThis();
    zval *zfd;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Cannot close connection in master process.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz", &zobject, swoole_server_class_entry_ptr, &zfd) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zfd) == FAILURE)
        {
            return;
        }
    }
    convert_to_long(zfd);
    swServer *serv = swoole_get_object(zobject);
    SW_CHECK_RETURN(serv->factory.end(&serv->factory, Z_LVAL_P(zfd)));
}

PHP_METHOD(swoole_server, stats)
{
    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long_ex(return_value, SW_STRL("start_time"), SwooleStats->start_time);
    add_assoc_long_ex(return_value, SW_STRL("connection_num"), SwooleStats->connection_num);
    add_assoc_long_ex(return_value, SW_STRL("accept_count"), SwooleStats->accept_count);
    add_assoc_long_ex(return_value, SW_STRL("close_count"), SwooleStats->close_count);
    add_assoc_long_ex(return_value, SW_STRL("tasking_num"), SwooleStats->tasking_num);
    add_assoc_long_ex(return_value, SW_STRL("request_count"), SwooleStats->request_count);
    add_assoc_long_ex(return_value, SW_STRL("worker_request_count"), SwooleWG.request_count);
    add_assoc_long_ex(return_value, SW_STRL("task_process_num"), SwooleGS->task_workers.run_worker_num);
}

PHP_FUNCTION(swoole_server_reload)
{
    zval *zobject = getThis();

    zend_bool only_reload_taskworker = 0;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|b", &zobject, swoole_server_class_entry_ptr,
                &only_reload_taskworker) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &only_reload_taskworker) == FAILURE)
        {
            return;
        }
    }

    int sig = only_reload_taskworker ? SIGUSR2 : SIGUSR1;
    if (kill(SwooleGS->manager_pid, sig) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "kill() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_heartbeat)
{
    zval *zobject = getThis();

    zend_bool close_connection = 0;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|b", &zobject, swoole_server_class_entry_ptr, &close_connection) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &close_connection) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);

    if (serv->heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    array_init(return_value);

    int fd;
    int checktime = (int) SwooleGS->now - serv->heartbeat_idle_time;
    swConnection *conn;

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        swTrace("heartbeat check fd=%d", fd);
        conn = &serv->connection_list[fd];

        if (1 == conn->active && conn->last_time < checktime)
        {
            conn->close_force = 1;
            /**
             * Close the connection
             */
            if (close_connection)
            {
                serv->factory.end(&serv->factory, fd);
            }
#ifdef SW_REACTOR_USE_SESSION
            add_next_index_long(return_value, conn->session_id);
#else
            add_next_index_long(return_value, fd);
#endif
        }
    }
}

PHP_FUNCTION(swoole_server_gettimer)
{
    zval *zobject = getThis();

    long interval;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr, &interval) == FAILURE)
        {
            return;
        }
    }

    if (SwooleG.timer.list == NULL)
    {
        RETURN_FALSE;
    }

    swTimer_node *timer_node;
    uint64_t key;
    array_init(return_value);

    do
    {
        timer_node = swHashMap_each_int(SwooleG.timer.list, &key);
        if (timer_node == NULL)
        {
            break;
        }
        if (timer_node->interval == 0)
        {
            continue;
        }
        add_next_index_long(return_value, key);

    } while(timer_node);
}

PHP_FUNCTION(swoole_server_addtimer)
{
    zval *zobject = getThis();

    long interval;

    if (swIsMaster())
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "master process cannot use timer.");
        RETURN_FALSE;
    }

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (SwooleG.serv->onTimer == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no onTimer callback, cannot use addtimer.");
        RETURN_FALSE;
    }

    if (php_sw_callback[SW_SERVER_CB_onTimer] == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onTimer is null, Can not use timer.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol", &zobject, swoole_server_class_entry_ptr, &interval) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &interval) == FAILURE)
        {
            return;
        }
    }

    php_swoole_check_timer(interval);
    SW_CHECK_RETURN(SwooleG.timer.add(&SwooleG.timer, (int )interval, 1, NULL));
}

PHP_FUNCTION(swoole_server_taskwait)
{
    zval *zobject = getThis();
    swEventData buf;

    zval *data;
    smart_str serialized_data = { 0 };
    php_serialize_data_t var_hash;

    double timeout = SW_TASKWAIT_TIMEOUT;
    long worker_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot use task in master process.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz|dl", &zobject, swoole_server_class_entry_ptr, &data, &timeout, &worker_id) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|dl", &data, &timeout, &worker_id) == FAILURE)
        {
            return;
        }
    }

    swServer *serv = swoole_get_object(zobject);

    if (SwooleG.task_worker_num < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot use task. Please set task_worker_num.");
        RETURN_FALSE;
    }

    if (worker_id >= SwooleG.task_worker_num)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "worker_id must be less than serv->task_worker_num");
        RETURN_FALSE;
    }

    if (SwooleWG.id >= serv->worker_num)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot dispatch task in task worker.");
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_TASK;
    //field fd save task_id
    buf.info.fd = php_swoole_task_id++;
    //field from_id save the worker_id
    buf.info.from_id = SwooleWG.id;
    swTask_type(&buf) = 0;

    //clear result buffer
    swEventData *task_result = &(SwooleG.task_result[SwooleWG.id]);
    bzero(task_result, sizeof(SwooleG.task_result[SwooleWG.id]));

    uint64_t notify;

    char *task_data_str;
    int task_data_len = 0;
    //need serialize
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(&buf) |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
#if PHP_MAJOR_VERSION<7
        task_data_str = serialized_data.c;
        task_data_len = serialized_data.len;
#else
        task_data_str = serialized_data.s->val;
        task_data_len = serialized_data.s->len;
#endif
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    if (task_data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
    {
        if (swTaskWorker_large_pack(&buf, task_data_str, task_data_len) < 0)
        {
            smart_str_free(&serialized_data);
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
            RETURN_FALSE;
        }
    }
    else
    {
        memcpy(buf.data, task_data_str, task_data_len);
        buf.info.len = task_data_len;
    }
    smart_str_free(&serialized_data);

    swPipe *task_notify_pipe = &SwooleG.task_notify[SwooleWG.id];
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);
    //clear history task
    while (read(efd, &notify, sizeof(notify)) > 0);

    if (swProcessPool_dispatch_blocking(&SwooleGS->task_workers, &buf, (int*) &worker_id) >= 0)
    {
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        swWorker *worker = swProcessPool_get_worker(&SwooleGS->task_workers, worker_id);
        sw_atomic_fetch_sub(&worker->tasking_num, 1);

        if (ret > 0)
        {
            zval *task_notify_data = php_swoole_get_task_result(task_result TSRMLS_CC);
            RETURN_ZVAL(task_notify_data, 0, 0);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(swoole_server_task)
{
    zval *zobject = getThis();
    swEventData buf;

    zval *data;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;

    long worker_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz|l", &zobject, swoole_server_class_entry_ptr, &data, &worker_id) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &data, &worker_id) == FAILURE)
        {
            return;
        }
    }

    swServer *serv = swoole_get_object(zobject);

    if (SwooleG.task_worker_num < 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "task can not use. Please set task_worker_num.");
        RETURN_FALSE;
    }

    if (worker_id >= SwooleG.task_worker_num)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "worker_id must be less than serv->task_worker_num.");
        RETURN_FALSE;
    }

    if (SwooleWG.id >= serv->worker_num)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot dispatch task in task worker.");
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_TASK;
    //task_id
    buf.info.fd = php_swoole_task_id++;
    //source worker_id
    buf.info.from_id = SwooleWG.id;
    swTask_type(&buf) = 0;

    swTask_type(&buf) |= SW_TASK_NONBLOCK;

    char *task_data_str = NULL;
    int task_data_len = 0;

    //need serialize
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(&buf) |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

#if PHP_MAJOR_VERSION<7
        task_data_str = serialized_data.c;
        task_data_len = serialized_data.len;
#else
        task_data_str = serialized_data.s->val;
        task_data_len = serialized_data.s->len;
#endif
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    //write to file
    if (task_data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
    {
        if (swTaskWorker_large_pack(&buf, task_data_str, task_data_len) < 0)
        {
            smart_str_free(&serialized_data);
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
            RETURN_FALSE;
        }
    }
    else
    {
        memcpy(buf.data, task_data_str, task_data_len);
        buf.info.len = task_data_len;
    }

    smart_str_free(&serialized_data);

    if (swProcessPool_dispatch(&SwooleGS->task_workers, &buf, (int*) &worker_id) >= 0)
    {
        sw_atomic_fetch_add(&SwooleStats->tasking_num, 1);
        RETURN_LONG(buf.info.fd);
    }
    else
    {
        RETURN_FALSE;
    }
}

PHP_METHOD(swoole_server, sendmessage)
{
    zval *zobject = getThis();
    swEventData buf;

    char *msg;
    zend_size_t msglen;
    long worker_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &msg, &msglen, &worker_id) == FAILURE)
    {
        return;
    }

    if (worker_id == SwooleWG.id)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot send message to self.");
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(zobject);
    if (worker_id >= serv->worker_num + SwooleG.task_worker_num)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "worker_id[%d] is invalid.", (int) worker_id);
        RETURN_FALSE;
    }

    if (!serv->onPipeMessage)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onPipeMessage is null, cannot use sendMessage.");
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_PIPE_MESSAGE;
    buf.info.from_id = SwooleWG.id;

    //write to file
    if (msglen >= SW_IPC_MAX_SIZE - sizeof(buf.info))
    {
        if (swTaskWorker_large_pack(&buf, msg, msglen) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
            RETURN_FALSE;
        }
    }
    else
    {
        memcpy(buf.data, msg, msglen);
        buf.info.len = msglen;
        buf.info.from_fd = 0;
    }

    swWorker *to_worker = swServer_get_worker(serv, worker_id);
    SW_CHECK_RETURN(swWorker_send2worker(to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK));
}

PHP_FUNCTION(swoole_server_finish)
{
    zval *zobject = getThis();
    zval *data;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz", &zobject, swoole_server_class_entry_ptr, &data) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);
    SW_CHECK_RETURN(php_swoole_task_finish(serv, data TSRMLS_CC));
}

PHP_METHOD(swoole_server, bind)
{
    zval *zobject = getThis();

    long fd = 0;
    long uid = 0;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &fd, &uid) == FAILURE)
    {
        return;
    }

    swServer *serv = swoole_get_object(zobject);

    swConnection *conn = swWorker_get_connection(serv, fd);

    //udp client
    if (conn == NULL)
    {
        swTrace("%ld conn error", fd);
        RETURN_FALSE;
    }

    //connection is closed
    if (conn->active == 0)
    {
        swTrace("fd:%ld a:%d, uid: %ld", fd, conn->active, conn->uid);
        RETURN_FALSE;
    }

    if (conn->uid != 0)
    {
        RETURN_FALSE;
    }

    int ret = 0;
    SwooleGS->lock.lock(&SwooleGS->lock);
    if (conn->uid == 0)
    {
        conn->uid = uid;
        ret = 1;
    }
    SwooleGS->lock.unlock(&SwooleGS->lock);
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_connection_info)
{
    zval *zobject = getThis();

    zend_bool noCheckConnection = 0;
    zval *zfd;
    long from_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz|lb", &zobject, swoole_server_class_entry_ptr, &zfd, &from_id, &noCheckConnection) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|lb", &zfd, &from_id, &noCheckConnection) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);

    long fd = 0;
    zend_bool ipv6_udp = 0;

    //ipv6 udp
    if (SW_Z_TYPE_P(zfd) == IS_STRING)
    {
        if (is_numeric_string(Z_STRVAL_P(zfd), Z_STRLEN_P(zfd), &fd, NULL, 0))
        {
            ipv6_udp = 0;
        }
        else
        {
            fd = 0;
            ipv6_udp = 1;
        }
    }
    else
    {
        convert_to_long(zfd);
        fd = Z_LVAL_P(zfd);
    }

    //udp
    if (ipv6_udp || swServer_is_udp(fd))
    {
        array_init(return_value);

        if (ipv6_udp)
        {
            add_assoc_zval(return_value, "remote_ip", zfd);
        }
        else
        {
            struct in_addr sin_addr;
            sin_addr.s_addr = fd;
            sw_add_assoc_string(return_value, "remote_ip", inet_ntoa(sin_addr), 1);
        }

        if (from_id == 0)
        {
            return;
        }

        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &from_id, sizeof(udp_info));
        swConnection *from_sock = swServer_connection_get(serv, udp_info.from_fd);

        if (from_sock != NULL)
        {
            add_assoc_long(return_value, "server_fd", from_sock->fd);
            add_assoc_long(return_value, "socket_type", from_sock->socket_type);
            add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        }
        add_assoc_long(return_value, "remote_port", udp_info.port);
        return;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 && !noCheckConnection)
    {
        RETURN_FALSE;
    }
    else
    {
        array_init(return_value);

        if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
        {
            add_assoc_long(return_value, "uid", conn->uid);
        }

        if (serv->open_websocket_protocol)
        {
            add_assoc_long(return_value, "websocket_status", conn->websocket_status);
        }

        swConnection *from_sock = swServer_connection_get(serv, conn->from_fd);
        add_assoc_long(return_value, "server_fd", conn->from_fd);
        add_assoc_long(return_value, "socket_type", conn->socket_type);
        add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        add_assoc_long(return_value, "remote_port", swConnection_get_port(conn));
        sw_add_assoc_string(return_value, "remote_ip", swConnection_get_ip(conn), 1);
        add_assoc_long(return_value, "from_id", conn->from_id);
        add_assoc_long(return_value, "connect_time", conn->connect_time);
        add_assoc_long(return_value, "last_time", conn->last_time);
    }
}

PHP_FUNCTION(swoole_connection_list)
{
    zval *zobject = getThis();

    long start_fd = 0;
    long find_count = 10;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ll", &zobject, swoole_server_class_entry_ptr, &start_fd, &find_count) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &start_fd, &find_count) == FAILURE)
        {
            return;
        }
    }
    swServer *serv = swoole_get_object(zobject);

    //超过最大查找数量
    if (find_count > SW_MAX_FIND_COUNT)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_connection_list max_find_count=%d", SW_MAX_FIND_COUNT);
        RETURN_FALSE;
    }

    //复制出来避免被其他进程改写
    int serv_max_fd = swServer_get_maxfd(serv);

    if (start_fd == 0)
    {
        start_fd = swServer_get_minfd(serv);
    }
#ifdef SW_REACTOR_USE_SESSION
    else
    {
        swConnection *conn = swWorker_get_connection(serv, start_fd);
        if (!conn)
        {
            RETURN_FALSE;
        }
        start_fd = conn->fd;
    }
#endif

    //达到最大，表示已经取完了
    if ((int) start_fd >= serv_max_fd)
    {
        RETURN_FALSE;
    }

    array_init(return_value);
    int fd = start_fd + 1;
    swConnection *conn;

    for (; fd <= serv_max_fd; fd++)
    {
        swTrace("maxfd=%d, fd=%d, find_count=%ld, start_fd=%ld", serv_max_fd, fd, find_count, start_fd);
        conn = &serv->connection_list[fd];

        if (conn->active && !conn->closed)
        {
#ifdef SW_REACTOR_USE_SESSION
            add_next_index_long(return_value, conn->session_id);
#else
            add_next_index_long(return_value, fd);
#endif
            find_count--;
        }
        //finish fetch
        if (find_count <= 0)
        {
            break;
        }
    }
}

PHP_METHOD(swoole_server, sendwait)
{
    zval *zobject = getThis();

    long fd;
    zval *zdata;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &fd, &zdata) == FAILURE)
    {
        return;
    }

    char *data;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);

    if (length < 0)
    {
        RETURN_FALSE;
    }
    else if (length == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swServer *serv = swoole_get_object(zobject);

    if (serv->factory_mode != SW_MODE_SINGLE || swIsTaskWorker())
    {
        swoole_php_fatal_error(E_WARNING, "cannot sendwait.");
        RETURN_FALSE;
    }

    //UDP
    if (swServer_is_udp(fd))
    {
        swoole_php_fatal_error(E_WARNING, "cannot sendwait.");
        RETURN_FALSE;
    }
    //TCP
    else
    {
        SW_CHECK_RETURN(swServer_tcp_sendwait(serv, fd, data, length));
    }
}

PHP_METHOD(swoole_server, exist)
{
    zval *zobject = getThis();

    long fd;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &fd) == FAILURE)
    {
        return;
    }

    swServer *serv = swoole_get_object(zobject);

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 || conn->closed)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_server_shutdown)
{
    zval *zobject = getThis();

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
        {
            return;
        }
    }
    if (kill(SwooleGS->master_pid, SIGTERM) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "shutdown failed. kill -SIGTERM master_pid[%d] fail. Error: %s[%d]", SwooleGS->master_pid, strerror(errno), errno);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

#ifdef HAVE_PCRE
static struct
{
    int current_fd;
    int max_fd;
    uint32_t session_id;
    int end;
    int index;
} server_itearator;

PHP_METHOD(swoole_connection_iterator, rewind)
{
    bzero(&server_itearator, sizeof(server_itearator));
    server_itearator.current_fd = swServer_get_minfd(SwooleG.serv);
}

PHP_METHOD(swoole_connection_iterator, valid)
{
    int fd = server_itearator.current_fd;
    swConnection *conn;

    int max_fd = swServer_get_maxfd(SwooleG.serv);
    for (; fd <= max_fd; fd++)
    {
        conn = &SwooleG.serv->connection_list[fd];

        if (conn->active && !conn->closed)
        {
            server_itearator.session_id = conn->session_id;
            server_itearator.current_fd = fd;
            server_itearator.index++;
            RETURN_TRUE;
        }
    }

    RETURN_FALSE;
}

PHP_METHOD(swoole_connection_iterator, current)
{
    RETURN_LONG(server_itearator.session_id);
}

PHP_METHOD(swoole_connection_iterator, next)
{
    server_itearator.current_fd ++;
}

PHP_METHOD(swoole_connection_iterator, key)
{
    RETURN_LONG(server_itearator.index);
}

PHP_METHOD(swoole_connection_iterator, count)
{
    RETURN_LONG(SwooleStats->connection_num);
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
