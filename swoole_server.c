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
  | license@php.net so we can mail you a copy immediately.               |
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
#include "ext/standard/php_smart_string.h"
#endif

static int php_swoole_task_id;
static int php_swoole_udp_from_id;
static int php_swoole_unix_dgram_fd;

zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

static int php_swoole_task_finish(swServer *serv, zval **data TSRMLS_DC);
static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC);
static int php_swoole_onReceive(swFactory *, swEventData *);
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

zval *php_swoole_get_data(swEventData *req TSRMLS_DC)
{
    zval *zdata;
    char *data_ptr = NULL;
    int data_len;

    MAKE_STD_ZVAL(zdata);

#ifdef SW_USE_RINGBUFFER
    swPackage package;
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        memcpy(&package, req->data, sizeof(package));

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
        ZVAL_STRINGL(zdata, data_ptr + 4, data_len - 4, 1);
    }
    else
    {
        ZVAL_STRINGL(zdata, data_ptr, data_len, 1);
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

void php_swoole_register_callback(swServer *serv)
{
    /*
     * optional callback
     */
    if (php_sw_callback[SW_SERVER_CB_onStart] != NULL)
    {
        serv->onStart = php_swoole_onStart;
    }
    if (php_sw_callback[SW_SERVER_CB_onShutdown] != NULL)
    {
        serv->onShutdown = php_swoole_onShutdown;
    }
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
}

static int php_swoole_task_finish(swServer *serv, zval **data TSRMLS_DC)
{
    int flags = 0;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;
    char *data_str;
    int data_len = 0;
    int ret;

    //need serialize
    if (Z_TYPE_PP(data) != IS_STRING)
    {
        //serialize
    	flags |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        data_str = serialized_data.c;
        data_len = serialized_data.len;
    }
    else
    {
        data_str = Z_STRVAL_PP(data);
        data_len = Z_STRLEN_PP(data);
    }

    ret = swTaskWorker_finish(serv, data_str, data_len, flags);

    smart_str_free(&serialized_data);
    return ret;
}

static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC)
{

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!zend_is_callable(cb, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_ERR;
    }
    efree(func_name);
#endif

    //zval_add_ref(&cb);
    php_sw_callback[key] = emalloc(sizeof(zval));
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
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;
    zval *zdata;
    zval *retval;

    MAKE_STD_ZVAL(zworker_id);
    MAKE_STD_ZVAL(zdata);

    zval **args[3];

    ZVAL_LONG(zworker_id, (long )req->info.from_id);

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

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onPipeMessage], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onPipeMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    zval_ptr_dtor(&zworker_id);
    zval_ptr_dtor(&zdata);

    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static int php_swoole_onReceive(swFactory *factory, swEventData *req)
{
    swServer *serv = factory->ptr;
    zval *zserv = (zval *)serv->ptr2;
    zval **args[4];

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;
    zval *retval;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    //UDP使用from_id作为port,fd做为ip
    php_swoole_udp_t udp_info;

    MAKE_STD_ZVAL(zfd);
    MAKE_STD_ZVAL(zfrom_id);

    //udp
    if (req->info.type == SW_EVENT_UDP)
    {
        udp_info.from_fd = req->info.from_fd;
        udp_info.port = req->info.from_id;
        memcpy(&php_swoole_udp_from_id, &udp_info, sizeof(php_swoole_udp_from_id));
        factory->last_from_id = php_swoole_udp_from_id;
        swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t)req->info.from_id, req->info.from_fd);

        ZVAL_LONG(zfrom_id, (long) php_swoole_udp_from_id);
        ZVAL_LONG(zfd, (long)req->info.fd);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        uint16_t sun_path_offset = req->info.fd;
        ZVAL_STRING(zfd, req->data + sun_path_offset, 1);
        req->info.len -= (Z_STRLEN_P(zfd) + 1);
        ZVAL_LONG(zfrom_id, (long)req->info.from_fd);
        php_swoole_unix_dgram_fd = req->info.from_fd;
    }
    else
    {
        ZVAL_LONG(zfrom_id, (long )req->info.from_id);
        ZVAL_LONG(zfd, (long )req->info.fd);
    }

    zdata = php_swoole_get_data(req TSRMLS_CC);

    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    //printf("req: fd=%d|len=%d|from_id=%d|data=%s\n", req->fd, req->len, req->from_id, req->data);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onReceive], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onReceive handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    zval_ptr_dtor(&zfd);
    zval_ptr_dtor(&zfrom_id);
    zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_onTask(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *)serv->ptr2;
    zval **args[4];

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;

    char *zdata_str;
    int zdata_len;
    zval *unserialized_zdata = NULL;
    zval *retval;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, (long )req->info.fd);

    MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, (long )req->info.from_id);

    MAKE_STD_ZVAL(zdata);

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
        ALLOC_INIT_ZVAL(unserialized_zdata);

        if (php_var_unserialize(&unserialized_zdata, (const unsigned char **) &zdata_str,
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

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTask], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        sw_atomic_fetch_sub(&SwooleStats->tasking_num, 1);
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTask handler error");
    }

    if (EG(exception))
    {
        sw_atomic_fetch_sub(&SwooleStats->tasking_num, 1);
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    zval_ptr_dtor(&zfd);
    zval_ptr_dtor(&zfrom_id);
    zval_ptr_dtor(&zdata);

    if (unserialized_zdata)
    {
        zval_ptr_dtor(&unserialized_zdata);
    }

    if (retval != NULL && Z_TYPE_P(retval) != IS_NULL)
    {
        php_swoole_task_finish(serv, &retval TSRMLS_CC);
        zval_ptr_dtor(&retval);
    }
    sw_atomic_fetch_sub(&SwooleStats->tasking_num, 1);
    return SW_OK;
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *)serv->ptr2;
    zval **args[3];

    zval *ztask_id;
    zval *zdata;
    zval *retval;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    MAKE_STD_ZVAL(ztask_id);
    ZVAL_LONG(ztask_id, (long) req->info.fd);

    MAKE_STD_ZVAL(zdata);
    
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
    args[1] = &ztask_id;
    args[2] = &zdata;

    //swTraceLog(60, "req: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onFinish], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onFinish handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    zval_ptr_dtor(&ztask_id);
    zval_ptr_dtor(&zdata);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static void php_swoole_onStart(swServer *serv)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *zserv = (zval *)serv->ptr2;
    zval **args[1];
    zval *retval;

    pid_t manager_pid = serv->factory_mode == SW_MODE_PROCESS ? SwooleGS->manager_pid : 0;

    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), SwooleGS->master_pid TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), manager_pid TSRMLS_CC);

    args[0] = &zserv;
    zval_add_ref(&zserv);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onManagerStart(swServer *serv)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *zserv = (zval *)serv->ptr2;
    zval **args[1];
    zval *retval;

    args[0] = &zserv;
    zval_add_ref(&zserv);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onManagerStop(swServer *serv)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *zserv = (zval *)serv->ptr2;
    zval **args[1];
    zval *retval;

    args[0] = &zserv;
    zval_add_ref(&zserv);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStop], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStop handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onTimer(swServer *serv, int interval)
{
    zval *zserv = (zval *)serv->ptr2;
    zval **args[2];
    zval *retval;
    zval *zinterval;

    MAKE_STD_ZVAL(zinterval);
    ZVAL_LONG(zinterval, interval);

    args[0] = &zserv;
    args[1] = &zinterval;
    zval_add_ref(&zserv);
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTimer], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTimer handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    zval_ptr_dtor(&zinterval);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onShutdown(swServer *serv)
{
    zval *zserv = (zval *)serv->ptr2;
    zval **args[1];
    zval *retval;

    args[0] = &zserv;
    zval_add_ref(&zserv);
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onShutdown], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onShutdown handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onWorkerStart(swServer *serv, int worker_id)
{
    zval *zserv = (zval *)serv->ptr2;
    zval *zworker_id;
    zval **args[2];
    zval *retval = NULL;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    args[0] = &zserv;
    zval_add_ref(&zserv);
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
     * Worker Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_pid"), getpid() TSRMLS_CC);

    zval_ptr_dtor(&zworker_id);

    /**
     * Have not set the event callback
     */
    if (php_sw_callback[SW_SERVER_CB_onWorkerStart] == NULL)
    {
        return;
    }

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStart], &retval, 2, args,  0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onWorkerStop(swServer *serv, int worker_id)
{
    zval *zobject = (zval *) serv->ptr2;
    zval *zworker_id;
    zval **args[2];  //这里必须与下面的数字对应
    zval *retval;

    MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval_add_ref(&zobject);
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    args[0] = &zobject;
    args[1] = &zworker_id;
    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStop], &retval, 2, args, 0,
            NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStop handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    zval_ptr_dtor(&zworker_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *object = worker->ptr;
    int id =  worker->id + serv->worker_num + SwooleG.task_worker_num;
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("id"), id TSRMLS_CC);

    php_swoole_process_start(worker, object TSRMLS_CC);
}

static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code)
{
    zval *zobject = (zval *)serv->ptr2;
    zval *zworker_id, *zworker_pid, *zexit_code;
    zval **args[4];
    zval *retval;

    MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    MAKE_STD_ZVAL(zworker_pid);
    ZVAL_LONG(zworker_pid, worker_pid);

    MAKE_STD_ZVAL(zexit_code);
    ZVAL_LONG(zexit_code, exit_code);

    zval_add_ref(&zobject);
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    args[0] = &zobject;
    args[1] = &zworker_id;
    args[2] = &zworker_pid;
    args[3] = &zexit_code;

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerError], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerError handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    zval_ptr_dtor(&zworker_id);
    zval_ptr_dtor(&zworker_pid);
    zval_ptr_dtor(&zexit_code);

    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onConnect(swServer *serv, int fd, int from_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval **args[3];
    zval *retval;

    MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, fd);

    MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, from_id);

    args[0] = &zserv;
    zval_add_ref(&zserv);
    args[1] = &zfd;
    args[2] = &zfrom_id;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onConnect], &retval, 3, args, 0,
            NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onConnect handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    zval_ptr_dtor(&zfd);
    zval_ptr_dtor(&zfrom_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

void php_swoole_onClose(swServer *serv, int fd, int from_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval **args[3];
    zval *retval;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, fd);

    MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, from_id);

    args[0] = &zserv;
    zval_add_ref(&zserv);
    args[1] = &zfd;
    args[2] = &zfrom_id;

    if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onClose], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onClose handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    zval_ptr_dtor(&zfd);
    zval_ptr_dtor(&zfrom_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
}

PHP_FUNCTION(swoole_server_create)
{
    int host_len = 0;
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

    swServer *serv = sw_malloc(sizeof(swServer));
    swServer_init(serv);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|ll", &serv_host, &host_len, &serv_port, &serv_mode_tmp, &sock_type) == FAILURE)
    {
        return;
    }

    serv_mode = serv_mode_tmp & 0x0f;
    packet_mode = (serv_mode_tmp & 0xf0 ) >> 4;
    serv-> packet_mode= packet_mode;

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
    bzero(php_sw_callback, sizeof(zval*) * PHP_SERVER_CALLBACK_NUM);

    if (swServer_addListener(serv, sock_type, serv_host, serv_port) < 0)
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

    zval *zres;
    MAKE_STD_ZVAL(zres);
    ZEND_REGISTER_RESOURCE(zres, serv, le_swoole_server);
    zend_update_property(swoole_server_class_entry_ptr, server_object, ZEND_STRL("_server"), zres TSRMLS_CC);
    zval_ptr_dtor(&zres);
}

PHP_FUNCTION(swoole_server_set)
{
    zval *zset = NULL;
    zval *zobject = getThis();
    HashTable *vht;
    swServer *serv;
    zval **v;

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
    SWOOLE_GET_SERVER(zobject, serv);

    vht = Z_ARRVAL_P(zset);

    //chroot
    if (sw_zend_hash_find(vht, ZEND_STRS("chroot"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        SwooleG.chroot = strndup(Z_STRVAL_PP(v), 256);
    }

    //user
    if (sw_zend_hash_find(vht, ZEND_STRS("user"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        SwooleG.user = strndup(Z_STRVAL_PP(v), 128);
    }

    //group
    if (sw_zend_hash_find(vht, ZEND_STRS("group"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        SwooleG.group = strndup(Z_STRVAL_PP(v), 128);
    }

    //daemonize
    if (sw_zend_hash_find(vht, ZEND_STRS("daemonize"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->daemonize = (int) Z_LVAL_PP(v);
    }
    //backlog
    if (sw_zend_hash_find(vht, ZEND_STRS("backlog"), (void **) &v) == SUCCESS)
    {
        serv->backlog = (int) Z_LVAL_PP(v);
    }
    //reactor thread num
    if (sw_zend_hash_find(vht, ZEND_STRS("reactor_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->reactor_num = (int) Z_LVAL_PP(v);
        if (serv->reactor_num <= 0)
        {
            serv->reactor_num = SwooleG.cpu_num;
        }
    }
    //worker_num
    if (sw_zend_hash_find(vht, ZEND_STRS("worker_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->worker_num = (int) Z_LVAL_PP(v);
        if (serv->worker_num <= 0)
        {
            serv->worker_num = SwooleG.cpu_num;
        }
    }
    //task_worker_num
    if (sw_zend_hash_find(vht, ZEND_STRS("task_worker_num"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        SwooleG.task_worker_num = (int) Z_LVAL_PP(v);
    }
    //task_worker_max
    if (sw_zend_hash_find(vht, ZEND_STRS("task_worker_max"), (void **)&v) == SUCCESS)
    {
	    convert_to_long(*v);
	    SwooleG.task_worker_max = (int)Z_LVAL_PP(v);
    }
    
    if (sw_zend_hash_find(vht, ZEND_STRS("task_ipc_mode"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        SwooleG.task_ipc_mode = (int) Z_LVAL_PP(v);
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("task_dispatch_mode"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        SwooleG.task_dispatch_mode = (int) Z_LVAL_PP(v);
    }
    /**
     * Temporary file directory for task_worker
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("task_tmpdir"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        SwooleG.task_tmpdir = emalloc(SW_TASK_TMPDIR_SIZE);
        SwooleG.task_tmpdir_len = snprintf(SwooleG.task_tmpdir, SW_TASK_TMPDIR_SIZE, "%s/task.XXXXXX", Z_STRVAL_PP(v)) + 1;

        if (SwooleG.task_tmpdir_len > SW_TASK_TMPDIR_SIZE - 1)
        {
            swoole_php_fatal_error(E_ERROR, "task_tmpdir is too long, max size is %d.", SW_TASK_TMPDIR_SIZE - 1);
            return;
        }
    }
    else
    {
        SwooleG.task_tmpdir = strndup(SW_TASK_TMP_FILE, sizeof(SW_TASK_TMP_FILE));
        SwooleG.task_tmpdir_len = sizeof(SW_TASK_TMP_FILE);
    }
    //max_connection
    if (sw_zend_hash_find(vht, ZEND_STRS("max_connection"), (void **)&v) == SUCCESS ||
            sw_zend_hash_find(vht, ZEND_STRS("max_conn"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->max_connection = (int)Z_LVAL_PP(v);
    }
    //max_request
    if (sw_zend_hash_find(vht, ZEND_STRS("max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->max_request = (int) Z_LVAL_PP(v);
    }
    //task_max_request
    if (sw_zend_hash_find(vht, ZEND_STRS("task_max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->task_max_request = (int) Z_LVAL_PP(v);
    }
    //cpu affinity
    if (sw_zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_cpu_affinity = (uint8_t) Z_LVAL_PP(v);
    }
    //cpu affinity set
    if (sw_zend_hash_find(vht, ZEND_STRS("cpu_affinity_ignore"), (void **) &v) == SUCCESS)
    {
        int ignore_num = zend_hash_num_elements(Z_ARRVAL_PP(v));
        int available_num = SW_CPU_NUM - ignore_num;
        int *available_cpu = (int *) sw_malloc(sizeof(int) * available_num);
        int flag, i, available_i = 0;

        for (i = 0; i < SW_CPU_NUM; i++)
        {
            flag = 1;
            for (zend_hash_internal_pointer_reset(Z_ARRVAL_PP(v));
            zend_hash_has_more_elements(Z_ARRVAL_PP(v)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_PP(v)))
            {
                zval **zval_core;
                zend_hash_get_current_data(Z_ARRVAL_PP(v), (void** ) &zval_core);
                int core = (int) Z_LVAL_PP(zval_core);
                if (i == core)
                {
                    flag = 0;
                    break;
                }
            }
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
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_tcp_nodelay = (uint8_t) Z_LVAL_PP(v);
    }
    //tcp_defer_accept
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_defer_accept"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->tcp_defer_accept = (uint8_t) Z_LVAL_PP(v);
    }
    //tcp_keepalive
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_keepalive"), (void **)&v) == SUCCESS)
    {
        serv->open_tcp_keepalive = (uint8_t) Z_LVAL_PP(v);
    }
    //buffer: check eof
    if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_eof_check = (uint8_t) Z_LVAL_PP(v);
    }
    //package eof
    if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &v) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("data_eof"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->package_eof_len = Z_STRLEN_PP(v);
        if (serv->package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            RETURN_FALSE;
        }
        bzero(serv->package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(serv->package_eof, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    //buffer: http_protocol
    if (sw_zend_hash_find(vht, ZEND_STRS("open_http_protocol"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_http_protocol = (uint8_t) Z_LVAL_PP(v);
    }
    //buffer: mqtt protocol
    if (sw_zend_hash_find(vht, ZEND_STRS("open_mqtt_protocol"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_mqtt_protocol = (uint8_t) Z_LVAL_PP(v);
    }
    //tcp_keepidle
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepidle"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->tcp_keepidle = (uint16_t)Z_LVAL_PP(v);
    }
    //tcp_keepinterval
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepinterval"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->tcp_keepinterval = (uint16_t)Z_LVAL_PP(v);
    }
    //tcp_keepcount
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepcount"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->tcp_keepcount = (uint16_t)Z_LVAL_PP(v);
    }
    //dispatch_mode
    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_mode"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->dispatch_mode = (int)Z_LVAL_PP(v);
    }

    //open_dispatch_key
    if (sw_zend_hash_find(vht, ZEND_STRS("open_dispatch_key"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_dispatch_key = (int)Z_LVAL_PP(v);
    }

    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_key_type"), (void **)&v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->dispatch_key_type = Z_STRVAL_PP(v)[0];
        serv->dispatch_key_size = swoole_type_size(serv->dispatch_key_type);

        if (serv->dispatch_key_size == 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow dispatch_key_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }

    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_key_offset"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->dispatch_key_offset = (uint16_t) Z_LVAL_PP(v);
    }

    //log_file
    if (sw_zend_hash_find(vht, ZEND_STRS("log_file"), (void **)&v) == SUCCESS)
    {
        convert_to_string(*v);
        if (Z_STRLEN_PP(v) > SW_LOG_FILENAME)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "log_file name to long");
            RETURN_FALSE;
        }
        memcpy(serv->log_file, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    //heartbeat_check_interval
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_check_interval"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->heartbeat_check_interval = (int) Z_LVAL_PP(v);
    }
    //heartbeat idle time
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_idle_time"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->heartbeat_idle_time = (int) Z_LVAL_PP(v);

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
        convert_to_string(*v);
        serv->heartbeat_ping_length = Z_STRLEN_PP(v);
        if (serv->heartbeat_ping_length > SW_HEARTBEAT_PING_LEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat ping package too long");
            RETURN_FALSE;
        }
        memcpy(serv->heartbeat_ping, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    //heartbeat_pong
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_pong"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->heartbeat_pong_length = Z_STRLEN_PP(v);
        if (serv->heartbeat_pong_length > SW_HEARTBEAT_PING_LEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat pong package too long");
            RETURN_FALSE;
        }
        memcpy(serv->heartbeat_pong, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    //open length check
    if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->open_length_check = (uint8_t)Z_LVAL_PP(v);
    }
    //package length size
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **)&v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->package_length_type = Z_STRVAL_PP(v)[0];
        serv->package_length_size = swoole_type_size(serv->package_length_type);

        if (serv->package_length_size == 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }
    //package length offset
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->package_length_offset = (int)Z_LVAL_PP(v);
    }
    //package body start
    if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &v) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("package_body_start"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->package_body_offset = (int) Z_LVAL_PP(v);
    }
    /**
     * package max length
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->package_max_length = (int) Z_LVAL_PP(v);
    }

     /**
     * swoole_packet_mode
     */
   if( serv-> packet_mode == 1)
    {
        serv-> package_max_length = 64*1024*1024;
        serv-> open_length_check = 1;
	serv-> package_length_offset = 0;
	serv-> package_body_offset = 4;
	serv-> package_length_type = 'N';
	serv-> open_eof_check = 0;
    }

    /**
     * buffer input size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_input_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->buffer_input_size = (int) Z_LVAL_PP(v);
    }
    /**
     * buffer output size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_output_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->buffer_output_size = (int) Z_LVAL_PP(v);
    }
    //message queue key
    if (sw_zend_hash_find(vht, ZEND_STRS("message_queue_key"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->message_queue_key = (int) Z_LVAL_PP(v);
    }

#ifdef SW_USE_OPENSSL
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->ssl_cert_file = strdup(Z_STRVAL_PP(v));
        if (access(serv->ssl_cert_file, R_OK) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl cert file[%s] not found.", serv->ssl_cert_file);
            return;
        }
        serv->open_ssl = 1;
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(*v);
        serv->ssl_key_file = strdup(Z_STRVAL_PP(v));
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

    zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_handler)
{
    zval *zobject = getThis();
    char *ha_name = NULL;
    int len, i;
    int ret = -1;
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);

    //必须与define顺序一致
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
    int len, i;
    int ret = -1;
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);

    //必须与define顺序一致
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
        "pipeMessage"
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
    swServer *serv = NULL;
    char *host;
    int host_len;
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
    SWOOLE_GET_SERVER(zobject, serv);
    SW_CHECK_RETURN(swServer_addListener(serv, (int)sock_type, host, (int)port));
}

PHP_METHOD(swoole_server, addprocess)
{
    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. cannot add process.");
        RETURN_FALSE;
    }

    zval *process = NULL;
    swServer *serv = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &process) == FAILURE)
    {
        return;
    }

    SWOOLE_GET_SERVER(getThis(), serv);

    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_class_entry_ptr TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "object is not instanceof swoole_process.");
        RETURN_FALSE;
    }

    if (serv->onUserWorkerStart == NULL)
    {
        serv->onUserWorkerStart = php_swoole_onUserWorkerStart;
    }

    zval_add_ref(&process);

    swWorker *worker = NULL;
    SWOOLE_GET_WORKER(process, worker);

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
    swServer *serv;
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

    SWOOLE_GET_SERVER(zobject, serv);
    php_swoole_register_callback(serv);

    if (php_sw_callback[SW_SERVER_CB_onReceive] == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onReceive callback");
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
    swServer *serv = NULL;
    swFactory *factory = NULL;
    swSendData _send;

    char *send_data;
    int send_len;

    zval *zfd;

    long _fd = 0;
    long from_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ozs|l", &zobject, swoole_server_class_entry_ptr, &zfd, &send_data,
                &send_len, &from_id) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|l", &zfd, &send_data, &send_len, &from_id) == FAILURE)
        {
            return;
        }
    }

    if (send_len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    SWOOLE_GET_SERVER(zobject, serv);
    factory = &(serv->factory);

    if (Z_TYPE_P(zfd) == IS_STRING)
    {
        //unix dgram
        if (!is_numeric_string(Z_STRVAL_P(zfd), Z_STRLEN_P(zfd), &_fd, NULL, 0))
        {
            _send.info.from_fd = (from_id > 0) ? from_id : php_swoole_unix_dgram_fd;
            if (_send.info.from_fd == 0)
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "no unix socket listener.");
                RETURN_FALSE;
            }

            _send.info.fd = (int) _fd;
            _send.info.type = SW_EVENT_UNIX_DGRAM;
            _send.sun_path = Z_STRVAL_P(zfd);
            _send.sun_path_len = Z_STRLEN_P(zfd);
            _send.info.len = send_len;
            _send.data = send_data;
            SW_CHECK_RETURN(factory->finish(factory, &_send));
        }
    }
    else
    {
        _fd = Z_LVAL_P(zfd);
    }

    uint32_t fd = (uint32_t) _fd;

    //UDP
    if (swServer_is_udp(fd))
    {
        if (from_id == -1)
        {
            from_id = php_swoole_udp_from_id;
        }
        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &from_id, sizeof(udp_info));

        _send.info.fd = fd;
        _send.info.from_id = (uint16_t) (udp_info.port);
        _send.info.from_fd = (uint16_t) (udp_info.from_fd);
        _send.info.type = SW_EVENT_UDP;
        _send.data = send_data;
        _send.info.len = send_len;
        swTrace("udp send: fd=%d|from_id=%d|from_fd=%d", _send.info.fd, (uint16_t)_send.info.from_id, _send.info.from_fd);
        SW_CHECK_RETURN(factory->finish(factory, &_send));
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
            uint32_t len_tmp= htonl(send_len);
            swServer_tcp_send(serv, fd, &len_tmp, 4);
        }

        swTrace("tcp send: fd=%d|from_id=%d", _send.info.fd, (uint16_t)_send.info.from_id);
        SW_CHECK_RETURN(swServer_tcp_send(serv, fd, send_data, send_len));
    }
}

PHP_FUNCTION(swoole_server_sendto)
{
    zval *zobject = getThis();
    swServer *serv = NULL;
    swFactory *factory = NULL;
    swSendData _send;

    char *send_data;
    int send_len;

    char* ip;
    char* ip_len;
    long port;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osls", &zobject, swoole_server_class_entry_ptr, &ip, &ip_len,
        		&port, &send_data, &send_len) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &ip, &ip_len,
        		&port, &send_data, &send_len) == FAILURE)
        {
            return;
        }
    }

    if (send_len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    SWOOLE_GET_SERVER(zobject, serv);
    factory = &(serv->factory);

    if (serv->dgram_socket_fd <= 0)
    {
    	php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must add an UDP listener to server before using sendto.");
        RETURN_FALSE;
    }

    struct sockaddr_in addr_in;
    if (inet_aton(ip, &addr_in.sin_addr)==0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "ip is invalid.");
        RETURN_FALSE;
	}
    _send.info.fd = addr_in.sin_addr.s_addr;
	_send.info.from_id = (uint16_t) port;
	_send.info.from_fd = (uint16_t) serv->dgram_socket_fd;
	_send.info.type = SW_EVENT_UDP;
	_send.data = send_data;
	_send.info.len = send_len;
	 swTrace("udp send: fd=%d|from_id=%d|from_fd=%d", _send.info.fd, (uint16_t)_send.info.from_id, _send.info.from_fd);
	 SW_CHECK_RETURN(factory->finish(factory, &_send));
}

PHP_FUNCTION(swoole_server_sendfile)
{
    zval *zobject = getThis();
    swServer *serv;
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
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ols", &zobject, swoole_server_class_entry_ptr, &conn_fd, &filename, &send_data.info.len) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &conn_fd, &filename, &send_data.info.len) == FAILURE)
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

    SWOOLE_GET_SERVER(zobject, serv);

    send_data.info.fd = (int) conn_fd;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, filename, send_data.info.len);
    buffer[send_data.info.len] = 0;
    send_data.info.len++;

    send_data.data = buffer;
    SW_CHECK_RETURN(serv->factory.finish(&serv->factory, &send_data));
}

PHP_FUNCTION(swoole_server_close)
{
    zval *zobject = getThis();
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);
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
    add_assoc_long_ex(return_value, SW_STRL("task_process_num"), SwooleGS->task_workers.run_worker_num);
}

PHP_FUNCTION(swoole_server_reload)
{
    zval *zobject = getThis();
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);

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
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);

    if (serv->heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    array_init(return_value);

    int fd;
    int checktime = (int) SwooleGS->now - serv->heartbeat_idle_time;

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        swTrace("heartbeat check fd=%d", fd);
        swConnection *conn = &serv->connection_list[fd];

        if (1 == conn->active && conn->last_time < checktime)
        {
            /**
             * Close the connection
             */
            if (close_connection)
            {
                serv->factory.end(&serv->factory, fd);
                if (serv->onClose != NULL)
                {
                    serv->onClose(serv, fd, conn->from_id);
                }
            }
            add_next_index_long(return_value, fd);
        }
    }
}

PHP_FUNCTION(swoole_server_gettimer)
{
    zval *zobject = getThis();
    swServer *serv = NULL;
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
    SWOOLE_GET_SERVER(zobject, serv);

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
    swServer *serv = NULL;
    long interval;

    if (swIsMaster())
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "master process cannot use timer.");
        RETURN_FALSE;
    }

    if (SwooleG.serv->onTimer == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no onTimer callback, cannot use addtimer.");
        RETURN_FALSE;
    }

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
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

    SWOOLE_GET_SERVER(zobject, serv);
    php_swoole_check_timer(interval);
    SW_CHECK_RETURN(SwooleG.timer.add(&SwooleG.timer, (int )interval, 1, NULL));
}

PHP_FUNCTION(swoole_server_taskwait)
{
    zval *zobject = getThis();
    swEventData buf;
    swServer *serv;

    zval **data;
    smart_str serialized_data = {0};
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
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "OZ|dl", &zobject, swoole_server_class_entry_ptr, &data, &timeout, &worker_id) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|dl", &data, &timeout, &worker_id) == FAILURE)
        {
            return;
        }
    }

    SWOOLE_GET_SERVER(zobject, serv);

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
    if (Z_TYPE_PP(data) != IS_STRING)
    {
        //serialize
        swTask_type(&buf) |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        task_data_str = serialized_data.c;
        task_data_len = serialized_data.len;
    }
    else
    {
        task_data_str = Z_STRVAL_PP(data);
        task_data_len = Z_STRLEN_PP(data);
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
            zval *task_notify_data, *task_notify_unserialized_data;
            char *task_notify_data_str;
            int task_notify_data_len = 0;
            php_unserialize_data_t var_hash;
            /**
             * Large result package
             */        
            if (task_result->info.type & SW_TASK_TMPFILE)
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
					RETURN_FALSE;
                }
                task_notify_data_str = data_str;
                task_notify_data_len = data_len;
            }
            else
            {
                task_notify_data_str = task_result->data;
                task_notify_data_len = task_result->info.len;
            }

            //TODO unserialize
            if (swTask_type(task_result) & SW_TASK_SERIALIZE)
            {
                PHP_VAR_UNSERIALIZE_INIT(var_hash);
                ALLOC_INIT_ZVAL(task_notify_unserialized_data);

                if (php_var_unserialize(&task_notify_unserialized_data, (const unsigned char **) &task_notify_data_str,
                        (const unsigned char *) (task_notify_data_str + task_notify_data_len), &var_hash TSRMLS_CC))
                {
                    task_notify_data = task_notify_unserialized_data;
                }
                else
                {
                    MAKE_STD_ZVAL(task_notify_data);
                    SW_ZVAL_STRINGL(task_notify_data, task_notify_data_str, task_notify_data_len, 1);
                }
                PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
            }
            else
            {
                MAKE_STD_ZVAL(task_notify_data);
                SW_ZVAL_STRINGL(task_notify_data, task_notify_data_str, task_notify_data_len, 1);
            }
            
            RETURN_ZVAL(task_notify_data, 0, 0);
        }
        else
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(swoole_server_task)
{
    zval *zobject = getThis();
    swEventData buf;
    swServer *serv;
    zval **data;
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
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "OZ|l", &zobject, swoole_server_class_entry_ptr, &data, &worker_id) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|l", &data, &worker_id) == FAILURE)
        {
            return;
        }
    }

    SWOOLE_GET_SERVER(zobject, serv);

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
    if (Z_TYPE_PP(data) != IS_STRING)
    {
        //serialize
        swTask_type(&buf) |= SW_TASK_SERIALIZE;
        //TODO php serialize
        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

        task_data_str = serialized_data.c;
        task_data_len = serialized_data.len;
    }
    else
    {
        task_data_str = Z_STRVAL_PP(data);
        task_data_len = Z_STRLEN_PP(data);
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
    swServer *serv;

    char *msg;
    int msglen;
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

    SWOOLE_GET_SERVER(zobject, serv);
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
    swServer *serv = NULL;

    zval **data;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "OZ", &zobject, swoole_server_class_entry_ptr, &data) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z", &data) == FAILURE)
        {
            return;
        }
    }

    SWOOLE_GET_SERVER(zobject, serv);
    SW_CHECK_RETURN(php_swoole_task_finish(serv, data TSRMLS_CC));
}

PHP_METHOD(swoole_server, bind)
{
    zval *zobject = getThis();
    swServer *serv;
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

    SWOOLE_GET_SERVER(zobject, serv);

    swConnection *conn = swServer_connection_get(serv, fd);

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
    SwooleG.lock.lock(&SwooleG.lock);
    if (conn->uid == 0)
    {
        conn->uid = uid;
        ret = 1;
    }
    SwooleG.lock.unlock(&SwooleG.lock);
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_connection_info)
{
    zval *zobject = getThis();
    swServer *serv;
    zend_bool noCheckConnection = 0;
    long fd = 0;
    long from_id = -1;

    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol|lb", &zobject, swoole_server_class_entry_ptr, &fd, &from_id, &noCheckConnection) == FAILURE)
        {
            return;
        }
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|lb", &fd, &from_id, &noCheckConnection) == FAILURE)
        {
            return;
        }
    }
    SWOOLE_GET_SERVER(zobject, serv);

    //udp client
    if (swServer_is_udp(fd))
    {
        array_init(return_value);
        php_swoole_udp_t udp_info;
        if (from_id < 0)
        {
            from_id = php_swoole_udp_from_id;
        }
        memcpy(&udp_info, &from_id, sizeof(udp_info));

        swConnection *from_sock = swServer_connection_get(serv, udp_info.from_fd);
        struct in_addr sin_addr;
        sin_addr.s_addr = fd;
        if (from_sock != NULL)
        {
            add_assoc_long(return_value, "from_fd", udp_info.from_fd);
            add_assoc_long(return_value, "from_port", from_sock->addr.sin_port);
        }
        if (from_id != 0)
        {
            add_assoc_long(return_value, "remote_port", udp_info.port);
        }
        sw_add_assoc_string(return_value, "remote_ip", inet_ntoa(sin_addr), 1);
        return;
    }

#ifdef SW_REACTOR_USE_SESSION
    fd = swServer_get_fd(serv, fd);
#endif

    swConnection *conn = swServer_connection_get(serv, fd);
    //connection is closed
    if (conn->active == 0 && !noCheckConnection)
    {
        RETURN_FALSE;
    }
    else
    {
        array_init(return_value);
        add_assoc_long(return_value, "uid", conn->uid);
        add_assoc_long(return_value, "from_id", conn->from_id);
        add_assoc_long(return_value, "from_fd", conn->from_fd);
        add_assoc_long(return_value, "connect_time", conn->connect_time);
        add_assoc_long(return_value, "last_time", conn->last_time);
        add_assoc_long(return_value, "websocket_status", conn->websocket_status);
        add_assoc_long(return_value, "from_port", serv->connection_list[conn->from_fd].addr.sin_port);
        add_assoc_long(return_value, "remote_port", ntohs(conn->addr.sin_port));
        sw_add_assoc_string(return_value, "remote_ip", inet_ntoa(conn->addr.sin_addr), 1);
    }
}

PHP_FUNCTION(swoole_connection_list)
{
    zval *zobject = getThis();
    swServer *serv;
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
    SWOOLE_GET_SERVER(zobject, serv);

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


PHP_FUNCTION(swoole_server_shutdown)
{
    zval *zobject = getThis();
    swServer *serv;

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
    SWOOLE_GET_SERVER(zobject, serv);
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
