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
#include "connection.h"

#include "websocket.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#endif
#include "ext/standard/php_var.h"
#include "zend_smart_str.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

typedef struct
{
    int current_fd;
    int max_fd;
    uint32_t session_id;
    swServer *serv;
    swListenPort *port;
    int end;
    int index;
} swConnectionIterator;

static int php_swoole_task_id = 0;
static int udp_server_socket;
static int dgram_server_socket;

struct
{
    zval *zobjects[SW_MAX_LISTEN_PORT];
    zval *zports;
    uint8_t num;
    swoole_server_port_property *primary_port;
} server_port_list;

zval *php_sw_server_callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];
zval _php_sw_server_callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];
zend_fcall_info_cache *php_sw_server_caches[PHP_SWOOLE_SERVER_CALLBACK_NUM];

static swHashMap *task_callbacks = NULL;
#ifdef SW_COROUTINE
static swHashMap *task_coroutine_map = NULL;
static swHashMap *send_coroutine_map = NULL;
#endif

#ifdef SW_COROUTINE
typedef struct
{
    php_context context;
    int *list;
    int count;
    zval *result;
    swTimer_node *timer;
} swTaskCo;
#endif

static int php_swoole_task_finish(swServer *serv, zval *data, swEventData *current_task);
static void php_swoole_onPipeMessage(swServer *serv, swEventData *req);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onWorkerStart(swServer *, int worker_id);
static void php_swoole_onWorkerStop(swServer *, int worker_id);
static void php_swoole_onWorkerExit(swServer *serv, int worker_id);
static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker);
static int php_swoole_onTask(swServer *, swEventData *task);
static int php_swoole_onFinish(swServer *, swEventData *task);
static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo);
static void php_swoole_onManagerStart(swServer *serv);
static void php_swoole_onManagerStop(swServer *serv);

#ifdef SW_COROUTINE
static void php_swoole_onConnect_finish(void *param);
static void php_swoole_onSendTimeout(swTimer *timer, swTimer_node *tnode);
static int php_swoole_server_send_resume(swServer *serv, php_context *context, int fd);
static void php_swoole_task_onTimeout(swTimer *timer, swTimer_node *tnode);
#endif

static zval* php_swoole_server_add_port(swServer *serv, swListenPort *port);

static inline zend_bool php_swoole_server_isset_callback(swListenPort *port, int event_type)
{
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (property->callbacks[event_type] || server_port_list.primary_port->callbacks[event_type])
    {
        return SW_TRUE;
    }
    else
    {
        return SW_FALSE;
    }
}

zval* php_swoole_server_get_callback(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    if (!port)
    {
        swWarn("invalid server_fd[%d].", server_fd);
        return NULL;
    }
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (!property)
    {
        goto _primary_port;
    }
    zval *callback = property->callbacks[event_type];
    if (!callback)
    {
        _primary_port: return server_port_list.primary_port->callbacks[event_type];
    }
    else
    {
        return callback;
    }
}

zend_fcall_info_cache* php_swoole_server_get_cache(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    if (!port)
    {
        swWarn("invalid server_fd[%d].", server_fd);
        return NULL;
    }
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (!property)
    {
        goto _primary_port;
    }
    zend_fcall_info_cache* cache = property->caches[event_type];
    if (!cache)
    {
        _primary_port: return server_port_list.primary_port->caches[event_type];
    }
    else
    {
        return cache;
    }
}

static int php_swoole_create_dir(const char* path, size_t length)
{
    if (access(path, F_OK) == 0)
    {
        return 0;
    }
#if 1
    return php_stream_mkdir(path, 0777, PHP_STREAM_MKDIR_RECURSIVE | REPORT_ERRORS, NULL) ? 0 : -1;
#else
    int     startpath;
    int     endpath;
    int     i            = 0;
    int     pathlen      = length;
    char    curpath[128] = {0};
    if ('/' != path[0])
    {
        if (getcwd(curpath, sizeof(curpath)) == NULL)
        {
            swoole_php_sys_error(E_WARNING, "getcwd() failed.");
            return -1;
        }
        strcat(curpath, "/");
        startpath   = strlen(curpath);
        strcat(curpath, path);
        if (path[pathlen] != '/')
        {
            strcat(curpath, "/");
        }
        endpath = strlen(curpath);
    }
    else
    {
        strcpy(curpath, path);
        if (path[pathlen] != '/')
        {
            strcat(curpath, "/");
        }
        startpath    = 1;
        endpath      = strlen(curpath);
    }
    for (i = startpath; i < endpath ; i++ )
    {
        if ('/' == curpath[i])
        {
            curpath[i] = '\0';
            if (access(curpath, F_OK) != 0)
            {
                if (mkdir(curpath, 0755) == -1)
                {
                    swoole_php_sys_error(E_WARNING, "mkdir(%s, 0755).", path);
                    return -1;
                }
            }
            curpath[i] = '/';
        }
    }
    return 0;
#endif
}

int php_swoole_task_pack(swEventData *task, zval *data)
{
    smart_str serialized_data = { 0 };
    php_serialize_data_t var_hash;
    zend_string *serialized_string = NULL;

    task->info.type = SW_EVENT_TASK;
    //field fd save task_id
    task->info.fd = php_swoole_task_id++;
    if (unlikely(php_swoole_task_id >= SW_MAX_INT))
    {
        php_swoole_task_id = 0;
    }
    //field from_id save the worker_id
    task->info.from_id = SwooleWG.id;
    swTask_type(task) = 0;

    char *task_data_str;
    int task_data_len = 0;
    //need serialize
    if (Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(task) |= SW_TASK_SERIALIZE;

        if (SWOOLE_G(fast_serialize))
        {
            serialized_string = php_swoole_serialize(data);
            task_data_str = serialized_string->val;
            task_data_len = serialized_string->len;
        }
        else
        {
            PHP_VAR_SERIALIZE_INIT(var_hash);
            php_var_serialize(&serialized_data, data, &var_hash);
            PHP_VAR_SERIALIZE_DESTROY(var_hash);

            if (!serialized_data.s)
            {
                return -1;
            }
            task_data_str = serialized_data.s->val;
            task_data_len = serialized_data.s->len;
        }
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    if (task_data_len >= SW_IPC_MAX_SIZE - sizeof(task->info))
    {
        if (swTaskWorker_large_pack(task, task_data_str, task_data_len) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "large task pack failed.");
            task->info.fd = SW_ERR;
            task->info.len = 0;
        }
    }
    else
    {
        memcpy(task->data, task_data_str, task_data_len);
        task->info.len = task_data_len;
    }

    if (SWOOLE_G(fast_serialize) && serialized_string)
    {
        zend_string_release(serialized_string);
    }
    else
    {
        smart_str_free(&serialized_data);
    }
    return task->info.fd;
}

void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length)
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
        swString *worker_buffer = swWorker_get_buffer(SwooleG.serv, req->info.from_id);
        data_ptr = worker_buffer->str;
        data_len = worker_buffer->length;
    }
#endif
    else
    {
        data_ptr = req->data;
        data_len = req->info.len;
    }

    if (header_length >= data_len)
    {
        ZVAL_STRING(zdata, "");
    }
    else
    {
        ZVAL_STRINGL(zdata, data_ptr + header_length, data_len - header_length);
    }

    if (header_length > 0)
    {
        memcpy(header, data_ptr, header_length);
    }

#ifdef SW_USE_RINGBUFFER
    if (req->info.type == SW_EVENT_PACKAGE)
    {
        swReactorThread *thread = swServer_get_thread(SwooleG.serv, req->info.from_id);
        thread->buffer_input->free(thread->buffer_input, data_ptr);
    }
#endif
}

size_t php_swoole_get_send_data(zval *zdata, char **str)
{
    size_t length;

    if (Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_buffer_class_entry_ptr))
    {
        swString *str_buffer = swoole_get_object(zdata);
        length = str_buffer->length - str_buffer->offset;
        *str = str_buffer->str + str_buffer->offset;
    }
    else
    {
        convert_to_string(zdata);
        length = Z_STRLEN_P(zdata);
        *str = Z_STRVAL_P(zdata);
    }

    return length;
}

static sw_inline int php_swoole_check_task_param(swServer *serv, int dst_worker_id)
{
    if (serv->task_worker_num < 1)
    {
        swoole_php_fatal_error(E_WARNING, "task method can't be executed, please set 'task_worker_num' > 0.");
        return SW_ERR;
    }

    if (dst_worker_id >= serv->task_worker_num)
    {
        swoole_php_fatal_error(E_WARNING, "worker_id must be less than serv->task_worker_num.");
        return SW_ERR;
    }

    if (!swIsWorker())
    {
        swoole_php_fatal_error(E_WARNING, "task method can only be used in the worker process.");
        return SW_ERR;
    }

    return SW_OK;
}

zval* php_swoole_task_unpack(swEventData *task_result)
{
    zval *result_data, *result_unserialized_data;
    char *result_data_str;
    int result_data_len = 0;
    php_unserialize_data_t var_hash;
    swString *large_packet;

    /**
     * Large result package
     */
    if (swTask_type(task_result) & SW_TASK_TMPFILE)
    {
        large_packet = swTaskWorker_large_unpack(task_result);
        /**
         * unpack failed
         */
        if (large_packet == NULL)
        {
            return NULL;
        }
        result_data_str = large_packet->str;
        result_data_len = large_packet->length;
    }
    else
    {
        result_data_str = task_result->data;
        result_data_len = task_result->info.len;
    }

    if (swTask_type(task_result) & SW_TASK_SERIALIZE)
    {
        SW_ALLOC_INIT_ZVAL(result_unserialized_data);

        if (SWOOLE_G(fast_serialize))
        {
            if (php_swoole_unserialize(result_data_str, result_data_len, result_unserialized_data, NULL, 0))
            {
                result_data = result_unserialized_data;
            }
            else
            {
                SW_ALLOC_INIT_ZVAL(result_data);
                ZVAL_STRINGL(result_data, result_data_str, result_data_len);
            }
        }
        else
        {
            PHP_VAR_UNSERIALIZE_INIT(var_hash);
            //unserialize success
            if (php_var_unserialize(
                    *&result_unserialized_data,
                    (const unsigned char **) &result_data_str,
                    (const unsigned char *) (result_data_str + result_data_len),
                    &var_hash
                )
            )
            {
                result_data = result_unserialized_data;
            }
            //failed
            else
            {
                SW_ALLOC_INIT_ZVAL(result_data);
                ZVAL_STRINGL(result_data, result_data_str, result_data_len);
            }
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        }
    }
    else
    {
        SW_ALLOC_INIT_ZVAL(result_data);
        ZVAL_STRINGL(result_data, result_data_str, result_data_len);
    }
    return result_data;
}

static void php_swoole_task_wait_co(swServer *serv, swEventData *req, double timeout, int dst_worker_id, INTERNAL_FUNCTION_PARAMETERS)
{
    swTask_type(req) |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);

    swTaskCo *task_co = emalloc(sizeof(swTaskCo));

    task_co->result = NULL;
    task_co->list = NULL;
    task_co->count = 1;
    task_co->context.state = SW_CORO_CONTEXT_RUNNING;
    Z_LVAL(task_co->context.coro_params) = req->info.fd;

    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
    if (swProcessPool_dispatch(&serv->gs->task_workers, req, &dst_worker_id) < 0)
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        RETURN_FALSE;
    }
    else
    {
        swHashMap_add_int(task_coroutine_map, req->info.fd, task_co);
    }

    int ms = (int) (timeout * 1000);
    swTimer_node *timer = swTimer_add(&SwooleG.timer, ms, 0, task_co, php_swoole_task_onTimeout);
    if (timer)
    {
        task_co->timer = timer;
    }
    coro_save(&task_co->context);
    coro_yield();
}

#ifdef SW_COROUTINE
static void php_swoole_task_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swTaskCo *task_co = (swTaskCo *) tnode->data;
    php_context *context = &task_co->context;
    zval *retval = NULL;

    //Server->taskwait, single task
    if (task_co->list == NULL)
    {
        zval result;
        ZVAL_FALSE(&result);
        int ret = coro_resume(context, &result, &retval);
        if (ret == CORO_END && retval)
        {
            zval_ptr_dtor(retval);
        }
        efree(task_co);
        swHashMap_del_int(task_coroutine_map, Z_LVAL(context->coro_params));
        return;
    }

    int i;
    zval *result = task_co->result;

    for (i = 0; i < task_co->count; i++)
    {
        if (!zend_hash_index_exists(Z_ARRVAL_P(result), i))
        {
            add_index_bool(result, i, 0);
            swHashMap_del_int(task_coroutine_map, task_co->list[i]);
        }
    }

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    sw_zval_free(result);
    efree(task_co);
}
#endif

static zval* php_swoole_server_add_port(swServer *serv, swListenPort *port)
{
    zval *port_object;
    SW_ALLOC_INIT_ZVAL(port_object);
    object_init_ex(port_object, swoole_server_port_class_entry_ptr);
    server_port_list.zobjects[server_port_list.num++] = port_object;

    swoole_server_port_property *property = emalloc(sizeof(swoole_server_port_property));
    bzero(property, sizeof(swoole_server_port_property));
    swoole_set_property(port_object, 0, property);
    swoole_set_object(port_object, port);
    property->serv = serv;
    property->port = port;

    port->ptr = property;

    zend_update_property_string(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("host"), port->host);
    zend_update_property_long(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("port"), port->port);
    zend_update_property_long(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("type"), port->type);
    zend_update_property_long(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("sock"), port->sock);

    zval *connection_iterator;
    SW_MAKE_STD_ZVAL(connection_iterator);
    object_init_ex(connection_iterator, swoole_connection_iterator_class_entry_ptr);
    zend_update_property(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("connections"), connection_iterator);

    swConnectionIterator *i = emalloc(sizeof(swConnectionIterator));
    bzero(i, sizeof(swConnectionIterator));
    i->port = port;
    i->serv = serv;
    swoole_set_object(connection_iterator, i);

    add_next_index_zval(server_port_list.zports, port_object);

    return port_object;
}

void php_swoole_server_before_start(swServer *serv, zval *zobject)
{
    /**
     * create swoole server
     */
    if (swServer_create(serv) < 0)
    {
        swoole_php_fatal_error(E_ERROR, "failed to create the server. Error: %s", sw_error);
        return;
    }

    swTrace("Create swoole_server host=%s, port=%d, mode=%d, type=%d", serv->listen_list->host, (int) serv->listen_list->port, serv->factory_mode, (int) serv->listen_list->type);

    Z_TRY_ADDREF_P(zobject);
    serv->ptr2 = sw_zval_dup(zobject);

#ifdef SW_COROUTINE
    coro_init();
    if (serv->send_yield)
    {
        send_coroutine_map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
        if (send_coroutine_map == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "failed to create send_coroutine_map. Error: %s", sw_error);
        }
        if (serv->onClose == NULL)
        {
            serv->onClose = php_swoole_onClose;
        }
    }
#endif

    /**
     * Master Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zobject, ZEND_STRL("master_pid"), getpid());

    zval *zsetting = sw_zend_read_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), 1);
    if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
    {
        SW_ALLOC_INIT_ZVAL(zsetting);
        array_init(zsetting);
#ifdef HT_ALLOW_COW_VIOLATION
        HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(zsetting));
#endif
        zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zsetting);
    }

    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("worker_num")))
    {
        add_assoc_long(zsetting, "worker_num", serv->worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("task_worker_num")))
    {
        add_assoc_long(zsetting, "task_worker_num", serv->task_worker_num);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("buffer_output_size")))
    {
        add_assoc_long(zsetting, "buffer_output_size", serv->buffer_output_size);
    }
    if (!zend_hash_str_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("max_connection")))
    {
        add_assoc_long(zsetting, "max_connection", serv->max_connection);
    }
#ifdef HAVE_PTRACE
    //trace request
    if (serv->request_slowlog_file && (serv->trace_event_worker || serv->task_worker_num > 0))
    {
        serv->manager_alarm = serv->request_slowlog_timeout;
        if (swServer_add_hook(serv, SW_SERVER_HOOK_MANAGER_TIMER, php_swoole_trace_check, 1) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "Unable to add server hook.");
            return;
        }
    }
#endif

    int i;
    zval *retval = NULL;
    zval *zport_object;
    zval *zport_setting;
    swListenPort *port;
    zend_bool find_http_port = SW_FALSE;

    for (i = 1; i < server_port_list.num; i++)
    {
        zport_object = server_port_list.zobjects[i];
        zport_setting = sw_zend_read_property(swoole_server_port_class_entry_ptr, zport_object, ZEND_STRL("setting"), 1);
        //use swoole_server->setting
        if (zport_setting == NULL || ZVAL_IS_NULL(zport_setting))
        {
            Z_TRY_ADDREF_P(zport_object);
            sw_zend_call_method_with_1_params(&zport_object, swoole_server_port_class_entry_ptr, NULL, "set", &retval, zsetting);
            if (retval != NULL)
            {
                zval_ptr_dtor(retval);
            }
        }
    }

    for (i = 0; i < server_port_list.num; i++)
    {
        zport_object = server_port_list.zobjects[i];
        port = swoole_get_object(zport_object);
        if (port->open_websocket_protocol || port->open_http_protocol)
        {
            find_http_port = SW_TRUE;
            if (port->open_websocket_protocol)
            {
                if (!php_swoole_server_isset_callback(port, SW_SERVER_CB_onMessage))
                {
                    swoole_php_fatal_error(E_ERROR, "require onMessage callback");
                    return;
                }
            }
            else if (port->open_http_protocol && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onRequest))
            {
                swoole_php_fatal_error(E_ERROR, "require onRequest callback");
                return;
            }
        }
        else if (!port->open_redis_protocol)
        {
            if (swSocket_is_dgram(port->type) && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onPacket))
            {
                swoole_php_fatal_error(E_ERROR, "require onPacket callback");
                return;
            }
            if (swSocket_is_stream(port->type) && !php_swoole_server_isset_callback(port, SW_SERVER_CB_onReceive))
            {
                swoole_php_fatal_error(E_ERROR, "require onReceive callback");
                return;
            }
        }
    }

    if (find_http_port)
    {
        serv->onReceive = php_swoole_http_onReceive;
        serv->onClose = php_swoole_http_onClose;
        php_swoole_http_server_before_start(serv, zobject);
    }
}

void php_swoole_register_callback(swServer *serv)
{
    /*
     * optional callback
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onStart] != NULL)
    {
        serv->onStart = php_swoole_onStart;
    }
    serv->onShutdown = php_swoole_onShutdown;
    /**
     * require callback, set the master/manager/worker PID
     */
    serv->onWorkerStart = php_swoole_onWorkerStart;

    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerStop] != NULL)
    {
        serv->onWorkerStop = php_swoole_onWorkerStop;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerExit] != NULL)
    {
        serv->onWorkerExit = php_swoole_onWorkerExit;
    }
    /**
     * Task Worker
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onTask] != NULL)
    {
        serv->onTask = php_swoole_onTask;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onFinish] != NULL)
    {
        serv->onFinish = php_swoole_onFinish;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerError] != NULL)
    {
        serv->onWorkerError = php_swoole_onWorkerError;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onManagerStart] != NULL)
    {
        serv->onManagerStart = php_swoole_onManagerStart;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onManagerStop] != NULL)
    {
        serv->onManagerStop = php_swoole_onManagerStop;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage] != NULL)
    {
        serv->onPipeMessage = php_swoole_onPipeMessage;
    }
    if (serv->send_yield)
    {
        serv->onBufferEmpty = php_swoole_onBufferEmpty;
    }
}

static int php_swoole_task_finish(swServer *serv, zval *data, swEventData *current_task)
{
    int flags = 0;
    smart_str serialized_data = {0};
    php_serialize_data_t var_hash;
    char *data_str;
    int data_len = 0;
    int ret;

    zend_string *serialized_string = NULL;

    //need serialize
    if (Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        flags |= SW_TASK_SERIALIZE;
        if (SWOOLE_G(fast_serialize))
        {
            serialized_string = php_swoole_serialize(data);
            data_str = serialized_string->val;
            data_len = serialized_string->len;
        }
        else
        {
            PHP_VAR_SERIALIZE_INIT(var_hash);
            php_var_serialize(&serialized_data, data, &var_hash);
            PHP_VAR_SERIALIZE_DESTROY(var_hash);
            data_str = serialized_data.s->val;
            data_len = serialized_data.s->len;
        }
    }
    else
    {
        data_str = Z_STRVAL_P(data);
        data_len = Z_STRLEN_P(data);
    }

    ret = swTaskWorker_finish(serv, data_str, data_len, flags, current_task);
    if (SWOOLE_G(fast_serialize) && serialized_string)
    {
        zend_string_release(serialized_string);
    }
    else
    {
        smart_str_free(&serialized_data);
    }
    return ret;
}

static void php_swoole_onPipeMessage(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, (long) req->info.from_id);

    zval *zdata = php_swoole_task_unpack(req);
    if (zdata == NULL)
    {
        return;
    }

    if (SwooleG.enable_coroutine)
    {
        zval *args[3];
        args[0] = zserv;
        args[1] = zworker_id;
        args[2] = zdata;

        zend_fcall_info_cache *cache = php_sw_server_caches[SW_SERVER_CB_onPipeMessage];
        int ret = coro_create(cache, args, 3, &retval, NULL, NULL);
        if (ret < 0)
        {
            zval_ptr_dtor(zworker_id);
            sw_zval_free(zdata);
            if (ret == CORO_LIMIT)
            {
                swWarn("Failed to handle onPipeMessage. Coroutine limited");
            }
            return;
        }
    }
    else
    {
        zval args[3];
        args[0] = *zserv;
        args[1] = *zworker_id;
        args[2] = *zdata;

        swTrace("PipeMessage: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

        if (sw_call_user_function_fast_ex(php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage], php_sw_server_caches[SW_SERVER_CB_onPipeMessage], &retval, 3, args) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onPipeMessage handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(zworker_id);
    sw_zval_free(zdata);

    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

int php_swoole_onReceive(swServer *serv, swEventData *req)
{
    swFactory *factory = &serv->factory;
    zval *zserv = (zval *) serv->ptr2;

    zval *zfd;
    zval *zfrom_id;
    zval *zdata;
    zval *retval = NULL;


    php_swoole_udp_t udp_info;
    swDgramPacket *packet;

    SW_MAKE_STD_ZVAL(zfd);
    SW_MAKE_STD_ZVAL(zfrom_id);
    SW_MAKE_STD_ZVAL(zdata);

    //dgram
    if (swEventData_is_dgram(req->info.type))
    {
        swoole_php_error(E_DEPRECATED, "The udp onReceive callback is deprecated, use onPacket instead.");

        swString *buffer = swWorker_get_buffer(serv, req->info.from_id);
        packet = (swDgramPacket*) buffer->str;

        //udp ipv4
        if (req->info.type == SW_EVENT_UDP)
        {
            udp_info.from_fd = req->info.from_fd;
            udp_info.port = packet->port;
            memcpy(&udp_server_socket, &udp_info, sizeof(udp_server_socket));
            factory->last_from_id = udp_server_socket;
            swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);
            ZVAL_STRINGL(zdata, packet->data, packet->length);
            ZVAL_LONG(zfrom_id, (long ) udp_server_socket);
            ZVAL_LONG(zfd, (long ) packet->addr.v4.s_addr);
        }
        //udp ipv6
        else if (req->info.type == SW_EVENT_UDP6)
        {
            udp_info.from_fd = req->info.from_fd;
            udp_info.port = packet->port;
            memcpy(&dgram_server_socket, &udp_info, sizeof(udp_server_socket));
            factory->last_from_id = dgram_server_socket;

            swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);

            ZVAL_LONG(zfrom_id, (long ) dgram_server_socket);
            char tmp[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &packet->addr.v6, tmp, sizeof(tmp));
            ZVAL_STRING(zfd, tmp);
            ZVAL_STRINGL(zdata, packet->data, packet->length);
        }
        //unix dgram
        else
        {
            ZVAL_STRINGL(zfd, packet->data, packet->addr.un.path_length);
            ZVAL_STRINGL(zdata, packet->data + packet->addr.un.path_length, packet->length - packet->addr.un.path_length);
            ZVAL_LONG(zfrom_id, (long ) req->info.from_fd);
            dgram_server_socket = req->info.from_fd;
        }
    }
    //stream
    else
    {
        ZVAL_LONG(zfrom_id, (long ) req->info.from_id);
        ZVAL_LONG(zfd, (long ) req->info.fd);
        php_swoole_get_recv_data(zdata, req, NULL, 0);
    }

    if (SwooleG.enable_coroutine)
    {
        zval *args[4];
        args[0] = zserv;
        args[1] = zfd;
        args[2] = zfrom_id;
        args[3] = zdata;

        zend_fcall_info_cache *cache = php_swoole_server_get_cache(serv, req->info.from_fd, SW_SERVER_CB_onReceive);
        int ret = coro_create(cache, args, 4, &retval, NULL, NULL);
        if (ret < 0)
        {
            zval_ptr_dtor(zfd);
            zval_ptr_dtor(zfrom_id);
            zval_ptr_dtor(zdata);
            if (ret == CORO_LIMIT)
            {
                serv->factory.end(&SwooleG.serv->factory, req->info.fd);
            }
            return SW_OK;
        }
    }
    else
    {
        zval args[4];
        zval *callback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onReceive);
        if (callback == NULL || ZVAL_IS_NULL(callback))
        {
            swoole_php_fatal_error(E_WARNING, "onReceive callback is null.");
            return SW_OK;
        }

        args[0] = *zserv;
        args[1] = *zfd;
        args[2] = *zfrom_id;
        args[3] = *zdata;

        zend_fcall_info_cache *fci_cache = php_swoole_server_get_cache(serv, req->info.from_fd, SW_SERVER_CB_onReceive);
        if (sw_call_user_function_fast_ex(callback, fci_cache, &retval, 4, args) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onReceive handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zfd);
    zval_ptr_dtor(zfrom_id);
    zval_ptr_dtor(zdata);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

int php_swoole_onPacket(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zdata;
    zval *zaddr;
    zval *retval = NULL;
    swDgramPacket *packet;


    SW_MAKE_STD_ZVAL(zdata);
    SW_MAKE_STD_ZVAL(zaddr);
    array_init(zaddr);

    swString *buffer = swWorker_get_buffer(serv, req->info.from_id);
    packet = (swDgramPacket*) buffer->str;

    add_assoc_long(zaddr, "server_socket", req->info.from_fd);
    swConnection *from_sock = swServer_connection_get(serv, req->info.from_fd);
    if (from_sock)
    {
        add_assoc_long(zaddr, "server_port", swConnection_get_port(from_sock));
    }

    char address[INET6_ADDRSTRLEN];

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        inet_ntop(AF_INET, &packet->addr.v4, address, sizeof(address));
        add_assoc_string(zaddr, "address", address);
        add_assoc_long(zaddr, "port", packet->port);
        ZVAL_STRINGL(zdata, packet->data, packet->length);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        inet_ntop(AF_INET6, &packet->addr.v6, address, sizeof(address));
        add_assoc_string(zaddr, "address", address);
        add_assoc_long(zaddr, "port", packet->port);
        ZVAL_STRINGL(zdata, packet->data, packet->length);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        add_assoc_stringl(zaddr, "address", packet->data, packet->addr.un.path_length);
        ZVAL_STRINGL(zdata, packet->data + packet->addr.un.path_length, packet->length - packet->addr.un.path_length);
        dgram_server_socket = req->info.from_fd;
    }

    if (SwooleG.enable_coroutine)
    {
        zval *args[3];
        args[0] = zserv;
        args[1] = zdata;
        args[2] = zaddr;

        zend_fcall_info_cache *cache = php_swoole_server_get_cache(serv, req->info.from_fd, SW_SERVER_CB_onPacket);
        int ret = coro_create(cache, args, 3, &retval, NULL, NULL);
        if (ret < 0)
        {
            zval_ptr_dtor(zaddr);
            zval_ptr_dtor(zdata);
            return SW_OK;
        }
    }
    else
    {
        zval args[3];
        args[0] = *zserv;
        args[1] = *zdata;
        args[2] = *zaddr;

        zval *callback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onPacket);
        if (callback == NULL || ZVAL_IS_NULL(callback))
        {
            swoole_php_fatal_error(E_WARNING, "onPacket callback is null.");
            return SW_OK;
        }

        if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onPacket handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zaddr);
    zval_ptr_dtor(zdata);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

static int php_swoole_onTask(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[4];

    zval *zfd;
    zval *zworker_id;

    sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);

    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, (long) req->info.fd);

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, (long) req->info.from_id);

    zval *zdata = php_swoole_task_unpack(req);
    if (zdata == NULL)
    {
        return SW_ERR;
    }

    args[0] = *zserv;
    args[1] = *zfd;
    args[2] = *zworker_id;
    args[3] = *zdata;

    zend_fcall_info_cache *fci_cache = php_sw_server_caches[SW_SERVER_CB_onTask];
    if (sw_call_user_function_fast_ex(php_sw_server_callbacks[SW_SERVER_CB_onTask], fci_cache, &retval, 4, args) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onTask handler error.");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(zfd);
    zval_ptr_dtor(zworker_id);
    sw_zval_free(zdata);

    if (retval)
    {
        if (Z_TYPE_P(retval) != IS_NULL)
        {
            php_swoole_task_finish(serv, retval, req);
        }
        zval_ptr_dtor(retval);
    }

    return SW_OK;
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[3];

    zval *ztask_id;
    zval *zdata;
    zval *retval = NULL;


    SW_MAKE_STD_ZVAL(ztask_id);
    ZVAL_LONG(ztask_id, (long) req->info.fd);

    zdata = php_swoole_task_unpack(req);
    if (zdata == NULL)
    {
        return SW_ERR;
    }

#ifdef SW_COROUTINE
    if (swTask_type(req) & SW_TASK_COROUTINE)
    {
        int task_id = req->info.fd;
        swTaskCo *task_co = swHashMap_find_int(task_coroutine_map, task_id);
        if (task_co == NULL)
        {
            swoole_php_fatal_error(E_WARNING, "task[%d] has expired.", task_id);
            fail: sw_zval_free(zdata);
            return SW_OK;
        }
        //Server->taskwait
        if (task_co->list == NULL)
        {
            if (task_co->timer)
            {
                swTimer_del(&SwooleG.timer, task_co->timer);
            }
            php_context *context = &task_co->context;
            int ret = coro_resume(context, zdata, &retval);
            if (ret == CORO_END && retval)
            {
                zval_ptr_dtor(retval);
            }
            efree(task_co);
            efree(zdata);
            swHashMap_del_int(task_coroutine_map, task_id);
            return SW_OK;
        }
        //Server->taskCo
        int i, task_index = -1;
        zval *result = task_co->result;
        for (i = 0; i < task_co->count; i++)
        {
            if (task_co->list[i] == task_id)
            {
                task_index = i;
                break;
            }
        }
        if (task_index < 0)
        {
            swoole_php_fatal_error(E_WARNING, "task[%d] is invalid.", task_id);
            goto fail;
        }
        add_index_zval(result, task_index, zdata);
        efree(zdata);
        swHashMap_del_int(task_coroutine_map, task_id);

        if (php_swoole_array_length(result) == task_co->count)
        {
            if (task_co->timer)
            {
                swTimer_del(&SwooleG.timer, task_co->timer);
                task_co->timer = NULL;
            }
            php_context *context = &task_co->context;
            int ret = coro_resume(context, result, &retval);
            if (ret == CORO_END && retval)
            {
                zval_ptr_dtor(retval);
            }
            sw_zval_free(result);
            efree(task_co);
        }
        return SW_OK;
    }
#endif

    args[0] = *zserv;
    args[1] = *ztask_id;
    args[2] = *zdata;

    zval *callback = NULL;
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        callback = swHashMap_find_int(task_callbacks, req->info.fd);
        if (callback == NULL)
        {
            swTask_type(req) = swTask_type(req) & (~SW_TASK_CALLBACK);
        }
    }
    if (callback == NULL)
    {
        callback = php_sw_server_callbacks[SW_SERVER_CB_onFinish];
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onFinish handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(ztask_id);
    sw_zval_free(zdata);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    if (swTask_type(req) & SW_TASK_CALLBACK)
    {
        swHashMap_del_int(task_callbacks, req->info.fd);
        sw_zval_free(callback);
    }
    return SW_OK;
}

static void php_swoole_onStart(swServer *serv)
{
    SwooleG.lock.lock(&SwooleG.lock);

    zval *zserv = (zval *) serv->ptr2;
    zval args[1];
    zval *retval = NULL;

    pid_t manager_pid = serv->factory_mode == SW_MODE_PROCESS ? serv->gs->manager_pid : 0;

    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), manager_pid);

    args[0] = *zserv;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onStart], &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onStart handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    SwooleG.lock.unlock(&SwooleG.lock);
}

static void php_swoole_onManagerStart(swServer *serv)
{

    zval *zserv = (zval *) serv->ptr2;
    zval args[1];
    zval *retval = NULL;

    pid_t manager_pid = serv->factory_mode == SW_MODE_PROCESS ? serv->gs->manager_pid : 0;

    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), manager_pid);

    args[0] = *zserv;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onManagerStart], &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onManagerStart handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onManagerStop(swServer *serv)
{
    zval *zserv = (zval *) serv->ptr2;
    zval args[1];
    zval *retval = NULL;

    args[0] = *zserv;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onManagerStop], &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onManagerStop handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onShutdown(swServer *serv)
{
    SwooleG.lock.lock(&SwooleG.lock);
    zval *zserv = (zval *) serv->ptr2;
    zval args[1];
    zval *retval = NULL;

    args[0] = *zserv;


    if (php_sw_server_callbacks[SW_SERVER_CB_onShutdown] != NULL)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onShutdown], &retval, 1, args, 0, NULL) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onShutdown handler error.");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR);
        }
        if (retval != NULL)
        {
            zval_ptr_dtor(retval);
        }
    }
    SwooleG.lock.unlock(&SwooleG.lock);
}

static void php_swoole_onWorkerStart_coroutine(zval *zserv, zval *zworker_id)
{
    zval *retval = NULL;
    zval *args[2];
    args[0] = zserv;
    args[1] = zworker_id;

    zend_fcall_info_cache *cache = php_sw_server_caches[SW_SERVER_CB_onWorkerStart];
    int ret = coro_create(cache, args, 2, &retval, NULL, NULL);
    if (ret < 0)
    {
        zval_ptr_dtor(zworker_id);
        if (ret == CORO_LIMIT)
        {
            swWarn("Failed to handle onWorkerStart. Coroutine limited.");
        }
        return;
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onWorkerStart_callback(zval *zserv, zval *zworker_id)
{
    zval *retval = NULL;
    zval args[2];
    args[0] = *zserv;
    args[1] = *zworker_id;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onWorkerStart], &retval,
            2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStart handler error.");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onWorkerStart(swServer *serv, int worker_id)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    /**
     * Master Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);

    /**
     * Manager Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    /**
     * Worker ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_id"), worker_id);

    /**
     * Is a task worker?
     */
    if (worker_id >= serv->worker_num)
    {
        zend_update_property_bool(swoole_server_class_entry_ptr, zserv, ZEND_STRL("taskworker"), 1);
    }
    else
    {
        zend_update_property_bool(swoole_server_class_entry_ptr, zserv, ZEND_STRL("taskworker"), 0);
    }

    /**
     * Worker Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_pid"), getpid());

    /**
     * Have not set the event callback
     */
    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerStart] == NULL)
    {
        return;
    }

    if (SwooleG.enable_coroutine && worker_id < serv->worker_num)
    {
        php_swoole_onWorkerStart_coroutine(zserv, zworker_id);
    }
    else
    {
        php_swoole_onWorkerStart_callback(zserv, zworker_id);
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
    zval args[2];
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);


    args[0] = *zobject;
    args[1] = *zworker_id;
    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onWorkerStop], &retval, 2, args, 0,
            NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStop handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zworker_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onWorkerExit(swServer *serv, int worker_id)
{
    zval *zobject = (zval *) serv->ptr2;
    zval *zworker_id;
    zval args[2];
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);


    args[0] = *zobject;
    args[1] = *zworker_id;
    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onWorkerExit], &retval, 2, args, 0,
            NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStop handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zworker_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_onUserWorkerStart(swServer *serv, swWorker *worker)
{

    zval *object = worker->ptr;
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("id"), SwooleWG.id);

    zval *zserv = (zval *) serv->ptr2;
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), serv->gs->master_pid);
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), serv->gs->manager_pid);

    php_swoole_process_start(worker, object);
}

static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo)
{
    zval *zobject = (zval *) serv->ptr2;
    zval *zworker_id, *zworker_pid, *zexit_code, *zsigno;
    zval args[5];
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    SW_MAKE_STD_ZVAL(zworker_pid);
    ZVAL_LONG(zworker_pid, worker_pid);

    SW_MAKE_STD_ZVAL(zexit_code);
    ZVAL_LONG(zexit_code, exit_code);

    SW_MAKE_STD_ZVAL(zsigno);
    ZVAL_LONG(zsigno, signo);


    args[0] = *zobject;
    args[1] = *zworker_id;
    args[2] = *zworker_pid;
    args[3] = *zexit_code;
    args[4] = *zsigno;

    if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_server_callbacks[SW_SERVER_CB_onWorkerError], &retval, 5, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerError handler error.");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(zworker_id);
    zval_ptr_dtor(zworker_pid);
    zval_ptr_dtor(zexit_code);
    zval_ptr_dtor(zsigno);

    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

#ifdef SW_COROUTINE
static void php_swoole_onConnect_finish(void *param)
{
    swServer *serv = SwooleG.serv;
    swTrace("onConnect finish and send confirm");
    swServer_tcp_feedback(serv, (uint32_t) (long) param, SW_EVENT_CONFIRM);
}
#endif

void php_swoole_onConnect(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval *retval = NULL;


    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, info->from_id);

    if (SwooleG.enable_coroutine)
    {
        zval *args[3];
        args[0] = zserv;
        args[1] = zfd;
        args[2] = zfrom_id;

        int ret;
        zend_fcall_info_cache *cache = php_swoole_server_get_cache(serv, info->from_fd, SW_SERVER_CB_onConnect);
        if (cache == NULL) {
            return;
        }
        if (serv->enable_delay_receive)
        {
            ret = coro_create(cache, args, 3, &retval, php_swoole_onConnect_finish, (void*) (long) info->fd);
        }
        else
        {
            ret = coro_create(cache, args, 3, &retval, NULL, NULL);
        }

        if (ret < 0)
        {
            zval_ptr_dtor(zfd);
            zval_ptr_dtor(zfrom_id);
            return;
        }
    }
    else
    {
        zval args[3];
        args[0] = *zserv;
        args[1] = *zfd;
        args[2] = *zfrom_id;

        zval *callback = php_swoole_server_get_callback(serv, info->from_fd, SW_SERVER_CB_onConnect);
        if (callback == NULL || ZVAL_IS_NULL(callback))
        {
            return;
        }

        if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL) == FAILURE)
        {
            swoole_php_error(E_WARNING, "onConnect handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(zfd);
    zval_ptr_dtor(zfrom_id);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

void php_swoole_onClose(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval *zfrom_id;
    zval *retval = NULL;


    if (SwooleG.enable_coroutine && serv->send_yield)
    {
        swLinkedList *coros_list = swHashMap_find_int(send_coroutine_map, info->fd);
        if (coros_list)
        {
            php_context *context = swLinkedList_shift(coros_list);
            if (context == NULL)
            {
                swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
            }
            else
            {
                SwooleG.error = ECONNRESET;
                zval_ptr_dtor(&context->coro_params);
                ZVAL_NULL(&context->coro_params);
                //resume coroutine
                php_swoole_server_send_resume(serv, context, info->fd);
                //free memory
                swLinkedList_free(coros_list);
                swHashMap_del_int(send_coroutine_map, info->fd);
            }
        }
    }

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, info->from_id);

    if (SwooleG.enable_coroutine)
    {
        int ret;

        zval *args[3];
        args[0] = zserv;
        args[1] = zfd;
        args[2] = zfrom_id;

        zend_fcall_info_cache *cache = php_swoole_server_get_cache(serv, info->from_fd, SW_SERVER_CB_onClose);
        if (cache == NULL)
        {
            return;
        }

        ret = coro_create(cache, args, 3, &retval, NULL, NULL);

        zval_ptr_dtor(zfd);
        zval_ptr_dtor(zfrom_id);

        if (ret < 0)
        {
            return;
        }
    }
    else
    {
        zval args[3];
        args[0] = *zserv;
        args[1] = *zfd;
        args[2] = *zfrom_id;

        zval *callback = php_swoole_server_get_callback(serv, info->from_fd, SW_SERVER_CB_onClose);
        if (callback == NULL)
        {
            return;
        }
        if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL) == FAILURE)
        {
            swoole_php_error(E_WARNING, "onClose handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

void php_swoole_onBufferFull(swServer *serv, swDataHead *info)
{
    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval args[2];
    zval *retval = NULL;

    zval *callback = php_swoole_server_get_callback(serv, info->from_fd, SW_SERVER_CB_onBufferFull);
    if (!callback)
    {
        return;
    }

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    args[0] = *zserv;
    args[1] = *zfd;

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_cache(serv, info->from_fd, SW_SERVER_CB_onBufferFull);
    if (sw_call_user_function_fast_ex(callback, fci_cache, &retval, 2, args) == FAILURE)
    {
        swoole_php_error(E_WARNING, "onBufferFull handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zfd);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

#ifdef SW_COROUTINE
static void php_swoole_onSendTimeout(swTimer *timer, swTimer_node *tnode)
{
    php_context *context = (php_context *) tnode->data;
    zval *zdata = &context->coro_params;
    zval *result;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(result);

    SwooleG.error = ETIMEDOUT;
    ZVAL_BOOL(result, 0);

    int fd = (int) (long) context->private_data;
    swLinkedList *coros_list = swHashMap_find_int(send_coroutine_map, fd);
    if (coros_list)
    {
        swLinkedList_remove(coros_list, context);
        //free memory
        if (coros_list->num == 0)
        {
            swLinkedList_free(coros_list);
            swHashMap_del_int(send_coroutine_map, fd);
        }
    }
    else
    {
        swWarn("send coroutine[fd=%d] not exists.", fd);
        return;
    }

    context->private_data = NULL;

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    zval_ptr_dtor(zdata);
    efree(context);
}

static int php_swoole_server_send_resume(swServer *serv, php_context *context, int fd)
{
    char *data;
    zval *zdata = &context->coro_params;
    zval *result;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(result);

    if (ZVAL_IS_NULL(zdata))
    {
        _fail: ZVAL_BOOL(result, 0);
    }
    else
    {
        size_t length = php_swoole_get_send_data(zdata, &data);
        if (length == 0)
        {
            goto _fail;
        }
        int ret = swServer_tcp_send(serv, fd, data, length);
        if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && serv->send_yield)
        {
            return SW_AGAIN;
        }
        ZVAL_BOOL(result, ret == SW_OK);
    }

    if (context->timer)
    {
        swTimer_del(&SwooleG.timer, (swTimer_node *) context->timer);
        context->timer = NULL;
    }

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    zval_ptr_dtor(zdata);
    efree(context);
    return SW_OK;
}

void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value)
{
    swLinkedList *coros_list = swHashMap_find_int(send_coroutine_map, fd);
    if (coros_list == NULL)
    {
        coros_list = swLinkedList_new(2, NULL);
        if (coros_list == NULL)
        {
            RETURN_FALSE;
        }
        if (swHashMap_add_int(send_coroutine_map, fd, (void*) coros_list) == SW_ERR)
        {
            swLinkedList_free(coros_list);
            RETURN_FALSE;
        }
    }

    php_context *context = emalloc(sizeof(php_context));
    if (swLinkedList_append(coros_list, (void *) context) == SW_ERR)
    {
        efree(context);
        RETURN_FALSE;
    }
    if (serv->send_timeout > 0)
    {
        context->private_data = (void*) (long) fd;
        context->timer = swTimer_add(&SwooleG.timer, (int) (serv->send_timeout * 1000), 0, context, php_swoole_onSendTimeout);
    }
    else
    {
        context->timer = NULL;
    }
    context->coro_params = *zdata;
    coro_save(context);
    coro_yield();
}
#endif

void php_swoole_onBufferEmpty(swServer *serv, swDataHead *info)
{

    zval *zserv = (zval *) serv->ptr2;
    zval *zfd;
    zval args[2];
    zval *retval = NULL;
    zval *callback;

#ifdef SW_COROUTINE
    if (serv->send_yield == 0)
    {
        goto _callback;
    }

    swLinkedList *coros_list = swHashMap_find_int(send_coroutine_map, info->fd);
    if (coros_list)
    {
        swLinkedList_node *node = coros_list->head;
        php_context *context = node ? node->data : NULL;
        if (context == NULL)
        {
            swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
            goto _callback;
        }
        //resume coroutine
        if (php_swoole_server_send_resume(serv, context, info->fd) == SW_AGAIN)
        {
            return;
        }
        else
        {
            swLinkedList_shift(coros_list);
            //free memory
            if (coros_list->num == 0)
            {
                swLinkedList_free(coros_list);
                swHashMap_del_int(send_coroutine_map, info->fd);
            }
        }
    }
#endif

#ifdef SW_COROUTINE
    _callback:
#endif
    callback = php_swoole_server_get_callback(serv, info->from_fd, SW_SERVER_CB_onBufferEmpty);
    if (!callback)
    {
        return;
    }

    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    args[0] = *zserv;
    args[1] = *zfd;

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_cache(serv, info->from_fd, SW_SERVER_CB_onBufferEmpty);
    if (sw_call_user_function_fast_ex(callback, fci_cache, &retval, 2, args) == FAILURE)
    {
        swoole_php_error(E_WARNING, "onBufferEmpty handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(zfd);
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

PHP_METHOD(swoole_server, __construct)
{
    size_t host_len = 0;
    char *serv_host;
    zend_long sock_type = SW_SOCK_TCP;
    zend_long serv_port = 0;
    zend_long serv_mode = SW_MODE_PROCESS;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_server only can be used in PHP CLI mode.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor != NULL)
    {
        swoole_php_fatal_error(E_ERROR, "eventLoop has already been created. unable to create swoole_server.");
        RETURN_FALSE;
    }

    if (SwooleG.serv != NULL)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. unable to create swoole_server.");
        RETURN_FALSE;
    }

    swServer *serv = sw_malloc(sizeof (swServer));
    swServer_init(serv);

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lll", &serv_host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "invalid swoole_server parameters.");
        return;
    }

    if (serv_mode != SW_MODE_BASE && serv_mode != SW_MODE_PROCESS)
    {
        swoole_php_fatal_error(E_ERROR, "invalid $mode parameters %d.", (int) serv_mode);
        return;
    }
    if (serv_mode == SW_MODE_BASE)
    {
        serv->reactor_num = 1;
        serv->worker_num = 1;
    }
    serv->factory_mode = serv_mode;

    bzero(php_sw_server_callbacks, sizeof(zval*) * PHP_SWOOLE_SERVER_CALLBACK_NUM);

    if (serv_port == 0 && strcasecmp(serv_host, "SYSTEMD") == 0)
    {
        if (swserver_add_systemd_socket(serv) <= 0)
        {
            swoole_php_fatal_error(E_ERROR, "failed to add systemd socket.");
            return;
        }
    }
    else
    {
        swListenPort *port = swServer_add_port(serv, sock_type, serv_host, serv_port);
        if (!port)
        {
            zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno, "failed to listen server port[%s:%ld]. Error: %s[%d].",
                    serv_host, serv_port, strerror(errno), errno);
            return;
        }
    }

    zval *server_object = getThis();

    zval *connection_iterator_object;
    SW_MAKE_STD_ZVAL(connection_iterator_object);
    object_init_ex(connection_iterator_object, swoole_connection_iterator_class_entry_ptr);
    zend_update_property(swoole_server_class_entry_ptr, server_object, ZEND_STRL("connections"), connection_iterator_object);

    swConnectionIterator *i = emalloc(sizeof(swConnectionIterator));
    bzero(i, sizeof(swConnectionIterator));
    i->serv = serv;
    swoole_set_object(connection_iterator_object, i);

    zend_update_property_stringl(swoole_server_class_entry_ptr, server_object, ZEND_STRL("host"), serv_host, host_len);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object, ZEND_STRL("port"), (long) serv->listen_list->port);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object, ZEND_STRL("mode"), serv->factory_mode);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object, ZEND_STRL("type"), sock_type);
    swoole_set_object(server_object, serv);

    zval *ports;
    SW_ALLOC_INIT_ZVAL(ports);
    array_init(ports);
    server_port_list.zports = ports;

#ifdef HT_ALLOW_COW_VIOLATION
    HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(ports));
#endif

    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        php_swoole_server_add_port(serv, ls);
    }

    server_port_list.primary_port = serv->listen_list->ptr;

    zend_update_property(swoole_server_class_entry_ptr, server_object, ZEND_STRL("ports"), ports);
}

PHP_METHOD(swoole_server, __destruct)
{
#if SW_DEBUG_SERVER_DESTRUCT
    int i;
    for (i = 0; i < PHP_SERVER_CALLBACK_NUM; i++)
    {
        if (php_sw_server_caches[i])
        {
            efree(php_sw_server_caches[i]);
            php_sw_server_caches[i] = NULL;
        }
    }

    zval *port_object;
    for (i = 0; i < server_port_list.num; i++)
    {
        port_object = server_port_list.zobjects[i];
        efree(port_object);
        server_port_list.zobjects[i] = NULL;
    }

    efree(server_port_list.zports);
    server_port_list.zports = NULL;
#endif
}

PHP_METHOD(swoole_server, set)
{
    zval *zset = NULL;
    zval *zobject = getThis();
    HashTable *vht;

    zval *v;

    swServer *serv = swoole_get_object(zobject);
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. unable to execute function 'swoole_server_set'.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_swoole_array_separate(zset);
    vht = Z_ARRVAL_P(zset);

    //chroot
    if (php_swoole_array_get_value(vht, "chroot", v))
    {
        convert_to_string(v);
        if (SwooleG.chroot)
        {
            sw_free(SwooleG.chroot);
        }
        SwooleG.chroot = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //user
    if (php_swoole_array_get_value(vht, "user", v))
    {
        convert_to_string(v);
        if (SwooleG.user)
        {
            sw_free(SwooleG.user);
        }
        SwooleG.user = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //group
    if (php_swoole_array_get_value(vht, "group", v))
    {
        convert_to_string(v);
        if (SwooleG.group)
        {
            sw_free(SwooleG.group);
        }
        SwooleG.group = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //daemonize
    if (php_swoole_array_get_value(vht, "daemonize", v))
    {
        convert_to_boolean(v);
        serv->daemonize = Z_BVAL_P(v);
    }
#ifdef SW_DEBUG
    //debug
    if (php_swoole_array_get_value(vht, "debug_mode", v))
    {
        convert_to_boolean(v);
        if (Z_BVAL_P(v))
        {
            SwooleG.log_level = 0;
        }
    }
#endif
    if (php_swoole_array_get_value(vht, "trace_flags", v))
    {
        convert_to_long(v);
        SwooleG.trace_flags = (int32_t) Z_LVAL_P(v);
    }
    //pid file
    if (php_swoole_array_get_value(vht, "pid_file", v))
    {
        convert_to_string(v);
        if (serv->pid_file)
        {
            sw_free(serv->pid_file);
        }
        serv->pid_file = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //reactor thread num
    if (php_swoole_array_get_value(vht, "reactor_num", v))
    {
        convert_to_long(v);
        serv->reactor_num = (int) Z_LVAL_P(v);
        if (serv->reactor_num <= 0)
        {
            serv->reactor_num = SwooleG.cpu_num;
        }
    }
    //worker_num
    if (php_swoole_array_get_value(vht, "worker_num", v))
    {
        convert_to_long(v);
        serv->worker_num = (int) Z_LVAL_P(v);
        if (serv->worker_num <= 0)
        {
            serv->worker_num = SwooleG.cpu_num;
        }
    }
    //max wait time
    if (php_swoole_array_get_value(vht, "max_wait_time", v))
    {
        convert_to_long(v);
        serv->max_wait_time = (uint32_t) Z_LVAL_P(v);
    }
#ifdef SW_COROUTINE
    if (php_swoole_array_get_value(vht, "enable_coroutine", v))
    {
        convert_to_boolean(v);
        SwooleG.enable_coroutine = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "max_coro_num", v) || php_swoole_array_get_value(vht, "max_coroutine", v))
    {
        convert_to_long(v);
        COROG.max_coro_num = (int) Z_LVAL_P(v);
        if (COROG.max_coro_num <= 0)
        {
            COROG.max_coro_num = SW_DEFAULT_MAX_CORO_NUM;
        }
        else if (COROG.max_coro_num >= SW_MAX_CORO_NUM_LIMIT)
        {
            COROG.max_coro_num = SW_MAX_CORO_NUM_LIMIT;
        }
    }
    if (php_swoole_array_get_value(vht, "send_yield", v))
    {
        convert_to_boolean(v);
        serv->send_yield = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "send_timeout", v))
    {
        convert_to_double(v);
        serv->send_timeout = Z_DVAL_P(v);
    }
#endif
    //dispatch_mode
    if (php_swoole_array_get_value(vht, "dispatch_mode", v))
    {
        convert_to_long(v);
        serv->dispatch_mode = (int) Z_LVAL_P(v);
    }
    //dispatch function
    if (php_swoole_array_get_value(vht, "dispatch_func", v))
    {
        swServer_dispatch_function func = NULL;
        while(1)
        {
            if (Z_TYPE_P(v) == IS_STRING)
            {
                func = swoole_get_function(Z_STRVAL_P(v), Z_STRLEN_P(v));
                break;
            }

            char *func_name = NULL;
            if (!sw_zend_is_callable(v, 0, &func_name))
            {
                swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
                efree(func_name);
                return;
            }
            efree(func_name);
            Z_TRY_ADDREF_P(v);
            serv->private_data_3 = sw_zval_dup(v);
            func = php_swoole_dispatch_func;
            break;
        }
        if (func)
        {
            serv->dispatch_mode = SW_DISPATCH_USERFUNC;
            serv->dispatch_func = func;
        }
    }
    //log_file
    if (php_swoole_array_get_value(vht, "log_file", v))
    {
        convert_to_string(v);
        if (SwooleG.log_file)
        {
            sw_free(SwooleG.log_file);
        }
        SwooleG.log_file = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //log_level
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        convert_to_long(v);
        SwooleG.log_level = (int) Z_LVAL_P(v);
    }
    /**
     * for dispatch_mode = 1/3
     */
    if (php_swoole_array_get_value(vht, "discard_timeout_request", v))
    {
        convert_to_boolean(v);
        serv->discard_timeout_request = Z_BVAL_P(v);
    }
    //onConnect/onClose event
    if (php_swoole_array_get_value(vht, "enable_unsafe_event", v))
    {
        convert_to_boolean(v);
        serv->enable_unsafe_event = Z_BVAL_P(v);
    }
    //delay receive
    if (php_swoole_array_get_value(vht, "enable_delay_receive", v))
    {
        convert_to_boolean(v);
        serv->enable_delay_receive = Z_BVAL_P(v);
    }
    //task_worker_num
    if (php_swoole_array_get_value(vht, "task_worker_num", v))
    {
        convert_to_long(v);
        serv->task_worker_num = (int) Z_LVAL_P(v);
        if (task_callbacks == NULL)
        {
            task_callbacks = swHashMap_new(1024, NULL);
        }
#ifdef SW_COROUTINE
        if (task_coroutine_map == NULL)
        {
            task_coroutine_map = swHashMap_new(1024, NULL);
        }
#endif
    }
    //slowlog
    if (php_swoole_array_get_value(vht, "trace_event_worker", v))
    {
        convert_to_boolean(v);
        serv->trace_event_worker = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "request_slowlog_timeout", v))
    {
        convert_to_long(v);
        serv->request_slowlog_timeout = (uint8_t) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "request_slowlog_file", v))
    {
        convert_to_string(v);
        serv->request_slowlog_file = fopen(Z_STRVAL_P(v), "a+");
        if (serv->request_slowlog_file == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "Unable to open request_slowlog_file[%s].", Z_STRVAL_P(v));
            return;
        }
        if (serv->request_slowlog_timeout == 0)
        {
            serv->request_slowlog_timeout = 1;
        }
    }
    //task ipc mode, 1,2,3
    if (php_swoole_array_get_value(vht, "task_ipc_mode", v))
    {
        convert_to_long(v);
        serv->task_ipc_mode = (int) Z_LVAL_P(v);
    }
    /**
     * Temporary file directory for task_worker
     */
    if (php_swoole_array_get_value(vht, "task_tmpdir", v))
    {
        convert_to_string(v);
        if (php_swoole_create_dir(Z_STRVAL_P(v), Z_STRLEN_P(v)) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "Unable to create task_tmpdir[%s].", Z_STRVAL_P(v));
            return;
        }
        if (SwooleG.task_tmpdir)
        {
            sw_free(SwooleG.task_tmpdir);
        }
        SwooleG.task_tmpdir = sw_malloc(Z_STRLEN_P(v) + sizeof(SW_TASK_TMP_FILE) + 1);
        SwooleG.task_tmpdir_len = snprintf(SwooleG.task_tmpdir, SW_TASK_TMPDIR_SIZE, "%s/swoole.task.XXXXXX", Z_STRVAL_P(v)) + 1;
    }
    //task_max_request
    if (php_swoole_array_get_value(vht, "task_max_request", v))
    {
        convert_to_long(v);
        serv->task_max_request = (int) Z_LVAL_P(v);
    }
    //max_connection
    if (php_swoole_array_get_value(vht, "max_connection", v) || php_swoole_array_get_value(vht, "max_conn", v))
    {
        convert_to_long(v);
        serv->max_connection = (int) Z_LVAL_P(v);
    }
    //heartbeat_check_interval
    if (php_swoole_array_get_value(vht, "heartbeat_check_interval", v))
    {
        convert_to_long(v);
        serv->heartbeat_check_interval = (int) Z_LVAL_P(v);
    }
    //heartbeat idle time
    if (php_swoole_array_get_value(vht, "heartbeat_idle_time", v))
    {
        convert_to_long(v);
        serv->heartbeat_idle_time = (int) Z_LVAL_P(v);

        if (serv->heartbeat_check_interval > serv->heartbeat_idle_time)
        {
            swoole_php_fatal_error(E_WARNING, "heartbeat_idle_time must be greater than heartbeat_check_interval.");
            serv->heartbeat_check_interval = serv->heartbeat_idle_time / 2;
        }
    }
    else if (serv->heartbeat_check_interval > 0)
    {
        serv->heartbeat_idle_time = serv->heartbeat_check_interval * 2;
    }
    //max_request
    if (php_swoole_array_get_value(vht, "max_request", v))
    {
        convert_to_long(v);
        serv->max_request = (int) Z_LVAL_P(v);
    }
    //reload async
    if (php_swoole_array_get_value(vht, "reload_async", v))
    {
        convert_to_boolean(v);
        serv->reload_async = Z_BVAL_P(v);
    }
    //cpu affinity
    if (php_swoole_array_get_value(vht, "open_cpu_affinity", v))
    {
        convert_to_boolean(v);
        serv->open_cpu_affinity = Z_BVAL_P(v);
    }
    //cpu affinity set
    if (php_swoole_array_get_value(vht, "cpu_affinity_ignore", v))
    {
        int ignore_num = zend_hash_num_elements(Z_ARRVAL_P(v));
        if (ignore_num >= SW_CPU_NUM)
        {
            swoole_php_fatal_error(E_ERROR, "cpu_affinity_ignore num must be less than cpu num (%d)", SW_CPU_NUM);
            RETURN_FALSE;
        }
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
    //paser x-www-form-urlencoded form data
    if (php_swoole_array_get_value(vht, "http_parse_post", v))
    {
        convert_to_boolean(v);
        serv->http_parse_post = Z_BVAL_P(v);
    }
#ifdef SW_HAVE_ZLIB
    //http content compression
    if (php_swoole_array_get_value(vht, "http_compression", v))
    {
        convert_to_boolean(v);
        serv->http_compression = Z_BVAL_P(v);
        serv->http_compression_level = Z_BEST_SPEED;
    }
    if (php_swoole_array_get_value(vht, "http_gzip_level", v) || php_swoole_array_get_value(vht, "http_compression_level", v))
    {
        convert_to_long(v);
        zend_long level = Z_LVAL_P(v);
        if (level > UINT8_MAX)
        {
            level = UINT8_MAX;
        }
        else if (level < 0)
        {
            level = 0;
        }
        serv->http_compression_level = level;
    }
#endif
    //temporary directory for HTTP uploaded file.
    if (php_swoole_array_get_value(vht, "upload_tmp_dir", v))
    {
        convert_to_string(v);
        if (php_swoole_create_dir(Z_STRVAL_P(v), Z_STRLEN_P(v)) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "Unable to create upload_tmp_dir[%s].", Z_STRVAL_P(v));
            return;
        }
        if (serv->upload_tmp_dir)
        {
            sw_free(serv->upload_tmp_dir);
        }
        serv->upload_tmp_dir = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    /**
     * http static file handler
     */
    if (php_swoole_array_get_value(vht, "enable_static_handler", v))
    {
        convert_to_boolean(v);
        serv->enable_static_handler = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "document_root", v))
    {
        convert_to_string(v);
        if (serv->document_root)
        {
            sw_free(serv->document_root);
        }
        serv->document_root = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
        if (serv->document_root[Z_STRLEN_P(v) - 1] == '/')
        {
            serv->document_root[Z_STRLEN_P(v) - 1] = 0;
            serv->document_root_len = Z_STRLEN_P(v) - 1;
        }
        else
        {
            serv->document_root_len = Z_STRLEN_P(v);
        }
    }
    /**
     * buffer input size
     */
    if (php_swoole_array_get_value(vht, "buffer_input_size", v))
    {
        convert_to_long(v);
        serv->buffer_input_size = (int) Z_LVAL_P(v);
    }
    /**
     * buffer output size
     */
    if (php_swoole_array_get_value(vht, "buffer_output_size", v))
    {
        convert_to_long(v);
        serv->buffer_output_size = (int) Z_LVAL_P(v);
    }
    //message queue key
    if (php_swoole_array_get_value(vht, "message_queue_key", v))
    {
        convert_to_long(v);
        serv->message_queue_key = (int) Z_LVAL_P(v);
    }

    zval *retval = NULL;
    zval *port_object = server_port_list.zobjects[0];

    Z_TRY_ADDREF_P(port_object);
    Z_TRY_ADDREF_P(zset);

    sw_zend_call_method_with_1_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "set", &retval, zset);

    zval *zsetting = sw_zend_read_property_array(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    zval_ptr_dtor(zset);

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, on)
{
    zval *name;
    zval *cb;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. unable to register event callback function.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &name, &cb) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    zend_fcall_info_cache *func_cache = emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, NULL, 0, &func_name, NULL, func_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);

    convert_to_string(name);

    char *callback_name[PHP_SWOOLE_SERVER_CALLBACK_NUM] = {
        "Start",
        "Shutdown",
        "WorkerStart",
        "WorkerStop",
        "Task",
        "Finish",
        "WorkerExit",
        "WorkerError",
        "ManagerStart",
        "ManagerStop",
        "PipeMessage",
    };

    int i;
    char property_name[128];
    int l_property_name = 0;
    memcpy(property_name, "on", 2);

    for (i = 0; i < PHP_SWOOLE_SERVER_CALLBACK_NUM; i++)
    {
        if (strncasecmp(callback_name[i], Z_STRVAL_P(name), Z_STRLEN_P(name)) != 0)
        {
            continue;
        }

        memcpy(property_name + 2, callback_name[i], Z_STRLEN_P(name));
        l_property_name = Z_STRLEN_P(name) + 2;
        property_name[l_property_name] = '\0';
        zend_update_property(swoole_server_class_entry_ptr, getThis(), property_name, l_property_name, cb);
        php_sw_server_callbacks[i] = sw_zend_read_property(swoole_server_class_entry_ptr, getThis(), property_name, l_property_name, 0);
        php_sw_server_caches[i] = func_cache;
        sw_copy_to_stack(php_sw_server_callbacks[i], _php_sw_server_callbacks[i]);
        break;
    }

    if (l_property_name == 0)
    {
        zval *port_object = server_port_list.zobjects[0];
        zval *retval = NULL;
        Z_TRY_ADDREF_P(port_object);
        sw_zend_call_method_with_2_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "on", &retval, name, cb);
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_METHOD(swoole_server, listen)
{
    char *host;
    size_t host_len;
    long sock_type;
    long port;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. can't add listener.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &host, &host_len, &port, &sock_type) == FAILURE)
    {
        RETURN_FALSE;
    }

    swListenPort *ls = swServer_add_port(serv, (int) sock_type, host, (int) port);
    if (!ls)
    {
        RETURN_FALSE;
    }

    zval *port_object = php_swoole_server_add_port(serv, ls);
    RETURN_ZVAL(port_object, 1, NULL);
}

PHP_METHOD(swoole_server, addProcess)
{
    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. can't add process.");
        RETURN_FALSE;
    }

    zval *process = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &process) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (ZVAL_IS_NULL(process))
    {
        swoole_php_fatal_error(E_WARNING, "the first parameter can't be empty.");
        RETURN_FALSE;
    }

    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_class_entry_ptr))
    {
        swoole_php_fatal_error(E_ERROR, "object is not instanceof swoole_process.");
        RETURN_FALSE;
    }

    if (serv->onUserWorkerStart == NULL)
    {
        serv->onUserWorkerStart = php_swoole_onUserWorkerStart;
    }

    zval *tmp_process = emalloc(sizeof(zval));
    memcpy(tmp_process, process, sizeof(zval));
    process = tmp_process;

    Z_TRY_ADDREF_P(process);

    swWorker *worker = swoole_get_object(process);
    worker->ptr = process;

    int id = swServer_add_worker(serv, worker);
    if (id < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swServer_add_worker failed.");
        RETURN_FALSE;
    }
    zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("id"), id);
    RETURN_LONG(id);
}

static inline zend_bool is_websocket_server(zval *zobject)
{
    return instanceof_function(Z_OBJCE_P(zobject), swoole_websocket_server_class_entry_ptr);
}

static inline zend_bool is_http_server(zval *zobject)
{
    return instanceof_function(Z_OBJCE_P(zobject), swoole_http_server_class_entry_ptr);
}

PHP_METHOD(swoole_server, start)
{
    zval *zobject = getThis();
    int ret;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is running. unable to execute swoole_server->start.");
        RETURN_FALSE;
    }

    php_swoole_register_callback(serv);
    serv->onReceive = php_swoole_onReceive;
    if (is_websocket_server(zobject) || is_http_server(zobject))
    {
        zval *zsetting = sw_zend_read_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
        if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
        {
            SW_ALLOC_INIT_ZVAL(zsetting);
            array_init(zsetting);
#ifdef HT_ALLOW_COW_VIOLATION
            HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(zsetting));
#endif
            zend_update_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("setting"), zsetting TSRMLS_CC);
        }
        add_assoc_bool(zsetting, "open_http_protocol", 1);
        add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
        add_assoc_bool(zsetting, "open_eof_check", 0);
        add_assoc_bool(zsetting, "open_length_check", 0);

        enum protocol_flags
        {
            SW_HTTP2_PROTOCOL = 1u << 1,
            SW_WEBSOCKET_PROTOCOL = 1u << 2
        };
        uint8_t protocol_flag = 0;
        swListenPort *ls = serv->listen_list;
        if (ls->open_http2_protocol)
        {
            protocol_flag |= SW_HTTP2_PROTOCOL;
        }
        if (ls->open_websocket_protocol || is_websocket_server(zobject))
        {
            add_assoc_bool(zsetting, "open_websocket_protocol", 1);
            protocol_flag |= SW_WEBSOCKET_PROTOCOL;
        }
        swPort_clear_protocol(serv->listen_list);
        ls->open_http_protocol = 1;
        ls->open_http2_protocol = !!(protocol_flag & SW_HTTP2_PROTOCOL);
        ls->open_websocket_protocol = !!(protocol_flag & SW_WEBSOCKET_PROTOCOL);
    }
    php_swoole_server_before_start(serv, zobject);

    ret = swServer_start(serv);
    if (ret < 0)
    {
        swoole_php_fatal_error(E_ERROR, "failed to start server. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_server, send)
{
    int ret;

    zval *zfd;
    zval *zdata;
    zend_long server_socket = -1;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_ZVAL(zfd)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(server_socket)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    if (serv->have_udp_sock && Z_TYPE_P(zfd) == IS_STRING)
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
        ret = swServer_tcp_send(serv, fd, data, length);
#ifdef SW_COROUTINE
        if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW && serv->send_yield)
        {
            zval_add_ref(zdata);
            php_swoole_server_send_yield(serv, fd, zdata, return_value);
        }
        else
#endif
        {
            SW_CHECK_RETURN(ret);
        }
    }
}

PHP_METHOD(swoole_server, sendto)
{
    char *ip;
    char *data;
    size_t len, ip_len;

    zend_long port;
    zend_long server_socket = -1;
    zend_bool ipv6 = 0;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(3, 4)
        Z_PARAM_STRING(ip, ip_len)
        Z_PARAM_LONG(port)
        Z_PARAM_STRING(data, len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(server_socket)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    if (strchr(ip, ':'))
    {
        ipv6 = 1;
    }

    if (ipv6 == 0 && serv->udp_socket_ipv4 <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "UDP listener has to be added before executing sendto.");
        RETURN_FALSE;
    }
    else if (ipv6 == 1 && serv->udp_socket_ipv6 <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "UDP6 listener has to be added before executing sendto.");
        RETURN_FALSE;
    }

    if (server_socket < 0)
    {
        server_socket = ipv6 ?  serv->udp_socket_ipv6 : serv->udp_socket_ipv4;
    }

    int ret;
    if (ipv6)
    {
        ret = swSocket_udp_sendto6(server_socket, ip, port, data, len);
    }
    else
    {
        ret = swSocket_udp_sendto(server_socket, ip, port, data, len);
    }
    SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_server, sendfile)
{
    size_t len;

    char *filename;
    long fd;
    long offset = 0;
    long length = 0;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls|ll", &fd, &filename, &len, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "can't sendfile[%s] to the connections in master process.", filename);
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(swServer_tcp_sendfile(serv, (int) fd, filename, len, offset, length));
}

PHP_METHOD(swoole_server, close)
{
    zend_bool reset = SW_FALSE;
    zend_long fd;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "can't close the connections in master process.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(fd)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(reset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(serv->close(serv, (int )fd, (int )reset));
}

PHP_METHOD(swoole_server, confirm)
{
    long fd;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "can't confirm the connections in master process.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(swServer_tcp_feedback(serv, fd, SW_EVENT_CONFIRM));
}

PHP_METHOD(swoole_server, pause)
{
    long fd;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(swServer_tcp_feedback(serv, fd, SW_EVENT_PAUSE_RECV));
}

PHP_METHOD(swoole_server, resume)
{
    long fd;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(swServer_tcp_feedback(serv, fd, SW_EVENT_RESUME_RECV));
}

PHP_METHOD(swoole_server, stats)
{
    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("start_time"), serv->stats->start_time);
    add_assoc_long_ex(return_value, ZEND_STRL("connection_num"), serv->stats->connection_num);
    add_assoc_long_ex(return_value, ZEND_STRL("accept_count"), serv->stats->accept_count);
    add_assoc_long_ex(return_value, ZEND_STRL("close_count"), serv->stats->close_count);
    /**
     * reset
     */
    int tasking_num = serv->stats->tasking_num;
    if (tasking_num < 0)
    {
        tasking_num = serv->stats->tasking_num = 0;
    }
    add_assoc_long_ex(return_value, ZEND_STRL("tasking_num"), tasking_num);
    add_assoc_long_ex(return_value, ZEND_STRL("request_count"), serv->stats->request_count);
    if (SwooleWG.worker)
    {
        add_assoc_long_ex(return_value, ZEND_STRL("worker_request_count"), SwooleWG.worker->request_count);
    }

    if (serv->task_ipc_mode > SW_TASK_IPC_UNIXSOCK && serv->gs->task_workers.queue)
    {
        int queue_num = -1;
        int queue_bytes = -1;
        if (swMsgQueue_stat(serv->gs->task_workers.queue, &queue_num, &queue_bytes) == 0)
        {
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_num"), queue_num);
            add_assoc_long_ex(return_value, ZEND_STRL("task_queue_bytes"), queue_bytes);
        }
    }

#ifdef SW_COROUTINE
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), COROG.coro_num);
#endif
}

PHP_METHOD(swoole_server, reload)
{
    zend_bool only_reload_taskworker = 0;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &only_reload_taskworker) == FAILURE)
    {
        RETURN_FALSE;
    }

    int sig = only_reload_taskworker ? SIGUSR2 : SIGUSR1;
    if (kill(serv->gs->manager_pid, sig) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "failed to send the reload signal. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_server, heartbeat)
{
    zend_bool close_connection = 0;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &close_connection) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (serv->heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    array_init(return_value);

    int fd;
    int checktime = (int) serv->gs->now - serv->heartbeat_idle_time;
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

PHP_METHOD(swoole_server, taskwait)
{
    swEventData buf;
    zval *data;

    double timeout = SW_TASKWAIT_TIMEOUT;
    long dst_worker_id = -1;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|dl", &data, &timeout, &dst_worker_id) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, data) < 0)
    {
        RETURN_FALSE;
    }

    int _dst_worker_id = (int) dst_worker_id;

    //coroutine
    if (sw_get_current_cid() >= 0)
    {
        php_swoole_task_wait_co(serv, &buf, timeout, _dst_worker_id, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    int task_id = buf.info.fd;

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);

    //clear history task
    while (read(efd, &notify, sizeof(notify)) > 0);

    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);

    if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        task_notify_pipe->timeout = timeout;
        while(1)
        {
            if (task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify)) > 0)
            {
                if (task_result->info.fd != task_id)
                {
                    continue;
                }
                zval *task_notify_data = php_swoole_task_unpack(task_result);
                if (task_notify_data == NULL)
                {
                    RETURN_FALSE;
                }
                else
                {
                    RETVAL_ZVAL(task_notify_data, 0, 0);
                    efree(task_notify_data);
                    return;
                }
                break;
            }
            else
            {
                swoole_php_error(E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
                break;
            }
        }
    }
    else
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
    }
    RETURN_FALSE;
}

PHP_METHOD(swoole_server, taskWaitMulti)
{
    swEventData buf;
    zval *tasks;
    zval *task;
    double timeout = SW_TASKWAIT_TIMEOUT;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &tasks, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    array_init(return_value);

    int dst_worker_id;
    int task_id;
    int i = 0;
    int n_task = Z_ARRVAL_P(tasks)->nNumOfElements;

    if (n_task >= SW_MAX_CONCURRENT_TASK)
    {
        swoole_php_fatal_error(E_WARNING, "too many concurrent tasks.");
        RETURN_FALSE;
    }

    int list_of_id[SW_MAX_CONCURRENT_TASK];

    uint64_t notify;
    swEventData *task_result = &(serv->task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv->task_notify[SwooleWG.id];
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    char _tmpfile[sizeof(SW_TASK_TMP_FILE)] = SW_TASK_TMP_FILE;
    int _tmpfile_fd = swoole_tmpfile(_tmpfile);
    if (_tmpfile_fd < 0)
    {
        RETURN_FALSE;
    }
    close(_tmpfile_fd);
    int *finish_count = (int *) task_result->data;

    worker->lock.lock(&worker->lock);
    *finish_count = 0;
    memcpy(task_result->data + 4, _tmpfile, sizeof(_tmpfile));
    worker->lock.unlock(&worker->lock);

    //clear history task
    int efd = task_notify_pipe->getFd(task_notify_pipe, 0);
    while (read(efd, &notify, sizeof(notify)) > 0);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(tasks), task)
        task_id = php_swoole_task_pack(&buf, task);
        if (task_id < 0)
        {
            swoole_php_fatal_error(E_WARNING, "task pack failed.");
            goto fail;
        }
        swTask_type(&buf) |= SW_TASK_WAITALL;
        dst_worker_id = -1;
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        if (swProcessPool_dispatch_blocking(&serv->gs->task_workers, &buf, &dst_worker_id) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
            task_id = -1;
            fail:
            add_index_bool(return_value, i, 0);
            n_task --;
        }
        else
        {
            sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        }
        list_of_id[i] = task_id;
        i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0)
    {
        SwooleG.error = SW_ERROR_TASK_DISPATCH_FAIL;
        RETURN_FALSE;
    }

    double _now = swoole_microtime();
    while (n_task > 0)
    {
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        if (ret > 0 && *finish_count < n_task)
        {
            if (swoole_microtime() - _now < timeout)
            {
                continue;
            }
        }
        break;
    }

    worker->lock.lock(&worker->lock);
    swString *content = swoole_file_get_contents(_tmpfile);
    worker->lock.unlock(&worker->lock);

    if (content == NULL)
    {
        RETURN_FALSE;
    }

    swEventData *result;
    zval *zdata;
    int j;

    do
    {
        result = (swEventData *) (content->str + content->offset);
        task_id = result->info.fd;
        zdata = php_swoole_task_unpack(result);
        if (zdata == NULL)
        {
            goto next;
        }
        for (j = 0; j < Z_ARRVAL_P(tasks)->nNumOfElements; j++)
        {
            if (list_of_id[j] == task_id)
            {
                break;
            }
        }
        add_index_zval(return_value, j, zdata);
        efree(zdata);
        next: content->offset += sizeof(swDataHead) + result->info.len;
    }
    while(content->offset < content->length);
    //free memory
    swString_free(content);
    //delete tmp file
    unlink(_tmpfile);
}

#ifdef SW_COROUTINE
PHP_METHOD(swoole_server, taskCo)
{
    swEventData buf;
    zval *tasks;
    zval *task;
    double timeout = SW_TASKWAIT_TIMEOUT;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &tasks, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    int dst_worker_id = -1;
    int task_id;
    int i = 0;
    int n_task = Z_ARRVAL_P(tasks)->nNumOfElements;

    if (n_task >= SW_MAX_CONCURRENT_TASK)
    {
        swoole_php_fatal_error(E_WARNING, "too many concurrent tasks.");
        RETURN_FALSE;
    }

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    int *list = ecalloc(n_task, sizeof(int));
    if (list == NULL)
    {
        RETURN_FALSE;
    }

    swTaskCo *task_co = emalloc(sizeof(swTaskCo));
    if (task_co == NULL)
    {
        efree(list);
        RETURN_FALSE;
    }

    zval *result;
    SW_ALLOC_INIT_ZVAL(result);
    array_init(result);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(tasks), task)
        task_id = php_swoole_task_pack(&buf, task);
        if (task_id < 0)
        {
            swoole_php_fatal_error(E_WARNING, "failed to pack task.");
            goto fail;
        }
        swTask_type(&buf) |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);
        dst_worker_id = -1;
        sw_atomic_fetch_add(&serv->stats->tasking_num, 1);
        if (swProcessPool_dispatch(&serv->gs->task_workers, &buf, &dst_worker_id) < 0)
        {
            task_id = -1;
            fail:
            add_index_bool(result, i, 0);
            n_task --;
            sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        }
        else
        {
            swHashMap_add_int(task_coroutine_map, buf.info.fd, task_co);
        }
        list[i] = task_id;
        i++;
    SW_HASHTABLE_FOREACH_END();

    if (n_task == 0)
    {
        SwooleG.error = SW_ERROR_TASK_DISPATCH_FAIL;
        RETURN_FALSE;
    }

    int ms = (int) (timeout * 1000);

    task_co->result = result;
    task_co->list = list;
    task_co->count = n_task;
    task_co->context.state = SW_CORO_CONTEXT_RUNNING;

    swTimer_node *timer = swTimer_add(&SwooleG.timer, ms, 0, task_co, php_swoole_task_onTimeout);
    if (timer)
    {
        task_co->timer = timer;
    }
    coro_save(&task_co->context);
    coro_yield();
}
#endif

PHP_METHOD(swoole_server, task)
{
    swEventData buf;
    zval *data;
    zval *callback = NULL;

    zend_long dst_worker_id = -1;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(dst_worker_id)
        Z_PARAM_ZVAL(callback)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_check_task_param(serv, dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, data) < 0)
    {
        RETURN_FALSE;
    }

    if (callback && !ZVAL_IS_NULL(callback))
    {
#ifdef PHP_SWOOLE_CHECK_CALLBACK
        char *func_name = NULL;
        if (!sw_zend_is_callable(callback, 0, &func_name))
        {
            swoole_php_fatal_error(E_WARNING, "function '%s' is not callable", func_name);
            efree(func_name);
            return;
        }
        efree(func_name);
#endif
        swTask_type(&buf) |= SW_TASK_CALLBACK;
        Z_TRY_ADDREF_P(callback);
        swHashMap_add_int(task_callbacks, buf.info.fd, sw_zval_dup(callback));
    }

    swTask_type(&buf) |= SW_TASK_NONBLOCK;

    int _dst_worker_id = (int) dst_worker_id;
    sw_atomic_fetch_add(&serv->stats->tasking_num, 1);

    if (swProcessPool_dispatch(&serv->gs->task_workers, &buf, &_dst_worker_id) >= 0)
    {
        RETURN_LONG(buf.info.fd);
    }
    else
    {
        sw_atomic_fetch_sub(&serv->stats->tasking_num, 1);
        RETURN_FALSE;
    }
}

PHP_METHOD(swoole_server, sendMessage)
{
    swEventData buf;

    zval *message;
    long worker_id = -1;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zl", &message, &worker_id) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_id == SwooleWG.id)
    {
        swoole_php_fatal_error(E_WARNING, "can't send messages to self.");
        RETURN_FALSE;
    }

    if (worker_id >= serv->worker_num + serv->task_worker_num)
    {
        swoole_php_fatal_error(E_WARNING, "worker_id[%d] is invalid.", (int) worker_id);
        RETURN_FALSE;
    }

    if (!serv->onPipeMessage)
    {
        swoole_php_fatal_error(E_WARNING, "onPipeMessage is null, can't use sendMessage.");
        RETURN_FALSE;
    }

    if (php_swoole_task_pack(&buf, message) < 0)
    {
        RETURN_FALSE;
    }

    buf.info.type = SW_EVENT_PIPE_MESSAGE;
    buf.info.from_id = SwooleWG.id;

    swWorker *to_worker = swServer_get_worker(serv, worker_id);
    SW_CHECK_RETURN(swWorker_send2worker(to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK));
}

PHP_METHOD(swoole_server, finish)
{
    zval *data;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(php_swoole_task_finish(serv, data, NULL));
}

PHP_METHOD(swoole_server, bind)
{
    long fd = 0;
    long uid = 0;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &fd, &uid) == FAILURE)
    {
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        RETURN_FALSE;
    }

    sw_spinlock(&conn->lock);
    if (conn->uid != 0)
    {
        RETVAL_FALSE;
    }
    else
    {
        conn->uid = (uint32_t) uid;
        RETVAL_TRUE;
    }
    sw_spinlock_release(&conn->lock);
}

#ifdef SWOOLE_SOCKETS_SUPPORT
PHP_METHOD(swoole_server, getSocket)
{
    long port = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &port) == FAILURE)
    {
        RETURN_FALSE;
    }

    zval *zobject = getThis();
    swServer *serv = swoole_get_object(zobject);

    int sock = swServer_get_socket(serv, port);
    php_socket *socket_object = swoole_convert_to_socket(sock);

    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
}
#endif

PHP_METHOD(swoole_server, connection_info)
{
    zval *zobject = getThis();

    zend_bool noCheckConnection = 0;
    zval *zfd;
    long from_id = -1;

    swServer *serv = swoole_get_object(zobject);
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|lb", &zfd, &from_id, &noCheckConnection) == FAILURE)
    {
        RETURN_FALSE;
    }

    zend_long fd = 0;
    zend_bool ipv6_udp = 0;

    //ipv6 udp
    if (Z_TYPE_P(zfd) == IS_STRING)
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

        swoole_php_error(E_DEPRECATED, "The UDP connection_info is deprecated, use onPacket instead.");

        if (ipv6_udp)
        {
            add_assoc_zval(return_value, "remote_ip", zfd);
        }
        else
        {
            struct in_addr sin_addr;
            sin_addr.s_addr = fd;
            add_assoc_string(return_value, "remote_ip", inet_ntoa(sin_addr));
        }

        if (from_id == 0)
        {
            return;
        }

        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &from_id, sizeof(udp_info));
        //server socket
        swConnection *from_sock = swServer_connection_get(serv, udp_info.from_fd);
        if (from_sock)
        {
            add_assoc_long(return_value, "server_fd", from_sock->fd);
            add_assoc_long(return_value, "socket_type", from_sock->socket_type);
            add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        }
        add_assoc_long(return_value, "remote_port", udp_info.port);
        return;
    }

    swConnection *conn = swServer_connection_verify(serv, fd);
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

        if (conn->uid > 0 || serv->dispatch_mode == SW_DISPATCH_UIDMOD)
        {
            add_assoc_long(return_value, "uid", conn->uid);
        }

        swListenPort *port = swServer_get_port(serv, conn->fd);
        if (port && port->open_websocket_protocol)
        {
            add_assoc_long(return_value, "websocket_status", conn->websocket_status);
        }

#ifdef SW_USE_OPENSSL
        if (conn->ssl_client_cert.length > 0)
        {
            add_assoc_stringl(return_value, "ssl_client_cert", conn->ssl_client_cert.str, conn->ssl_client_cert.length - 1);
        }
#endif
        //server socket
        swConnection *from_sock = swServer_connection_get(serv, conn->from_fd);
        if (from_sock)
        {
            add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        }
        add_assoc_long(return_value, "server_fd", conn->from_fd);
        add_assoc_long(return_value, "socket_fd", conn->fd);
        add_assoc_long(return_value, "socket_type", conn->socket_type);
        add_assoc_long(return_value, "remote_port", swConnection_get_port(conn));
        add_assoc_string(return_value, "remote_ip", swConnection_get_ip(conn));
        add_assoc_long(return_value, "reactor_id", conn->from_id);
        add_assoc_long(return_value, "connect_time", conn->connect_time);
        add_assoc_long(return_value, "last_time", conn->last_time);
        add_assoc_long(return_value, "close_errno", conn->close_errno);
    }
}

PHP_METHOD(swoole_server, connection_list)
{
    long start_fd = 0;
    long find_count = 10;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ll", &start_fd, &find_count) == FAILURE)
    {
        RETURN_FALSE;
    }

    //超过最大查找数量
    if (find_count > SW_MAX_FIND_COUNT)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_connection_list max_find_count=%d", SW_MAX_FIND_COUNT);
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
#ifdef SW_USE_OPENSSL
            if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
            {
                continue;
            }
#endif
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
    long fd;
    zval *zdata;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz", &fd, &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *data;
    size_t length = php_swoole_get_send_data(zdata, &data);

    if (length == 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    if (serv->factory_mode != SW_MODE_BASE || swIsTaskWorker())
    {
        swoole_php_fatal_error(E_WARNING, "can't sendwait.");
        RETURN_FALSE;
    }

    //UDP
    if (swServer_is_udp(fd))
    {
        swoole_php_fatal_error(E_WARNING, "can't sendwait.");
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
    zend_long fd;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

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

PHP_METHOD(swoole_server, protect)
{
    long fd;
    zend_bool value = 1;

    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|b", &fd, &value) == FAILURE)
    {
        RETURN_FALSE;
    }

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
        conn->protect = value;
        RETURN_TRUE;
    }
}

#ifdef SW_BUFFER_RECV_TIME
PHP_METHOD(swoole_server, getReceivedTime)
{
    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }
    if (serv->last_receive_usec > 0)
    {
        RETURN_DOUBLE(serv->last_receive_usec);
    }
    else
    {
        RETURN_FALSE;
    }
}
#endif

PHP_METHOD(swoole_server, shutdown)
{
    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    if (kill(serv->gs->master_pid, SIGTERM) < 0)
    {
        swoole_php_sys_error(E_WARNING, "failed to shutdown. kill(%d, SIGTERM) failed.", serv->gs->master_pid);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_METHOD(swoole_server, stop)
{
    swServer *serv = swoole_get_object(getThis());
    if (serv->gs->start == 0)
    {
        swoole_php_fatal_error(E_WARNING, "server is not running.");
        RETURN_FALSE;
    }

    zend_bool wait_reactor = 0;
    long worker_id = SwooleWG.id;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lb", &worker_id, &wait_reactor) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_id == SwooleWG.id && wait_reactor == 0)
    {
        if (SwooleG.main_reactor != NULL)
        {
            SwooleG.main_reactor->running = 0;
        }
        SwooleG.running = 0;
    }
    else
    {
        swWorker *worker = swServer_get_worker(SwooleG.serv, worker_id);
        if (worker == NULL)
        {
            RETURN_FALSE;
        }
        else if (kill(worker->pid, SIGTERM) < 0)
        {
            swoole_php_sys_error(E_WARNING, "kill(%d, SIGTERM) failed.", worker->pid);
            RETURN_FALSE;
        }
    }
    RETURN_TRUE;
}

// swoole_connection_iterator

PHP_METHOD(swoole_connection_iterator, rewind)
{
    swConnectionIterator *itearator = swoole_get_object(getThis());
    itearator->current_fd = swServer_get_minfd(SwooleG.serv);
}

PHP_METHOD(swoole_connection_iterator, valid)
{
    swConnectionIterator *itearator = swoole_get_object(getThis());
    int fd = itearator->current_fd;
    swConnection *conn;

    int max_fd = swServer_get_maxfd(itearator->serv);
    for (; fd <= max_fd; fd++)
    {
        conn = &SwooleG.serv->connection_list[fd];

        if (conn->active && !conn->closed)
        {
#ifdef SW_USE_OPENSSL
            if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
            {
                continue;
            }
#endif
            if (itearator->port && conn->from_fd != itearator->port->sock)
            {
                continue;
            }
            itearator->session_id = conn->session_id;
            itearator->current_fd = fd;
            itearator->index++;
            RETURN_TRUE;
        }
    }

    RETURN_FALSE;
}

PHP_METHOD(swoole_connection_iterator, current)
{
    swConnectionIterator *itearator = swoole_get_object(getThis());
    RETURN_LONG(itearator->session_id);
}

PHP_METHOD(swoole_connection_iterator, next)
{
    swConnectionIterator *itearator = swoole_get_object(getThis());
    itearator->current_fd++;
}

PHP_METHOD(swoole_connection_iterator, key)
{
    swConnectionIterator *itearator = swoole_get_object(getThis());
    RETURN_LONG(itearator->index);
}

PHP_METHOD(swoole_connection_iterator, count)
{
    swConnectionIterator *i = swoole_get_object(getThis());
    if (i->port)
    {
        RETURN_LONG(i->port->connection_num);
    }
    else
    {
        RETURN_LONG(i->serv->stats->connection_num);
    }
}

PHP_METHOD(swoole_connection_iterator, offsetExists)
{
    zval *zobject = (zval *) SwooleG.serv->ptr2;
    zval *retval = NULL;
    zval *zfd;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(&zobject, swoole_server_class_entry_ptr, NULL, "exist", &retval, zfd);
    if (retval)
    {
        RETVAL_BOOL(Z_BVAL_P(retval));
        zval_ptr_dtor(retval);
    }
}

PHP_METHOD(swoole_connection_iterator, offsetGet)
{
    zval *zobject = (zval *) SwooleG.serv->ptr2;
    zval *retval = NULL;
    zval *zfd;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }
    sw_zend_call_method_with_1_params(&zobject, swoole_server_class_entry_ptr, NULL, "connection_info", &retval, zfd);
    if (retval)
    {
        RETVAL_ZVAL(retval, 0, 0);
    }
}

PHP_METHOD(swoole_connection_iterator, offsetSet)
{
    return;
}

PHP_METHOD(swoole_connection_iterator, offsetUnset)
{
    return;
}

PHP_METHOD(swoole_connection_iterator, __destruct)
{
    swConnectionIterator *i = swoole_get_object(getThis());
    efree(i);
    swoole_set_object(getThis(), NULL);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
