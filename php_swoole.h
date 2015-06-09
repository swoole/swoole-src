<<<<<<< HEAD
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

/* $Id$ */

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"
#include <ext/date/php_date.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

#define PHP_SWOOLE_VERSION  "1.7.17"
#define PHP_SWOOLE_CHECK_CALLBACK

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define SW_HOST_SIZE  128

typedef struct
{
    uint16_t port;
    uint16_t from_fd;
} php_swoole_udp_t;

typedef struct _swTimer_callback
{
    zval* callback;
    zval* data;
    int interval;
    int type;
} swTimer_callback;

extern zend_module_entry swoole_module_entry;

#define phpext_swoole_ptr &swoole_module_entry

#ifdef PHP_WIN32
#	define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_SWOOLE_API
#endif

typedef struct
{
    void **array;
    uint32_t size;
} swoole_object_array;

#ifdef ZTS
#include "TSRM.h"
extern void ***sw_thread_ctx;
extern __thread swoole_object_array swoole_objects;
#else
extern swoole_object_array swoole_objects;
#endif


//#define SW_USE_PHP        1
#define SW_CHECK_RETURN(s)         if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{RETURN_FALSE;}return

#define swoole_php_error(level, fmt_str, ...)   if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_fatal_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_sys_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str" Error: %s[%d].", ##__VA_ARGS__, strerror(errno), errno)

#ifdef SW_ASYNC_MYSQL
#if defined(SW_HAVE_MYSQLI) && defined(SW_HAVE_MYSQLND)
#else
#error "Enable async_mysql support, But no mysqli or mysqlnd."
#undef SW_ASYNC_MYSQL
#endif
#endif

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, But no openssl library."
#endif
#endif

#if PHP_MAJOR_VERSION < 7
typedef zend_rsrc_list_entry zend_resource;
#define SW_RETURN_STRING                      RETURN_STRING
#define SW_Z_ARRVAL_P                         Z_ARRVAL_P
#define sw_add_assoc_string                   add_assoc_string
inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v);
#define sw_zend_hash_del                      zend_hash_del
#define sw_zend_hash_update                   zend_hash_update
#define sw_zend_hash_index_find               zend_hash_index_find
#define SW_ZVAL_STRINGL                       ZVAL_STRINGL
#define SW_ZEND_FETCH_RESOURCE_NO_RETURN      ZEND_FETCH_RESOURCE_NO_RETURN
#define SW_ZEND_FETCH_RESOURCE                ZEND_FETCH_RESOURCE
#define SW_ZEND_REGISTER_RESOURCE             ZEND_REGISTER_RESOURCE
#define SW_MAKE_STD_ZVAL(p,o)                 MAKE_STD_ZVAL(p)
#define SW_ZVAL_STRING                        ZVAL_STRING
#define SW_ALLOC_INIT_ZVAL(p,o)               ALLOC_INIT_ZVAL(p)
#define SW_RETVAL_STRINGL                     RETVAL_STRINGL
#define sw_smart_str                          smart_str
#define sw_php_var_unserialize                php_var_unserialize
#define sw_zend_is_callable                   zend_is_callable
#define sw_zend_hash_add                      zend_hash_add
#define sw_zend_hash_index_update             zend_hash_index_update
#define sw_call_user_function_ex              call_user_function_ex
#define sw_add_assoc_stringl_ex               add_assoc_stringl_ex
#define sw_add_assoc_stringl                  add_assoc_stringl
#define sw_zval_ptr_dtor                      zval_ptr_dtor
#define sw_zend_hash_copy                     zend_hash_copy
#define sw_zval_add_ref                       zval_add_ref
#define sw_zend_hash_exists                   zend_hash_exists
#define sw_strndup(v,l)                       strndup(Z_STRVAL_P(v),l)
#define sw_php_format_date                    php_format_date
#define sw_php_url_encode                     php_url_encode
#define SW_RETURN_STRINGL                     RETURN_STRINGL
#define sw_zend_register_internal_class_ex    zend_register_internal_class_ex
#define sw_zend_call_method_with_2_params     zend_call_method_with_2_params
#define zend_size_t                           int

#define SWOOLE_GET_SERVER(zobject, serv) zval *zserv;\
    if (sw_zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_server"), (void **) &zserv) == FAILURE){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have swoole server");\
    RETURN_FALSE;}\
    ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);

#define SWOOLE_GET_WORKER(zobject, process) zval *zprocess;\
    if (sw_zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_process"), (void **) &zprocess) == FAILURE){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have process");\
    RETURN_FALSE;}\
    ZEND_FETCH_RESOURCE(process, swWorker *, &zprocess, -1, SW_RES_PROCESS_NAME, le_swoole_process);

#define WRAPPER_ZEND_HASH_FOREACH_VAL(ht, entry)\
                zval **tmp = NULL;\
                for (zend_hash_internal_pointer_reset(ht);\
                     zend_hash_has_more_elements(ht) == SUCCESS; \
                     zend_hash_move_forward(ht)) {\
                     if (zend_hash_get_current_data(ht, (void**)&tmp) == FAILURE) {\
			continue;\
                       }\
                       entry = *tmp;
#define WRAPPER_ZEND_HASH_FOREACH_END() }
#define sw_zend_read_property                  zend_read_property
#define wrapper_zend_hash_get_current_key(a,b,c,d) zend_hash_get_current_key_ex(a,b,c,d,0,NULL)
#define sw_php_var_serialize(a,b,c)       php_var_serialize(a,&b,c)
#define IS_TRUE    1
inline int SW_Z_TYPE_P(zval *z);
#define SW_Z_TYPE_PP(z)        SW_Z_TYPE_P(*z)
#else
#define sw_php_var_serialize                php_var_serialize
#define zend_size_t                         size_t
#define SW_RETVAL_STRINGL(s, l,dup)         RETVAL_STRINGL(s,l)
#define ZEND_SET_SYMBOL(ht,str,arr) zend_hash_str_update(ht, str, sizeof(str)-1, arr);
inline int Z_BVAL_P(zval *v);
#define sw_add_assoc_stringl(__arg, __key, __str, __length, __duplicate) sw_add_assoc_stringl_ex(__arg, __key, strlen(__key)+1, __str, __length, __duplicate)
inline int sw_add_assoc_stringl_ex(zval *arg, const char *key, size_t key_len, char *str, size_t length,int duplicate);
#define SW_Z_ARRVAL_P(z)                          Z_ARRVAL_P(z)->ht
#define WRAPPER_ZEND_HASH_FOREACH_VAL(ht, entry)  ZEND_HASH_FOREACH_VAL(ht, entry){
#define WRAPPER_ZEND_HASH_FOREACH_END() }ZEND_HASH_FOREACH_END();
#define Z_ARRVAL_PP(s)                             Z_ARRVAL_P(*s)
#define SW_Z_TYPE_P                                Z_TYPE_P
#define SW_Z_TYPE_PP(s)                            SW_Z_TYPE_P(*s)
#define Z_STRVAL_PP(s)                             Z_STRVAL_P(*s)
#define Z_STRLEN_PP(s)                             Z_STRLEN_P(*s)
#define Z_LVAL_PP(v)                               Z_LVAL_P(*v)
#define sw_strndup(s,l)                            \
        ({zend_string *str = zend_string_copy(Z_STR_P(s));\
        str->val;})
inline char * sw_php_format_date(char *format, size_t format_len, time_t ts, int localtime);

inline char * sw_php_url_encode(char *value, size_t value_len, int* exten);

#define sw_zval_add_ref(p) Z_TRY_ADDREF_P(*p)
#define sw_zval_ptr_dtor(p)
#define sw_call_user_function_ex(function_table, object_pp, function_name, retval_ptr_ptr, param_count, params, no_separation, ymbol_table)\
    ({zval  real_params[param_count];\
    int i=0;\
    for(;i<param_count;i++){\
       real_params[i] = **params[i];\
    }\
    zval phpng_retval;\
    *retval_ptr_ptr = &phpng_retval;\
    call_user_function_ex(function_table,NULL,function_name,&phpng_retval,param_count,real_params,no_separation,NULL);})

#define sw_php_var_unserialize(rval, p, max, var_hash)\
php_var_unserialize(*rval, p, max, var_hash)

#define SW_MAKE_STD_ZVAL(p,o) \
    switch(o){                           \
    case 0:                              \
       { zval sw_data0;p = &sw_data0;break;}\
    case 1:                               \
       { zval sw_data1;p = &sw_data1;break;}\
    case 2:                                    \
       { zval sw_data2;p = &sw_data2;break;}\
    default:                                \
            break;\
     }

#define SW_RETURN_STRINGL(z,l,t)                      \
               zval key;\
                ZVAL_STRING(&key, z);\
                RETURN_STR(Z_STR(key))

#define SW_ALLOC_INIT_ZVAL(p,o)        SW_MAKE_STD_ZVAL(p,o)
#define SW_ZEND_FETCH_RESOURCE_NO_RETURN(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type)        \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))
#define SW_ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#define SW_RETURN_STRING(val, duplicate)     RETURN_STRING(val)
#define sw_add_assoc_string(array, key, value, duplicate)   add_assoc_string(array, key, value)
#define sw_zend_hash_copy(target,source,pCopyConstructor,tmp,size) zend_hash_copy(target,source,pCopyConstructor)
#define sw_zend_register_internal_class_ex(entry,ptr,str)    zend_register_internal_class(entry)
#define sw_zend_call_method_with_2_params(obj,ptr,what,char,return,name,cb)     zend_call_method_with_2_params(*obj,ptr,what,char,*return,name,cb)
#define SW_ZVAL_STRINGL(z, s, l, dup)         ZVAL_STRINGL(z, s, l)
#define SW_ZVAL_STRING(z,s,dup)               ZVAL_STRING(z,s)
#define sw_smart_str                          smart_string

inline zval * sw_zend_read_property(zend_class_entry *class_ptr,zval *obj,char *s, int len,int what);
inline int sw_zend_is_callable(zval *cv, int a, char **name);

inline int sw_zend_hash_del(HashTable *ht, char *k, int len);
inline int sw_zend_hash_add(HashTable *ht, char *k, int len,void *pData,int datasize,void **pDest);

inline int sw_zend_hash_index_update(HashTable *ht, int key,void *pData,int datasize,void **pDest);

inline int sw_zend_hash_update(HashTable *ht, char *k, int len ,void * val,int size,void *ptr);

inline int wrapper_zend_hash_get_current_key( HashTable *ht, char **key, uint *idx, ulong *num);

inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v);

inline int sw_zend_hash_exists(HashTable *ht, char *k, int len);

#define SWOOLE_GET_SERVER(zobject, serv)zval rv; zval *zserv = zend_read_property(swoole_server_class_entry_ptr, zobject, SW_STRL("_server")-1, 0,&rv TSRMLS_CC);\
    if (!zserv || ZVAL_IS_NULL(zserv)){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have swoole_server");\
    RETURN_FALSE;}\
    serv = (swServer*) zend_fetch_resource(Z_RES_P(zserv), SW_RES_SERVER_NAME, le_swoole_server);

#define SWOOLE_GET_WORKER(zobject, process)zval rv2; zval *zprocess = zend_read_property(swoole_process_class_entry_ptr, zobject, SW_STRL("_process")-1, 0 ,&rv2 TSRMLS_CC);\
    if (!zprocess || ZVAL_IS_NULL(zprocess)){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have process");\
    RETURN_FALSE;}\
    process = (swWorker*) zend_fetch_resource(Z_RES_P(zprocess), SW_RES_PROCESS_NAME, le_swoole_process);

#endif


#define PHP_CLIENT_CALLBACK_NUM             4
//---------------------------------------------------
#define SW_CLIENT_CB_onConnect              0
#define SW_CLIENT_CB_onReceive              1
#define SW_CLIENT_CB_onClose                2
#define SW_CLIENT_CB_onError                3

#define SW_MAX_FIND_COUNT                   100    //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE           65535

#define PHP_SERVER_CALLBACK_NUM             16
//--------------------------------------------------------
#define SW_SERVER_CB_onStart                0 //Server start(master)
#define SW_SERVER_CB_onConnect              1 //accept new connection(worker)
#define SW_SERVER_CB_onReceive              2 //receive data(worker)
#define SW_SERVER_CB_onClose                3 //close tcp connection(worker)
#define SW_SERVER_CB_onShutdown             4 //Server sthudown(master)
#define SW_SERVER_CB_onTimer                5 //timer call(master)
#define SW_SERVER_CB_onWorkerStart          6 //Worker start(worker)
#define SW_SERVER_CB_onWorkerStop           7 //Worker shutdown(worker)
#define SW_SERVER_CB_onMasterConnect        8 //accept new connection(master)
#define SW_SERVER_CB_onMasterClose          9 //close tcp connection(master)
#define SW_SERVER_CB_onTask                 10 //new task(task_worker)
#define SW_SERVER_CB_onFinish               11 //async task finish(worker)
#define SW_SERVER_CB_onWorkerError          12 //worker exception(manager)
#define SW_SERVER_CB_onManagerStart         13
#define SW_SERVER_CB_onManagerStop          14
#define SW_SERVER_CB_onPipeMessage          15
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 9)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP))
#define php_swoole_array_length(array)      (Z_ARRVAL_P(array)->nNumOfElements)
static sw_inline void* swoole_get_object(zval *object)
{
#if PHP_MAJOR_VERSION < 7
zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
int handle = (int)Z_OBJ_HANDLE(*object);
#endif
    
    assert(handle < swoole_objects.size);
    return  swoole_objects.array[handle];
}

static sw_inline void swoole_set_object(zval *object, void *ptr)
{
       #if PHP_MAJOR_VERSION < 7
zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
int handle = (int)Z_OBJ_HANDLE(*object);
#endif
    if (handle >= swoole_objects.size)
    {
        swoole_objects.size = swoole_objects.size * 2;
        if (swoole_objects.size > SW_MAX_SOCKET_ID)
        {
            swoole_objects.size = SW_MAX_SOCKET_ID;
        }
        assert(handle < SW_MAX_SOCKET_ID);
        swoole_objects.array = erealloc(swoole_objects.array, swoole_objects.size);
    }
    swoole_objects.array[handle] = ptr;
}

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_lock_class_entry_ptr;
extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_table_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;

extern zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

extern HashTable php_sw_long_connections;
extern HashTable php_sw_aio_callback;

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_cpu_num);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_get_local_ip);

PHP_FUNCTION(swoole_server_create);
PHP_FUNCTION(swoole_server_set);
PHP_FUNCTION(swoole_server_start);
PHP_FUNCTION(swoole_server_stop);
PHP_FUNCTION(swoole_server_send);
PHP_FUNCTION(swoole_server_sendfile);
PHP_FUNCTION(swoole_server_close);
PHP_FUNCTION(swoole_server_on);
PHP_FUNCTION(swoole_server_handler);
PHP_FUNCTION(swoole_server_addlisten);
PHP_FUNCTION(swoole_server_addtimer);
PHP_FUNCTION(swoole_server_gettimer);
PHP_FUNCTION(swoole_server_task);
PHP_FUNCTION(swoole_server_taskwait);
PHP_FUNCTION(swoole_server_finish);
PHP_FUNCTION(swoole_server_reload);
PHP_FUNCTION(swoole_server_shutdown);
PHP_FUNCTION(swoole_server_heartbeat);
PHP_FUNCTION(swoole_connection_list);
PHP_FUNCTION(swoole_connection_info);

#ifdef HAVE_PCRE
PHP_METHOD(swoole_connection_iterator, count);
PHP_METHOD(swoole_connection_iterator, rewind);
PHP_METHOD(swoole_connection_iterator, next);
PHP_METHOD(swoole_connection_iterator, current);
PHP_METHOD(swoole_connection_iterator, key);
PHP_METHOD(swoole_connection_iterator, valid);
#endif

PHP_METHOD(swoole_server, sendmessage);
PHP_METHOD(swoole_server, addprocess);
PHP_METHOD(swoole_server, stats);
PHP_METHOD(swoole_server, bind);
PHP_METHOD(swoole_server, sendto);
PHP_METHOD(swoole_server, sendwait);

PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_set);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_write);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);

PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_close);
PHP_FUNCTION(swoole_async_readfile);
PHP_FUNCTION(swoole_async_writefile);
PHP_FUNCTION(swoole_async_dns_lookup);
PHP_FUNCTION(swoole_async_set);

PHP_FUNCTION(swoole_timer_add);
PHP_FUNCTION(swoole_timer_del);
PHP_FUNCTION(swoole_timer_after);
PHP_FUNCTION(swoole_timer_tick);
PHP_FUNCTION(swoole_timer_clear);

PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
#endif

PHP_FUNCTION(swoole_client_select);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_http_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_event_init();
void php_swoole_check_timer(int interval);
void php_swoole_register_callback(swServer *serv);
long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC);

zval *php_swoole_get_recv_data(zval *,swEventData *req TSRMLS_DC);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onClose(swServer *, int fd, int from_id);

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    key_t message_queue_key;
    uint32_t socket_buffer_size;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif	/* PHP_SWOOLE_H */
=======
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

/* $Id$ */

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"

#include <ext/standard/info.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

#define PHP_SWOOLE_VERSION  "1.7.18-alpha"
#define PHP_SWOOLE_CHECK_CALLBACK

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define SW_HOST_SIZE  128

typedef struct
{
    uint16_t port;
    uint16_t from_fd;
} php_swoole_udp_t;

typedef struct _swTimer_callback
{
    zval* callback;
    zval* data;
    int interval;
    int type;
} swTimer_callback;

extern zend_module_entry swoole_module_entry;

#define phpext_swoole_ptr &swoole_module_entry

#ifdef PHP_WIN32
#	define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_SWOOLE_API
#endif

typedef struct
{
    void **array;
    uint32_t size;
} swoole_object_array;

#ifdef ZTS
#include "TSRM.h"
extern void ***sw_thread_ctx;
extern __thread swoole_object_array swoole_objects;
#else
extern swoole_object_array swoole_objects;
#endif


//#define SW_USE_PHP        1
#define SW_CHECK_RETURN(s)         if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{RETURN_FALSE;}return

#define swoole_php_error(level, fmt_str, ...)   if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_fatal_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_sys_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str" Error: %s[%d].", ##__VA_ARGS__, strerror(errno), errno)

#ifdef SW_ASYNC_MYSQL
#if defined(SW_HAVE_MYSQLI) && defined(SW_HAVE_MYSQLND)
#else
#error "Enable async_mysql support, But no mysqli or mysqlnd."
#undef SW_ASYNC_MYSQL
#endif
#endif

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, But no openssl library."
#endif
#endif

#if PHP_MAJOR_VERSION < 7
typedef zend_rsrc_list_entry zend_resource;
#define SW_RETURN_STRING                     RETURN_STRING
#define sw_add_assoc_string                  add_assoc_string
#define sw_zend_hash_find                    zend_hash_find
#define sw_zend_hash_index_find              zend_hash_index_find
#define SW_ZVAL_STRINGL                      ZVAL_STRINGL
#else
#define SW_RETURN_STRING(val, duplicate)     RETURN_STRING(val)
#define sw_add_assoc_string(array, key, value, duplicate)   add_assoc_string(array, key, value)
#define SW_ZVAL_STRINGL(z, s, l, dup)         ZVAL_STRINGL(z, s, l)

static inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v)
{
    char _key[128];
    zend_string *key;

    if (sizeof(zend_string) + len > sizeof(_key))
    {
        key = emalloc(sizeof(zend_string) + len);
    }
    else
    {
       key = _key;
    }

    key->len = len;
    memcpy(key->val, k, len);
    key->val[len] = 0;

    zval *value = zend_hash_find(ht, key);

    if (value == NULL)
    {
        return FAILURE;
    }
    else
    {
        *v = value;
        return SUCCESS;
    }
}
#endif

#define PHP_CLIENT_CALLBACK_NUM             4
//---------------------------------------------------
#define SW_CLIENT_CB_onConnect              0
#define SW_CLIENT_CB_onReceive              1
#define SW_CLIENT_CB_onClose                2
#define SW_CLIENT_CB_onError                3

#define SW_MAX_FIND_COUNT                   100    //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE           65535

#define PHP_SERVER_CALLBACK_NUM             16
//--------------------------------------------------------
#define SW_SERVER_CB_onStart                0 //Server start(master)
#define SW_SERVER_CB_onConnect              1 //accept new connection(worker)
#define SW_SERVER_CB_onReceive              2 //receive data(worker)
#define SW_SERVER_CB_onClose                3 //close tcp connection(worker)
#define SW_SERVER_CB_onShutdown             4 //Server sthudown(master)
#define SW_SERVER_CB_onTimer                5 //timer call(master)
#define SW_SERVER_CB_onWorkerStart          6 //Worker start(worker)
#define SW_SERVER_CB_onWorkerStop           7 //Worker shutdown(worker)
#define SW_SERVER_CB_onMasterConnect        8 //accept new connection(master)
#define SW_SERVER_CB_onMasterClose          9 //close tcp connection(master)
#define SW_SERVER_CB_onTask                 10 //new task(task_worker)
#define SW_SERVER_CB_onFinish               11 //async task finish(worker)
#define SW_SERVER_CB_onWorkerError          12 //worker exception(manager)
#define SW_SERVER_CB_onManagerStart         13
#define SW_SERVER_CB_onManagerStop          14
#define SW_SERVER_CB_onPipeMessage          15
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 9)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP))
#define php_swoole_array_length(array)      (Z_ARRVAL_P(array)->nNumOfElements)

static sw_inline void* swoole_get_object(zval *object)
{
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
    assert(handle < swoole_objects.size);
    return  swoole_objects.array[handle];
}

static sw_inline void swoole_set_object(zval *object, void *ptr)
{
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
    if (handle >= swoole_objects.size)
    {
        uint32_t old_size = swoole_objects.size;
        swoole_objects.size = old_size * 2;
        if (swoole_objects.size > SW_MAX_SOCKET_ID)
        {
            swoole_objects.size = SW_MAX_SOCKET_ID;
        }
        assert(handle < SW_MAX_SOCKET_ID);
        swoole_objects.array = erealloc(swoole_objects.array, swoole_objects.size);
        bzero(swoole_objects.array + (old_size * sizeof(void*)), (swoole_objects.size - old_size) * sizeof(void**));
    }
    swoole_objects.array[handle] = ptr;
}

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_lock_class_entry_ptr;
extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_table_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;

extern zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

extern HashTable php_sw_long_connections;
extern HashTable php_sw_aio_callback;

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_cpu_num);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_get_local_ip);

PHP_FUNCTION(swoole_server_create);
PHP_FUNCTION(swoole_server_set);
PHP_FUNCTION(swoole_server_start);
PHP_FUNCTION(swoole_server_stop);
PHP_FUNCTION(swoole_server_send);
PHP_FUNCTION(swoole_server_sendfile);
PHP_FUNCTION(swoole_server_close);
PHP_FUNCTION(swoole_server_on);
PHP_FUNCTION(swoole_server_handler);
PHP_FUNCTION(swoole_server_addlisten);
PHP_FUNCTION(swoole_server_addtimer);
PHP_FUNCTION(swoole_server_gettimer);
PHP_FUNCTION(swoole_server_task);
PHP_FUNCTION(swoole_server_taskwait);
PHP_FUNCTION(swoole_server_finish);
PHP_FUNCTION(swoole_server_reload);
PHP_FUNCTION(swoole_server_shutdown);
PHP_FUNCTION(swoole_server_heartbeat);
PHP_FUNCTION(swoole_connection_list);
PHP_FUNCTION(swoole_connection_info);

#ifdef HAVE_PCRE
PHP_METHOD(swoole_connection_iterator, count);
PHP_METHOD(swoole_connection_iterator, rewind);
PHP_METHOD(swoole_connection_iterator, next);
PHP_METHOD(swoole_connection_iterator, current);
PHP_METHOD(swoole_connection_iterator, key);
PHP_METHOD(swoole_connection_iterator, valid);
#endif

PHP_METHOD(swoole_server, sendmessage);
PHP_METHOD(swoole_server, addprocess);
PHP_METHOD(swoole_server, stats);
PHP_METHOD(swoole_server, bind);
PHP_METHOD(swoole_server, sendto);
PHP_METHOD(swoole_server, sendwait);

PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_set);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_write);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);

PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_close);
PHP_FUNCTION(swoole_async_readfile);
PHP_FUNCTION(swoole_async_writefile);
PHP_FUNCTION(swoole_async_dns_lookup);
PHP_FUNCTION(swoole_async_set);

PHP_FUNCTION(swoole_timer_add);
PHP_FUNCTION(swoole_timer_del);
PHP_FUNCTION(swoole_timer_after);
PHP_FUNCTION(swoole_timer_tick);
PHP_FUNCTION(swoole_timer_clear);

PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
#endif

PHP_FUNCTION(swoole_client_select);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_http_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_event_init();
void php_swoole_check_timer(int interval);
void php_swoole_register_callback(swServer *serv);
long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC);

zval *php_swoole_get_recv_data(swEventData *req TSRMLS_DC);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onClose(swServer *, int fd, int from_id);

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    key_t message_queue_key;
    uint32_t socket_buffer_size;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif	/* PHP_SWOOLE_H */
>>>>>>> 0f94d97b1c71851cad8d92519f2cb2210006ac7d
