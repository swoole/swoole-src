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
#include "php_streams.h"
#include "php_network.h"

#include "ext/standard/file.h"


#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "ext/standard/basic_functions.h"
#include <setjmp.h>
#endif


typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _filename;
#endif
    zval *callback;
    zval *filename;
    int fd;
    off_t offset;
    uint16_t type;
    uint8_t once;
    char *content;
    uint32_t length;
} file_request;

typedef struct
{
    int fd;
    off_t offset;
} file_handle;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _domain;
#endif
    zval *callback;
    zval *domain;
#ifdef SW_COROUTINE
    php_context *context;  //add for coro
    uint8_t useless; //1 代表没有用
    swTimer_node *timer;
#endif

} dns_request;

typedef struct
{
    swString *zaddress;
    int64_t  update_time;
} dns_cache;

typedef struct
{
    zval *callback;
#ifdef SW_COROUTINE
    php_context *context;
#endif
    pid_t pid;
    int fd;
    swString *buffer;
} process_stream;

static void php_swoole_aio_onComplete(swAio_event *event);
static void php_swoole_dns_callback(char *domain, swDNSResolver_result *result, void *data);
#ifdef SW_COROUTINE
static void php_swoole_dns_callback_coro(char *domain, swDNSResolver_result *result, void *data);
static void php_swoole_dns_timeout_coro(swTimer *timer, swTimer_node *tnode);
#endif

static void php_swoole_file_request_free(void *data);

static swHashMap *php_swoole_open_files;
static swHashMap *php_swoole_aio_request;

#ifdef SW_COROUTINE
static swHashMap *request_cache_map = NULL; //以domin为区分
#endif

#ifdef SW_COROUTINE
static sw_inline int64_t swTimer_get_now_msec()
{
    struct timeval now;
    if (swTimer_now(&now) < 0)
    {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec) / 1000;
    return msec1 + msec2;
}
#endif

static sw_inline void swoole_aio_free(void *ptr)
{
    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        free(ptr);
    }
    else
    {
        efree(ptr);
    }
}

static sw_inline void* swoole_aio_malloc(size_t __size)
{
#ifdef HAVE_LINUX_AIO
    void *memory;
    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        size_t buf_len = __size + (sysconf(_SC_PAGESIZE) - (__size % sysconf(_SC_PAGESIZE)));
        if (posix_memalign((void **) &memory, sysconf(_SC_PAGESIZE), buf_len) != 0)
        {
            return NULL;
        }
        else
        {
            return memory;
        }
    }
    else
#endif
    {
        return emalloc(__size);
    }
}

static void php_swoole_file_request_free(void *data)
{
    file_request *file_req = data;
    if (file_req->callback)
    {
        sw_zval_ptr_dtor(&file_req->callback);
    }
    swoole_aio_free(file_req->content);
    sw_zval_ptr_dtor(&file_req->filename);
    efree(file_req);
}

void swoole_async_init(int module_number TSRMLS_DC)
{
    bzero(&SwooleAIO, sizeof(SwooleAIO));

    REGISTER_LONG_CONSTANT("SWOOLE_AIO_BASE", SW_AIO_BASE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_AIO_LINUX", SW_AIO_LINUX, CONST_CS | CONST_PERSISTENT);

    php_swoole_open_files = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (php_swoole_open_files == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "create hashmap[1] failed.");
    }
    php_swoole_aio_request = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, php_swoole_file_request_free);
    if (php_swoole_aio_request == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "create hashmap[2] failed.");
    }
}

void php_swoole_check_aio()
{
    if (SwooleAIO.init == 0)
    {
        php_swoole_check_reactor();
        swAio_init();
    }
    if (!SwooleAIO.callback)
    {
        SwooleAIO.callback = php_swoole_aio_onComplete;
    }
}

static void php_swoole_dns_callback(char *domain, swDNSResolver_result *result, void *data)
{
    SWOOLE_GET_TSRMLS;
    dns_request *req = data;
    zval *retval = NULL;
    zval *zaddress;
    zval **args[2];
    char *address;

    SW_MAKE_STD_ZVAL(zaddress);
    if (result->num > 0)
    {
        if (SwooleG.dns_lookup_random)
        {
            address = result->hosts[rand() % result->num].address;
        }
        else
        {
            address = result->hosts[0].address;
        }
        SW_ZVAL_STRING(zaddress, address, 1);
    }
    else
    {
        SW_ZVAL_STRING(zaddress, "", 1);
    }

    args[0] = &req->domain;
    args[1] = &zaddress;

    zval *zcallback = req->callback;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_asyns_dns_lookup handler error.");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&req->callback);
    sw_zval_ptr_dtor(&req->domain);
    efree(req);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zaddress);
}

//用于coro 回调
#ifdef SW_COROUTINE
static void php_swoole_dns_callback_coro(char *domain, swDNSResolver_result *result, void *data)
{
    SWOOLE_GET_TSRMLS;
    dns_request *req = data;
    zval *retval = NULL;

    zval *zaddress;
    char *address;
    SW_MAKE_STD_ZVAL(zaddress);
    if (result->num > 0)
    {
        if (SwooleG.dns_lookup_random)
        {
            address = result->hosts[rand() % result->num].address;
        }
        else
        {
            address = result->hosts[0].address;
        }

        SW_ZVAL_STRING(zaddress, address, 1);
    }
    else
    {
        SW_ZVAL_STRING(zaddress, "", 1);
    }

    //update cache
    dns_cache *cache = swHashMap_find(request_cache_map, Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain));
    if (cache == NULL )
    {
        cache = emalloc(sizeof(dns_cache));
        swHashMap_add(request_cache_map, Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain), cache);
        cache->zaddress = swString_new(20);
    }

    swString_write_ptr(cache->zaddress, 0, Z_STRVAL_P(zaddress), Z_STRLEN_P(zaddress));

    cache->update_time = (int64_t) swTimer_get_now_msec + (int64_t) (SwooleG.dns_cache_refresh_time * 1000);

    //timeout
    if (req->timer)
    {
        swTimer_del(&SwooleG.timer, req->timer);
        req->timer = NULL;
    }
    if (req->useless)
    {
        efree(req);
        return;
    }

    int ret = coro_resume(req->context, zaddress, &retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    //说明已经yield走了
    free_zdata:
    // free 上下文
    sw_zval_ptr_dtor(&zaddress);
    efree(req->context);
    efree(req);
}

//用于timeout
static void php_swoole_dns_timeout_coro(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval *zaddress;
    php_context *cxt = (php_context *) tnode->data;
#if PHP_MAJOR_VERSION < 7
    dns_request *req =(dns_request *) cxt->coro_params;
#else
    dns_request *req = (dns_request *) cxt->coro_params.value.ptr;
#endif

    SW_MAKE_STD_ZVAL(zaddress);

    dns_cache *cache = swHashMap_find(request_cache_map, Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain));
    if (cache != NULL && cache->update_time > (int64_t) swTimer_get_now_msec)
    {
        SW_ZVAL_STRINGL(zaddress, (*cache->zaddress).str, (*cache->zaddress).length, 1);
    }
    else
    {
        SW_ZVAL_STRING(zaddress, "", 1);
    }

    int ret = coro_resume(req->context, zaddress, &retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zaddress);
    efree(req->context);
    req->useless = 1;

}
#endif

static void php_swoole_aio_onComplete(swAio_event *event)
{
    int isEOF = SW_FALSE;
    int64_t ret;

    zval *retval = NULL, *zcallback = NULL, *zwriten = NULL;
    zval *zcontent = NULL;
    zval **args[2];
    file_request *file_req = NULL;
    dns_request *dns_req = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#else
    zval _zcontent;
    zval _zwriten;
    bzero(&_zcontent, sizeof(zval));
    bzero(&_zwriten, sizeof(zval));
#endif

    if (event->type == SW_AIO_GETHOSTBYNAME)
    {
        dns_req = (dns_request *) event->req;
        if (dns_req->callback == NULL)
        {
            swoole_php_error(E_WARNING, "swoole_async: onAsyncComplete callback not found[0]");
            return;
        }
        zcallback = dns_req->callback;
    }
    else
    {
        file_req = swHashMap_find_int(php_swoole_aio_request, event->task_id);
        if (!file_req)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete callback not found[1]");
            return;
        }
        if (file_req->callback == NULL && file_req->type == SW_AIO_READ)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete callback not found[2]");
            return;
        }
        zcallback = file_req->callback;
    }

    ret = event->ret;
    if (ret < 0)
    {
        SwooleG.error = event->error;
        swoole_php_error(E_WARNING, "Aio Error: %s[%d]", strerror(event->error), event->error);
    }
    else if (file_req != NULL)
    {
        if (ret == 0)
        {
            bzero(event->buf, event->nbytes);
            isEOF = SW_TRUE;
        }
        else if (file_req->once == 1)
        {
            if (SwooleAIO.mode != SW_AIO_LINUX && ret < file_req->length)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_async: ret_length[%d] < req->length[%d].", (int ) ret, file_req->length);
            }
        }
        else if (event->type == SW_AIO_READ)
        {
            file_req->offset += event->ret;
        }
    }

    if (event->type == SW_AIO_READ)
    {
        args[0] = &file_req->filename;
        args[1] = &zcontent;
#if PHP_MAJOR_VERSION < 7
        SW_MAKE_STD_ZVAL(zcontent);
#else
        zcontent = &_zcontent;
#endif
        if (ret < 0)
        {
            SW_ZVAL_STRING(zcontent, "", 1);
        }
        else
        {
            SW_ZVAL_STRINGL(zcontent, event->buf, ret, 1);
        }
    }
    else if (event->type == SW_AIO_WRITE)
    {
#if PHP_MAJOR_VERSION < 7
        SW_MAKE_STD_ZVAL(zwriten);
#else
        zwriten = &_zwriten;
#endif
        args[0] = &file_req->filename;
        args[1] = &zwriten;
        ZVAL_LONG(zwriten, ret);
    }
    else if(event->type == SW_AIO_GETHOSTBYNAME)
    {
        args[0] = &dns_req->domain;
#if PHP_MAJOR_VERSION < 7
        SW_MAKE_STD_ZVAL(zcontent);
#else
        zcontent = &_zcontent;
#endif
        if (ret < 0)
        {
            SW_ZVAL_STRING(zcontent, "", 1);
        }
        else
        {
            SW_ZVAL_STRING(zcontent, event->buf, 1);
        }
        args[1] = &zcontent;
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete unknown event type[%d].", event->type);
        return;
    }

    if (zcallback)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete handler error");
            return;
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
    }

    //file io
    if (file_req)
    {
        if (file_req->once == 1)
        {
            close_file:
            close(event->fd);
            swHashMap_del_int(php_swoole_aio_request, event->task_id);
        }
        else if(file_req->type == SW_AIO_WRITE)
        {
            if (retval != NULL && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
            {
                swHashMap_del(php_swoole_open_files, Z_STRVAL_P(file_req->filename), Z_STRLEN_P(file_req->filename));
                goto close_file;
            }
            else
            {
                swHashMap_del_int(php_swoole_aio_request, event->task_id);
            }
        }
        else
        {
            if ((retval != NULL && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval)) || isEOF)
            {
                goto close_file;
            }
            //Less than expected, at the end of the file
            else if (event->ret < event->nbytes)
            {
                event->ret = 0;
                php_swoole_aio_onComplete(event);
            }
            //continue to read
            else
            {
                int ret = SwooleAIO.read(event->fd, event->buf, event->nbytes, file_req->offset);
                if (ret < 0)
                {
                    swoole_php_fatal_error(E_WARNING, "swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error), event->error);
                    goto close_file;
                }
                else
                {
                    swHashMap_move_int(php_swoole_aio_request, event->task_id, ret);
                }
            }
        }
    }
    else if (dns_req)
    {
        sw_zval_ptr_dtor(&dns_req->callback);
        sw_zval_ptr_dtor(&dns_req->domain);
        efree(dns_req);
        efree(event->buf);
    }
    if (zcontent)
    {
        sw_zval_ptr_dtor(&zcontent);
    }
    if (zwriten)
    {
        sw_zval_ptr_dtor(&zwriten);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

PHP_FUNCTION(swoole_async_read)
{
    zval *callback;
    zval *filename;
    long buf_size = SW_AIO_DEFAULT_CHUNK_SIZE;
    long offset = 0;
    int open_flag = O_RDONLY;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|ll", &filename, &callback, &buf_size, &offset) == FAILURE)
    {
        return;
    }

    if (offset < 0)
    {
        swoole_php_fatal_error(E_WARNING, "offset must be greater than 0.");
        RETURN_FALSE;
    }
    if (buf_size > SW_AIO_MAX_CHUNK_SIZE)
    {
        buf_size = SW_AIO_MAX_CHUNK_SIZE;
    }

#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX && (buf_size % SW_AIO_MIN_UNIT_SIZE) != 0)
    {
        swoole_php_fatal_error(E_WARNING, "the chunk buffer size must be an integer multiple of %d.", SW_AIO_MIN_UNIT_SIZE);
        RETURN_FALSE;
    }
#endif

    convert_to_string(filename);

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        open_flag |= O_DIRECT;
    }

    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        swoole_php_sys_error(E_WARNING, "open(%s, O_RDONLY) failed.", Z_STRVAL_P(filename));
        RETURN_FALSE;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        swoole_php_sys_error(E_WARNING, "fstat(%s) failed.", Z_STRVAL_P(filename));
        close(fd);
        RETURN_FALSE;
    }
    if (offset >= file_stat.st_size)
    {
        swoole_php_fatal_error(E_WARNING, "offset must be less than file_size[=%ld].", file_stat.st_size);
        close(fd);
        RETURN_FALSE;
    }

    void *fcnt = swoole_aio_malloc(buf_size);
    if (fcnt == NULL)
    {
        swoole_php_sys_error(E_WARNING, "malloc failed.");
        close(fd);
        RETURN_FALSE;
    }

    file_request *req = emalloc(sizeof(file_request));
    req->fd = fd;

    req->filename = filename;
    sw_zval_add_ref(&filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(req->callback, req->_callback);
    }

    req->content = fcnt;
    req->once = 0;
    req->type = SW_AIO_READ;
    req->length = buf_size;
    req->offset = offset;

    php_swoole_check_aio();

    int ret = SwooleAIO.read(fd, fcnt, buf_size, offset);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        swHashMap_add_int(php_swoole_aio_request, ret, req);
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_write)
{
    zval *callback = NULL;
    zval *filename;

    char *fcnt;
    zend_size_t fcnt_len = 0;
    off_t offset = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|lz", &filename, &fcnt, &fcnt_len, &offset, &callback) == FAILURE)
    {
        return;
    }
    if (fcnt_len <= 0)
    {
        RETURN_FALSE;
    }
#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX && (fcnt_len % SW_AIO_MIN_UNIT_SIZE) != 0)
    {
        swoole_php_fatal_error(E_WARNING, "the length must be an integer multiple of %d.", SW_AIO_MIN_UNIT_SIZE);
        RETURN_FALSE;
    }
#endif
    if (callback && !ZVAL_IS_NULL(callback))
    {
        char *func_name = NULL;
        if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_WARNING, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
    }

    convert_to_string(filename);

    long fd = (long) swHashMap_find(php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename));
    if (fd == 0)
    {
        int open_flag = O_WRONLY | O_CREAT;

#ifdef HAVE_LINUX_AIO
        if (SwooleAIO.mode == SW_AIO_LINUX)
        {
            open_flag |= O_DIRECT;
            if (offset < 0)
            {
                swoole_php_fatal_error(E_WARNING, "cannot use FILE_APPEND with linux native aio.");
                RETURN_FALSE;
            }
        }
        else
#endif
        if (offset < 0)
        {
            open_flag |= O_APPEND;
        }

        fd = open(Z_STRVAL_P(filename), open_flag, 0644);
        if (fd < 0)
        {
            swoole_php_fatal_error(E_WARNING, "open(%s, %d) failed. Error: %s[%d]", Z_STRVAL_P(filename), open_flag, strerror(errno), errno);
            RETURN_FALSE;
        }
        swHashMap_add(php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename), (void*) fd);
    }

    if (offset < 0)
    {
        offset = 0;
    }

    file_request *req = emalloc(sizeof(file_request));
    char *wt_cnt = swoole_aio_malloc(fcnt_len);
    req->fd = fd;
    req->content = wt_cnt;
    req->once = 0;
    req->type = SW_AIO_WRITE;
    req->length = fcnt_len;
    req->offset = offset;
    req->filename = filename;
    sw_zval_add_ref(&filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(req->callback, req->_callback);
    }
    else
    {
        req->callback = NULL;
    }

    memcpy(wt_cnt, fcnt, fcnt_len);
    php_swoole_check_aio();

    int ret = SwooleAIO.write(fd, wt_cnt, fcnt_len, offset);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        swHashMap_add_int(php_swoole_aio_request, ret, req);
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_readfile)
{
    zval *callback;
    zval *filename;

    int open_flag = O_RDONLY;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        open_flag |=  O_DIRECT;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &filename, &callback) == FAILURE)
    {
        return;
    }
    convert_to_string(filename);

    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "open file[%s] failed. Error: %s[%d]", Z_STRVAL_P(filename), strerror(errno), errno);
        RETURN_FALSE;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "fstat failed. Error: %s[%d]", strerror(errno), errno);
        close(fd);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "file is empty.");
        close(fd);
        RETURN_FALSE;
    }
    if (file_stat.st_size > SW_AIO_MAX_FILESIZE)
    {
        swoole_php_fatal_error(E_WARNING, "file_size[size=%ld|max_size=%d] is too big. Please use swoole_async_read.",
                (long int) file_stat.st_size, SW_AIO_MAX_FILESIZE);
        close(fd);
        RETURN_FALSE;
    }

    size_t length = file_stat.st_size;

#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX && length % SwooleG.pagesize > 0)
    {
        length += SwooleG.pagesize - (length % SwooleG.pagesize);
    }
#endif

    file_request *req = emalloc(sizeof(file_request));
    req->fd = fd;

    req->filename = filename;
    sw_zval_add_ref(&filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(req->callback, req->_callback);
    }

    req->content = swoole_aio_malloc(length);
    req->once = 1;
    req->type = SW_AIO_READ;
    req->length = length;
    req->offset = 0;

    php_swoole_check_aio();

    int ret = SwooleAIO.read(fd, req->content, length, 0);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        swHashMap_add_int(php_swoole_aio_request, ret, req);
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_writefile)
{
    zval *callback = NULL;
    zval *filename;
    char *fcnt;
    zend_size_t fcnt_len;
    long flags = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "zs|zl", &filename, &fcnt, &fcnt_len, &callback, &flags) == FAILURE)
    {
        return;
    }
    int open_flag = O_CREAT | O_WRONLY;

#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        open_flag |= O_DIRECT;
        if (flags & PHP_FILE_APPEND)
        {
            swoole_php_fatal_error(E_WARNING, "cannot use FILE_APPEND with linux native aio.");
            RETURN_FALSE;
        }
    }
    else
#endif

    if (flags & PHP_FILE_APPEND)
    {
        open_flag |= O_APPEND;
    }
    else
    {
        open_flag |= O_TRUNC;
    }
    if (fcnt_len <= 0)
    {
        RETURN_FALSE;
    }
    if (fcnt_len > SW_AIO_MAX_FILESIZE)
    {
        swoole_php_fatal_error(E_WARNING, "file_size[size=%d|max_size=%d] is too big. Please use swoole_async_write.",
                fcnt_len, SW_AIO_MAX_FILESIZE);
        RETURN_FALSE;
    }
    if (callback && !ZVAL_IS_NULL(callback))
    {
        char *func_name = NULL;
        if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_WARNING, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
    }

    convert_to_string(filename);
    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "open file failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    size_t memory_size = fcnt_len;
#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX && memory_size % SwooleG.pagesize > 0)
    {
        memory_size += SwooleG.pagesize - (memory_size % SwooleG.pagesize);
    }
#endif

    char *wt_cnt = swoole_aio_malloc(memory_size);

    file_request *req = emalloc(sizeof(file_request));
    req->filename = filename;
    sw_zval_add_ref(&filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(req->callback, req->_callback);
    }
    else
    {
        req->callback = NULL;
    }

    req->fd = fd;
    req->type = SW_AIO_WRITE;
    req->content = wt_cnt;
    req->once = 1;
    req->length = fcnt_len;
    req->offset = 0;

    memcpy(wt_cnt, fcnt, fcnt_len);
#ifdef HAVE_LINUX_AIO
    if (SwooleAIO.mode == SW_AIO_LINUX && memory_size != fcnt_len)
    {
        memset(wt_cnt + fcnt_len, 0, memory_size - fcnt_len);
    }
#endif

    php_swoole_check_aio();

    int ret = SwooleAIO.write(fd, wt_cnt, memory_size, 0);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        swHashMap_add_int(php_swoole_aio_request, ret, req);
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_set)
{
    if (SwooleG.main_reactor != NULL)
    {
        swoole_php_fatal_error(E_ERROR, "eventLoop has already been created. unable to create swoole_server.");
        RETURN_FALSE;
    }

    zval *zset = NULL;
    HashTable *vht;
    zval *v;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }

    php_swoole_array_separate(zset);

    vht = Z_ARRVAL_P(zset);
    if (php_swoole_array_get_value(vht, "aio_mode", v))
    {
        convert_to_long(v);
        SwooleAIO.mode = (uint8_t) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "thread_num", v))
    {
        convert_to_long(v);
        SwooleAIO.thread_num = (uint8_t) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "enable_signalfd", v))
    {
        convert_to_boolean(v);
        SwooleG.enable_signalfd = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "dns_cache_refresh_time", v))
    {
          convert_to_double(v);
          SwooleG.dns_cache_refresh_time = Z_DVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        convert_to_long(v);
        SwooleG.socket_buffer_size = Z_LVAL_P(v);
        if (SwooleG.socket_buffer_size <= 0 || SwooleG.socket_buffer_size > SW_MAX_INT)
        {
            SwooleG.socket_buffer_size = SW_MAX_INT;
        }
    }
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        convert_to_long(v);
        SwooleG.log_level = Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "display_errors", v))
    {
        convert_to_boolean(v);
        SWOOLE_G(display_errors) = 0;
    }
    if (php_swoole_array_get_value(vht, "socket_dontwait", v))
    {
        convert_to_boolean(v);
        SwooleG.socket_dontwait = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "dns_lookup_random", v))
    {
        convert_to_boolean(v);
        SwooleG.dns_lookup_random = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "dns_server", v))
    {
        convert_to_string(v);
        SwooleG.dns_server_v4 = sw_strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    if (php_swoole_array_get_value(vht, "use_async_resolver", v))
    {
        convert_to_boolean(v);
        SwooleG.use_async_resolver = Z_BVAL_P(v);
    }
#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    //reuse port
    if (php_swoole_array_get_value(vht, "enable_reuse_port", v))
    {
        convert_to_boolean(v);
        if (Z_BVAL_P(v) && swoole_version_compare(SwooleG.uname.release, "3.9.0") >= 0)
        {
            SwooleG.reuse_port = 1;
        }
    }
#endif
    sw_zval_ptr_dtor(&zset);
}

PHP_FUNCTION(swoole_async_dns_lookup)
{
    zval *domain;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &domain, &cb) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(domain) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "invalid domain name.");
        RETURN_FALSE;
    }

    if (Z_STRLEN_P(domain) == 0)
    {
        swoole_php_fatal_error(E_WARNING, "domain name empty.");
        RETURN_FALSE;
    }

    dns_request *req = emalloc(sizeof(dns_request));
    req->callback = cb;
    sw_copy_to_stack(req->callback, req->_callback);
    sw_zval_add_ref(&req->callback);

    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    sw_zval_add_ref(&req->domain);

    /**
     * Use asynchronous IO
     */
    if (SwooleG.use_async_resolver)
    {
        php_swoole_check_reactor();

        SW_CHECK_RETURN(swDNSResolver_request(Z_STRVAL_P(domain), php_swoole_dns_callback, (void *) req));
    }

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        SwooleAIO.init = 0;
    }
    php_swoole_check_aio();

    /**
     * Use thread pool
     */
    int buf_size;
    if (Z_STRLEN_P(domain) < SW_IP_MAX_LENGTH)
    {
        buf_size = SW_IP_MAX_LENGTH + 1;
    }
    else
    {
        buf_size = Z_STRLEN_P(domain) + 1;
    }

    void *buf = emalloc(buf_size);
    bzero(buf, buf_size);
    memcpy(buf, Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    php_swoole_check_aio();
    SW_CHECK_RETURN(swAio_dns_lookup(req, buf, buf_size));
}

static int process_stream_onRead(swReactor *reactor, swEvent *event)
{
    SWOOLE_GET_TSRMLS;

    process_stream *ps = event->socket->object;
    char *buf = ps->buffer->str + ps->buffer->length;
    size_t len = ps->buffer->size - ps->buffer->length;

    int ret = read(event->fd, buf, len);
    if (ret > 0)
    {
        ps->buffer->length += ret;
        if (ps->buffer->length == ps->buffer->size)
        {
            swString_extend(ps->buffer, ps->buffer->size * 2);
        }
        return SW_OK;
    }
    else if (ret < 0)
    {
        swSysError("read() failed.");
        return SW_OK;
    }

    zval *retval = NULL;
    zval **args[2];

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    SW_ZVAL_STRINGL(zdata, ps->buffer->str, ps->buffer->length, 1);

    SwooleG.main_reactor->del(SwooleG.main_reactor, ps->fd);

    swString_free(ps->buffer);
    args[0] = &zdata;

    int status;
    zval *zstatus;
    SW_MAKE_STD_ZVAL(zstatus);

    pid_t pid = swWaitpid(ps->pid, &status, WNOHANG);
    if (pid > 0)
    {
        array_init(zstatus);
        add_assoc_long(zstatus, "code", WEXITSTATUS(status));
        add_assoc_long(zstatus, "signal", WTERMSIG(status));
    }
    else
    {
        ZVAL_FALSE(zstatus);
    }

    args[1] = &zstatus;

    zval *zcallback = ps->callback;

    if (zcallback)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete handler error");
        }
        sw_zval_free(zcallback);
    }
    else
    {
#ifdef SW_COROUTINE
        php_context *context = ps->context;
        sw_zval_add_ref(&zdata);
        add_assoc_zval(zstatus, "output", zdata);
        int ret = coro_resume(context, zstatus, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        efree(context);
#else
        return SW_OK;
#endif
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
    sw_zval_ptr_dtor(&zstatus);
    close(ps->fd);
    efree(ps);

    return SW_OK;
}

PHP_METHOD(swoole_async, exec)
{
    char *command;
    zend_size_t command_len;
    zval *callback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &command, &command_len, &callback) == FAILURE)
    {
        return;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_READ, process_stream_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_ERROR, process_stream_onRead);
    }

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid);
    if (fd < 0)
    {
        swoole_php_error(E_WARNING, "Unable to execute '%s'", command);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(1024);
    if (buffer == NULL)
    {
        RETURN_FALSE;
    }

    process_stream *ps = emalloc(sizeof(process_stream));
    ps->callback = sw_zval_dup(callback);
#ifdef SW_COROUTINE
    ps->context = NULL;
#endif
    sw_zval_add_ref(&ps->callback);

    ps->fd = fd;
    ps->pid = pid;
    ps->buffer = buffer;

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, ps->fd, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_READ) < 0)
    {
        sw_zval_free(ps->callback);
        efree(ps);
        RETURN_FALSE;
    }
    else
    {
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, ps->fd);
        _socket->object = ps;
        RETURN_LONG(pid);
    }
}

#ifdef SW_COROUTINE
PHP_FUNCTION(swoole_coroutine_exec)
{
    char *command;
    zend_size_t command_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &command, &command_len) == FAILURE)
    {
        return;
    }

    coro_check(TSRMLS_C);

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_READ, process_stream_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_ERROR, process_stream_onRead);
    }

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid);
    if (fd < 0)
    {
        swoole_php_error(E_WARNING, "Unable to execute '%s'", command);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(1024);
    if (buffer == NULL)
    {
        RETURN_FALSE;
    }

    process_stream *ps = emalloc(sizeof(process_stream));
    ps->callback = NULL;
    ps->context = emalloc(sizeof(php_context));
    ps->fd = fd;
    ps->pid = pid;
    ps->buffer = buffer;

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, ps->fd, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_READ) < 0)
    {
        efree(ps->context);
        efree(ps);
        RETURN_FALSE;
    }
    else
    {
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, ps->fd);
        _socket->object = ps;
        coro_save(ps->context);
        coro_yield();
    }
}

PHP_FUNCTION(swoole_async_dns_lookup_coro)
{
    zval *domain;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|d", &domain, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    coro_check(TSRMLS_C);
    if (Z_TYPE_P(domain) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "invalid domain name.");
        RETURN_FALSE;
    }

    if (Z_STRLEN_P(domain) == 0)
    {
        swoole_php_fatal_error(E_WARNING, "domain name empty.");
        RETURN_FALSE;
    }
    if (!request_cache_map)
    {
        request_cache_map = swHashMap_new(256, NULL);
    }

    //find cache
    dns_cache *cache = swHashMap_find(request_cache_map, Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    if (cache != NULL && cache->update_time > (int64_t)swTimer_get_now_msec )
    {
        SW_RETURN_STRINGL((*cache->zaddress).str,(*cache->zaddress).length,1);
    }

    dns_request *req = emalloc(sizeof(dns_request));
    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    req->useless = 0;

    php_context *sw_current_context = emalloc(sizeof(php_context));
    sw_current_context->onTimeout = NULL;
    sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
#if PHP_MAJOR_VERSION < 7
    sw_current_context->coro_params = req;
#else
    sw_current_context->coro_params.value.ptr = (void *) req;
#endif
    req->context = sw_current_context;

    php_swoole_check_reactor();
    int ret = swDNSResolver_request(Z_STRVAL_P(domain), php_swoole_dns_callback_coro, (void *) req);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }
    //add timeout
    php_swoole_check_timer(timeout);
    req->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, sw_current_context, php_swoole_dns_timeout_coro);
    if (req->timer)
    {
        sw_current_context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
    }
    coro_save(sw_current_context);
    coro_yield();
}
#endif
