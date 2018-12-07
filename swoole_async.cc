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
#endif

#include <string>
#include <unordered_map>

typedef struct
{
    zval _callback;
    zval _filename;
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
    zval _callback;
    zval _domain;
    zval *callback;
    zval *domain;
    php_context *context;
    uint8_t useless;
    swTimer_node *timer;
} dns_request;

typedef struct
{
    char address[16];
    time_t update_time;
} dns_cache;

typedef struct
{
    zval *callback;
    pid_t pid;
    int fd;
    swString *buffer;
} process_stream;

static void aio_onFileCompleted(swAio_event *event);
static void aio_onDNSCompleted(swAio_event *event);
static void php_swoole_dns_callback(char *domain, swDNSResolver_result *result, void *data);
#ifdef SW_COROUTINE
static void coro_onDNSCompleted(char *domain, swDNSResolver_result *result, void *data);
static void dns_timeout_coro(swTimer *timer, swTimer_node *tnode);
#endif

static void php_swoole_file_request_free(void *data);

static std::unordered_map<std::string, int> open_files;
static std::unordered_map<std::string, dns_cache*> request_cache_map;

static void php_swoole_file_request_free(void *data)
{
    file_request *file_req = (file_request *) data;
    if (file_req->callback)
    {
        zval_ptr_dtor(file_req->callback);
    }
    efree(file_req->content);
    zval_ptr_dtor(file_req->filename);
    efree(file_req);
}

void swoole_async_init(int module_number)
{
    bzero(&SwooleAIO, sizeof(SwooleAIO));

    REGISTER_LONG_CONSTANT("SWOOLE_AIO_BASE", 0, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_AIO_LINUX", 0, CONST_CS | CONST_PERSISTENT);
}

void php_swoole_check_aio()
{
    if (unlikely(SwooleAIO.init == 0))
    {
        php_swoole_check_reactor();
        swAio_init();
    }
}

static void php_swoole_dns_callback(char *domain, swDNSResolver_result *result, void *data)
{
    dns_request *req = (dns_request *) data;
    zval *retval = NULL;
    zval *zaddress;
    zval args[2];
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
        ZVAL_STRING(zaddress, address);
    }
    else
    {
        ZVAL_STRING(zaddress, "");
    }

    args[0] = *req->domain;
    args[1] = *zaddress;

    zval *zcallback = req->callback;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_asyns_dns_lookup handler error.");
        return;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(req->callback);
    zval_ptr_dtor(req->domain);
    efree(req);
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zaddress);
}

static void coro_onDNSCompleted(char *domain, swDNSResolver_result *result, void *data)
{
    dns_request *req = (dns_request *) data;
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

        ZVAL_STRING(zaddress, address);
    }
    else
    {
        ZVAL_STRING(zaddress, "");
    }

    std::string key(Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain));
    dns_cache *cache;
    auto cache_iterator = request_cache_map.find(key);
    if (cache_iterator == request_cache_map.end())
    {
        cache = (dns_cache *) emalloc(sizeof(dns_cache));
        bzero(cache, sizeof(dns_cache));
        request_cache_map[key] = cache;
    }
    else
    {
        cache = cache_iterator->second;
    }

    memcpy(cache->address, Z_STRVAL_P(zaddress), Z_STRLEN_P(zaddress));
    cache->address[Z_STRLEN_P(zaddress)] = '\0';

    cache->update_time = swTimer_get_absolute_msec() + (int64_t) (SwooleG.dns_cache_refresh_time * 1000);

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

    int ret = sw_coro_resume(req->context, zaddress, retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    free_zdata:
    zval_ptr_dtor(zaddress);
    efree(req->context);
    efree(req);
}

static void dns_timeout_coro(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval *zaddress;
    php_context *cxt = (php_context *) tnode->data;
    dns_request *req = (dns_request *) cxt->coro_params.value.ptr;

    SW_MAKE_STD_ZVAL(zaddress);

    dns_cache *cache = request_cache_map[std::string(Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain))];
    if (cache != NULL && cache->update_time > swTimer_get_absolute_msec())
    {
        ZVAL_STRING(zaddress, cache->address);
    }
    else
    {
        ZVAL_STRING(zaddress, "");
    }

    int ret = sw_coro_resume(req->context, zaddress, retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    free_zdata:
    zval_ptr_dtor(zaddress);
    efree(req->context);
    req->useless = 1;
}

static void aio_onDNSCompleted(swAio_event *event)
{
    int64_t ret;

    dns_request *dns_req = NULL;
    zval *retval = NULL, *zcallback = NULL;
    zval args[2];
    zval _zcontent, *zcontent = &_zcontent;

    dns_req = (dns_request *) event->req;
    zcallback = dns_req->callback;
    ZVAL_NULL(zcontent);

    ret = event->ret;
    if (ret < 0)
    {
        SwooleG.error = event->error;
        swoole_php_error(E_WARNING, "Aio Error: %s[%d]", strerror(event->error), event->error);
    }

    args[0] = *dns_req->domain;
    if (ret < 0)
    {
        ZVAL_STRING(zcontent, "");
    }
    else
    {
        ZVAL_STRING(zcontent, (char *) event->buf);
    }
    args[1] = *zcontent;

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete handler error");
        return;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }

    zval_ptr_dtor(dns_req->callback);
    zval_ptr_dtor(dns_req->domain);
    efree(dns_req);
    efree(event->buf);

    if (!ZVAL_IS_NULL(zcontent))
    {
        zval_ptr_dtor(zcontent);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void aio_onFileCompleted(swAio_event *event)
{
    int isEOF = SW_FALSE;
    int64_t ret = event->ret;
    file_request *file_req = (file_request *) event->object;

    zval *retval = NULL, *zcallback = NULL;
    zval args[2];
    zval _zcontent, *zcontent = &_zcontent;
    zval _zwriten, *zwriten = &_zwriten;

    zcallback = file_req->callback;
    ZVAL_NULL(zcontent);
    ZVAL_NULL(zwriten);

    if (ret < 0)
    {
        SwooleG.error = event->error;
        swoole_php_error(E_WARNING, "Aio Error: %s[%d]", strerror(event->error), event->error);
    }
    else
    {
        if (ret == 0)
        {
            bzero(event->buf, event->nbytes);
            isEOF = SW_TRUE;
        }
        else if (file_req->once == 1 && ret < file_req->length)
        {
            swoole_php_fatal_error(E_WARNING, "ret_length[%d] < req->length[%d].", (int ) ret, file_req->length);
        }
        else if (event->type == SW_AIO_READ)
        {
            file_req->offset += event->ret;
        }
    }

    if (event->type == SW_AIO_READ)
    {
        if (ret < 0)
        {
            ZVAL_STRING(zcontent, "");
        }
        else
        {
            ZVAL_STRINGL(zcontent, (char* )event->buf, ret);
        }
        args[0] = *file_req->filename;
        args[1] = *zcontent;
    }
    else if (event->type == SW_AIO_WRITE)
    {
        ZVAL_LONG(zwriten, ret);
        args[0] = *file_req->filename;
        args[1] = *zwriten;
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async: onFileCompleted unknown event type[%d].", event->type);
        return;
    }

    if (zcallback)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete handler error");
            return;
        }
        if (UNEXPECTED(EG(exception)))
        {
            zend_exception_error(EG(exception), E_ERROR);
        }
    }

    //file io
    if (file_req->once == 1)
    {
        close_file:
        close(event->fd);
        php_swoole_file_request_free(file_req);
    }
    else if(file_req->type == SW_AIO_WRITE)
    {
        if (retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
        {
            open_files.erase(std::string(Z_STRVAL_P(file_req->filename), Z_STRLEN_P(file_req->filename)));
            goto close_file;
        }
        else
        {
            php_swoole_file_request_free(file_req);
        }
    }
    else
    {
        if ((retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval)) || isEOF)
        {
            goto close_file;
        }
        //Less than expected, at the end of the file
        else if (event->ret < (int) event->nbytes)
        {
            event->ret = 0;
            aio_onFileCompleted(event);
        }
        //continue to read
        else
        {
            swAio_event ev;
            ev.fd = event->fd;
            ev.buf = event->buf;
            ev.type = SW_AIO_READ;
            ev.nbytes = event->nbytes;
            ev.offset = file_req->offset;
            ev.flags = 0;
            ev.object = file_req;
            ev.handler = swAio_handler_read;
            ev.callback = aio_onFileCompleted;

            int ret = swAio_dispatch(&ev);
            if (ret < 0)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error), event->error);
                goto close_file;
            }
        }
    }

    if (!ZVAL_IS_NULL(zcontent))
    {
        zval_ptr_dtor(zcontent);
    }
    if (!ZVAL_IS_NULL(zwriten))
    {
        zval_ptr_dtor(zwriten);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

PHP_FUNCTION(swoole_async_read)
{
    zval *callback;
    zval *filename;
    long buf_size = SW_AIO_DEFAULT_CHUNK_SIZE;
    long offset = 0;
    int open_flag = O_RDONLY;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz|ll", &filename, &callback, &buf_size, &offset) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (offset < 0)
    {
        swoole_php_fatal_error(E_WARNING, "offset must be greater than 0.");
        RETURN_FALSE;
    }
    if (!php_swoole_is_callable(callback))
    {
        RETURN_FALSE;
    }
    if (buf_size > SW_AIO_MAX_CHUNK_SIZE)
    {
        buf_size = SW_AIO_MAX_CHUNK_SIZE;
    }

    convert_to_string(filename);
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
        swoole_php_fatal_error(E_WARNING, "offset must be less than file_size[=%jd].", (intmax_t) file_stat.st_size);
        close(fd);
        RETURN_FALSE;
    }

    void *fcnt = emalloc(buf_size);
    if (fcnt == NULL)
    {
        swoole_php_sys_error(E_WARNING, "malloc failed.");
        close(fd);
        RETURN_FALSE;
    }

    file_request *req = (file_request *) emalloc(sizeof(file_request));
    req->fd = fd;

    req->filename = filename;
    Z_TRY_ADDREF_P(filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (!php_swoole_is_callable(callback))
    {
        RETURN_FALSE;
    }

    req->callback = callback;
    Z_TRY_ADDREF_P(callback);
    sw_copy_to_stack(req->callback, req->_callback);
    req->content = (char*) fcnt;
    req->once = 0;
    req->type = SW_AIO_READ;
    req->length = buf_size;
    req->offset = offset;

    php_swoole_check_aio();

    swAio_event ev;
    ev.fd = fd;
    ev.buf = fcnt;
    ev.type = SW_AIO_READ;
    ev.nbytes = buf_size;
    ev.offset = offset;
    ev.flags = 0;
    ev.object = req;
    ev.handler = swAio_handler_read;
    ev.callback = aio_onFileCompleted;

    int ret = swAio_dispatch(&ev);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_write)
{
    zval *callback = NULL;
    zval *filename;

    char *fcnt;
    size_t fcnt_len = 0;
    off_t offset = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zs|lz", &filename, &fcnt, &fcnt_len, &offset, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (fcnt_len <= 0)
    {
        RETURN_FALSE;
    }
    if (callback && !ZVAL_IS_NULL(callback))
    {
        if (!php_swoole_is_callable(callback))
        {
            RETURN_FALSE;
        }
    }

    convert_to_string(filename);

    int fd;
    std::string key(Z_STRVAL_P(filename), Z_STRLEN_P(filename));
    auto file_iterator = open_files.find(key);
    if (file_iterator == open_files.end())
    {
        int open_flag = O_WRONLY | O_CREAT;
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
        open_files[key] = fd;
    }
    else
    {
        fd = file_iterator->second;
    }

    if (offset < 0)
    {
        offset = 0;
    }

    file_request *req = (file_request *) emalloc(sizeof(file_request));
    char *wt_cnt = (char *) emalloc(fcnt_len);
    req->fd = fd;
    req->content = wt_cnt;
    req->once = 0;
    req->type = SW_AIO_WRITE;
    req->length = fcnt_len;
    req->offset = offset;
    req->filename = filename;
    Z_TRY_ADDREF_P(filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        Z_TRY_ADDREF_P(callback);
        sw_copy_to_stack(req->callback, req->_callback);
    }
    else
    {
        req->callback = NULL;
    }

    memcpy(wt_cnt, fcnt, fcnt_len);
    php_swoole_check_aio();

    swAio_event ev;
    ev.fd = fd;
    ev.buf = wt_cnt;
    ev.type = SW_AIO_WRITE;
    ev.nbytes = fcnt_len;
    ev.offset = offset;
    ev.flags = 0;
    ev.object = req;
    ev.handler = swAio_handler_write;
    ev.callback = aio_onFileCompleted;

    int ret = swAio_dispatch(&ev);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_readfile)
{
    zval *callback;
    zval *filename;

    int open_flag = O_RDONLY;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &filename, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    convert_to_string(filename);

    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "open file[%s] failed. Error: %s[%d]", Z_STRVAL_P(filename), strerror(errno), errno);
        RETURN_FALSE;
    }
    if (!php_swoole_is_callable(callback))
    {
        close(fd);
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
    file_request *req = (file_request *) emalloc(sizeof(file_request));
    req->fd = fd;

    req->filename = filename;
    Z_TRY_ADDREF_P(filename);
    sw_copy_to_stack(req->filename, req->_filename);

    req->callback = callback;
    Z_TRY_ADDREF_P(callback);
    sw_copy_to_stack(req->callback, req->_callback);

    req->content = (char *) emalloc(length);
    req->once = 1;
    req->type = SW_AIO_READ;
    req->length = length;
    req->offset = 0;

    php_swoole_check_aio();

    swAio_event ev;
    ev.fd = fd;
    ev.buf = req->content;
    ev.type = SW_AIO_READ;
    ev.nbytes = length;
    ev.offset = 0;
    ev.flags = 0;
    ev.object = req;
    ev.handler = swAio_handler_read;
    ev.callback = aio_onFileCompleted;

    int ret = swAio_dispatch(&ev);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_writefile)
{
    zval *callback = NULL;
    zval *filename;
    char *fcnt;
    size_t fcnt_len;
    long flags = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zs|zl", &filename, &fcnt, &fcnt_len, &callback, &flags) == FAILURE)
    {
        RETURN_FALSE;
    }
    int open_flag = O_CREAT | O_WRONLY;
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
        swoole_php_fatal_error(E_WARNING, "file_size[size=%zd|max_size=%d] is too big. Please use swoole_async_write.",
                fcnt_len, SW_AIO_MAX_FILESIZE);
        RETURN_FALSE;
    }
    if (callback && !ZVAL_IS_NULL(callback))
    {
        if (!php_swoole_is_callable(callback))
        {
            RETURN_FALSE;
        }
    }

    convert_to_string(filename);
    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "open file failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    size_t memory_size = fcnt_len;
    char *wt_cnt = (char *) emalloc(memory_size);

    file_request *req = (file_request *) emalloc(sizeof(file_request));
    req->filename = filename;
    Z_TRY_ADDREF_P(filename);
    sw_copy_to_stack(req->filename, req->_filename);

    if (callback && !ZVAL_IS_NULL(callback))
    {
        req->callback = callback;
        Z_TRY_ADDREF_P(callback);
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

    php_swoole_check_aio();

    swAio_event ev;
    ev.fd = fd;
    ev.buf = wt_cnt;
    ev.type = SW_AIO_WRITE;
    ev.nbytes = memory_size;
    ev.offset = 0;
    ev.flags = 0;
    ev.object = req;
    ev.handler = swAio_handler_write;
    ev.callback = aio_onFileCompleted;

    int ret = swAio_dispatch(&ev);
    if (ret == SW_ERR)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_async_set)
{
    if (SwooleG.main_reactor != NULL)
    {
        swoole_php_fatal_error(E_ERROR, "eventLoop has already been created. unable to change settings.");
        RETURN_FALSE;
    }

    zval *zset = NULL;
    HashTable *vht;
    zval *v;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_swoole_array_separate(zset);

    vht = Z_ARRVAL_P(zset);
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
        SWOOLE_G(display_errors) = Z_BVAL_P(v);
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
    if (php_swoole_array_get_value(vht, "enable_coroutine", v))
    {
        convert_to_boolean(v);
        SwooleG.enable_coroutine = Z_BVAL_P(v);
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
    zval_ptr_dtor(zset);
}

PHP_FUNCTION(swoole_async_dns_lookup)
{
    zval *domain;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz", &domain, &cb) == FAILURE)
    {
        RETURN_FALSE;
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

    if (!php_swoole_is_callable(cb))
    {
        RETURN_FALSE;
    }

    dns_request *req = (dns_request *) emalloc(sizeof(dns_request));
    req->callback = cb;
    sw_copy_to_stack(req->callback, req->_callback);
    Z_TRY_ADDREF_P(req->callback);

    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    Z_TRY_ADDREF_P(req->domain);

    /**
     * Use asynchronous IO
     */
    if (SwooleG.use_async_resolver)
    {
        php_swoole_check_reactor();
        SW_CHECK_RETURN(swDNSResolver_request(Z_STRVAL_P(domain), php_swoole_dns_callback, (void *) req));
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

    swAio_event ev;
    ev.fd = 0;
    ev.buf = buf;
    ev.type = SW_AIO_WRITE;
    ev.nbytes = buf_size;
    ev.offset = 0;
    ev.flags = 0;
    ev.object = req;
    ev.req = req;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = aio_onDNSCompleted;
    SW_CHECK_RETURN(swAio_dispatch(&ev));
}

static int process_stream_onRead(swReactor *reactor, swEvent *event)
{
    process_stream *ps = (process_stream *) event->socket->object;
    char *buf = ps->buffer->str + ps->buffer->length;
    size_t len = ps->buffer->size - ps->buffer->length;

    int ret = read(event->fd, buf, len);
    if (ret > 0)
    {
        ps->buffer->length += ret;
        if (ps->buffer->length == ps->buffer->size && swString_extend(ps->buffer, ps->buffer->size * 2) == 0)
        {
            return SW_OK;
        }
    }
    else if (ret < 0)
    {
        swSysError("read() failed.");
        return SW_OK;
    }

    zval *retval = NULL;
    zval args[2];

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    if (ps->buffer->length == 0)
    {
        ZVAL_EMPTY_STRING(zdata);
    }
    else
    {
        ZVAL_STRINGL(zdata, ps->buffer->str, ps->buffer->length);
    }

    SwooleG.main_reactor->del(SwooleG.main_reactor, ps->fd);

    swString_free(ps->buffer);
    args[0] = *zdata;

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

    args[1] = *zstatus;

    zval *zcallback = ps->callback;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async: onAsyncComplete handler error");
    }
    sw_zval_free(zcallback);

    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zdata);
    zval_ptr_dtor(zstatus);
    close(ps->fd);
    efree(ps);

    return SW_OK;
}

PHP_METHOD(swoole_async, exec)
{
    char *command;
    size_t command_len;
    zval *callback;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &command, &command_len, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_READ, process_stream_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_PROCESS_STREAM | SW_EVENT_ERROR, process_stream_onRead);
    }

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, 0);
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

    process_stream *ps = ( process_stream *) emalloc(sizeof(process_stream));
    ps->callback = sw_zval_dup(callback);
    Z_TRY_ADDREF_P(ps->callback);

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
PHP_FUNCTION(swoole_async_dns_lookup_coro)
{
    zval *domain;
    double timeout = SW_CLIENT_CONNECT_TIMEOUT;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &domain, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    coro_check();
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

    //find cache
    std::string key(Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    dns_cache *cache;

    if (request_cache_map.find(key) != request_cache_map.end())
    {
        cache = request_cache_map[key];
        if (cache->update_time > swTimer_get_absolute_msec())
        {
            RETURN_STRING(cache->address);
        }
    }

    dns_request *req = (dns_request *) emalloc(sizeof(dns_request));
    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    req->useless = 0;

    php_context *context = (php_context *) emalloc(sizeof(php_context));
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->coro_params.value.ptr = (void *) req;
    req->context = context;

    php_swoole_check_reactor();
    int ret = swDNSResolver_request(Z_STRVAL_P(domain), coro_onDNSCompleted, (void *) req);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }
    //add timeout
    req->timer = swTimer_add(&SwooleG.timer, (int) (timeout * 1000), 0, context, dns_timeout_coro);
    if (req->timer)
    {
        context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
    }
    sw_coro_save(return_value, context);
    sw_coro_yield();
}
#endif
