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
} dns_request;

static void php_swoole_check_aio();
static void php_swoole_aio_onComplete(swAio_event *event);
static void php_swoole_dns_callback(char *domain, swDNSResolver_result *result, void *data);
static void php_swoole_file_request_free(void *data);

static swHashMap *php_swoole_open_files;
static swHashMap *php_swoole_aio_request;

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
    void *memory;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        int buf_len = __size + (sysconf(_SC_PAGESIZE) - (__size % sysconf(_SC_PAGESIZE)));
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

static void php_swoole_check_aio()
{
    if (SwooleAIO.init == 0)
    {
        php_swoole_check_reactor();
        swAio_init();
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

    sw_zval_ptr_dtor(&req->callback);
    sw_zval_ptr_dtor(&req->domain);
    efree(req);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zaddress);
}

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

    if (event->type == SW_AIO_DNS_LOOKUP)
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
        else if (file_req->once == 1 && ret < file_req->length)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async: ret_length[%d] < req->length[%d].", (int ) ret, file_req->length);
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
        memset(event->buf + ret, 0, 1);
        SW_ZVAL_STRINGL(zcontent, event->buf, ret, 1);
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
    else if(event->type == SW_AIO_DNS_LOOKUP)
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
            //continue to read
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
    long buf_size = 8192;
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
        if (SwooleAIO.mode == SW_AIO_LINUX)
        {
            open_flag |= O_DIRECT;
            if (offset < 0)
            {
                swoole_php_fatal_error(E_WARNING, "cannot use FILE_APPEND with linux native aio.");
                RETURN_FALSE;
            }
        }
        else if (offset < 0)
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

    req->content = swoole_aio_malloc(file_stat.st_size + 1);
    req->once = 1;
    req->type = SW_AIO_READ;
    req->length = file_stat.st_size;
    req->offset = 0;

    php_swoole_check_aio();

    int ret = SwooleAIO.read(fd, req->content, file_stat.st_size, 0);
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
    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        open_flag |= O_DIRECT;
        if (flags & PHP_FILE_APPEND)
        {
            swoole_php_fatal_error(E_WARNING, "cannot use FILE_APPEND with linux native aio.");
            RETURN_FALSE;
        }
    }
    else if (flags & PHP_FILE_APPEND)
    {
        open_flag |= O_APPEND;
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

    char *wt_cnt = swoole_aio_malloc(fcnt_len);

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
    php_swoole_check_aio();

    int ret = SwooleAIO.write(fd, wt_cnt, fcnt_len, 0);
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
        SwooleG.use_signalfd = Z_BVAL_P(v);
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
        SwooleG.dns_server_v4 = strndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
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
