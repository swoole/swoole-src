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
    char *file_content;
    uint32_t content_length;
} file_request;

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

static swHashMap *php_swoole_open_files;
static swHashMap *php_swoole_aio_request;

void swoole_async_init(int module_number TSRMLS_DC)
{
    bzero(&SwooleAIO, sizeof(SwooleAIO));

    REGISTER_LONG_CONSTANT("SWOOLE_AIO_BASE", SW_AIO_BASE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_AIO_GCC", SW_AIO_GCC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_AIO_LINUX", SW_AIO_LINUX, CONST_CS | CONST_PERSISTENT);

    php_swoole_open_files = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (php_swoole_open_files == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "create hashmap[1] failed.");
    }
    php_swoole_aio_request = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (php_swoole_aio_request == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "create hashmap[2] failed.");
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
#endif

    if (event->type == SW_AIO_DNS_LOOKUP)
    {
        dns_req = (dns_request *) event->req;
        if (dns_req->callback == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete callback not found[0]");
            return;
        }
        zcallback = dns_req->callback;
    }
    else
    {
        file_req = swHashMap_find_int(php_swoole_aio_request, event->fd);
        if (!file_req)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete callback not found[1]");
            return;
        }
        if (file_req->callback == NULL && file_req->type == SW_AIO_READ)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete callback not found[2]");
            return;
        }
        zcallback = file_req->callback;
    }

    ret = event->ret;
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: Aio Error: %s[%d]", strerror(event->error), event->error);
    }
    else if (file_req != NULL)
    {
        if (ret == 0)
        {
            bzero(event->buf, event->nbytes);
            isEOF = SW_TRUE;
        }
        else if (file_req->once == 1 && ret < file_req->content_length)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: ret_length[%d] < req->length[%d].", (int) ret,
                    file_req->content_length);
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
        SW_ZVAL_STRINGL(zcontent, event->buf, ret, 0);
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

        if (file_req->once != 1)
        {
            if (SwooleAIO.mode == SW_AIO_LINUX)
            {
                free(event->buf);
            }
            else
            {
                efree(event->buf);
            }
        }
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
            SW_ZVAL_STRING(zcontent, "", 0);
        }
        else
        {
            SW_ZVAL_STRING(zcontent, event->buf, 0);
        }
        args[1] = &zcontent;
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete unknow event type");
        return;
    }

    if (zcallback)
    {
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete handler error");
            return;
        }
    }

    //readfile/writefile
    if (file_req != NULL)
    {
        if (file_req->once == 1)
        {
            close_file:
            sw_zval_ptr_dtor(&file_req->callback);
            sw_zval_ptr_dtor(&file_req->filename);

            if (SwooleAIO.mode == SW_AIO_LINUX)
            {
                free(event->buf);
            }
            else
            {
                efree(event->buf);
            }
            close(event->fd);
            swHashMap_del_int(php_swoole_aio_request, event->fd);
            efree(file_req);
        }
        else if(file_req->type == SW_AIO_WRITE)
        {
            if (retval != NULL && !Z_BVAL_P(retval))
            {
                swHashMap_del(php_swoole_open_files, Z_STRVAL_P(file_req->filename), Z_STRLEN_P(file_req->filename));
                goto close_file;
            }
        }
        else
        {
            if (!Z_BVAL_P(retval) || isEOF)
            {
                goto close_file;
            }
            else if (SwooleAIO.read(event->fd, event->buf, event->nbytes, file_req->offset) < 0)
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error), event->error);
            }
        }
    }
    else if (dns_req != NULL)
    {
        sw_zval_ptr_dtor(&dns_req->callback);
        sw_zval_ptr_dtor(&dns_req->domain);

        efree(dns_req);
        efree(event->buf);
    }
    if (zcontent != NULL)
    {
        sw_zval_ptr_dtor(&zcontent);
    }
    if (zwriten != NULL)
    {
        sw_zval_ptr_dtor(&zwriten);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

PHP_FUNCTION(swoole_async_read)
{
    zval *cb;
    zval *filename;
    long buf_size = 8192;
    long offset = 0;
    int open_flag = O_RDONLY;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|ll", &filename, &cb, &buf_size, &offset) == FAILURE)
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
        RETURN_FALSE;
    }
    if (offset >= file_stat.st_size)
    {
        swoole_php_fatal_error(E_WARNING, "offset must be less than file_size[=%ld].", file_stat.st_size);
        RETURN_FALSE;
    }

    void *fcnt;
    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        int buf_len = buf_size + (sysconf(_SC_PAGESIZE) - (buf_size % sysconf(_SC_PAGESIZE)));
        if (posix_memalign((void **) &fcnt, sysconf(_SC_PAGESIZE), buf_len))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
    }
    else
    {
        fcnt = emalloc(buf_size);
        if (fcnt == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "malloc failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
    }

    file_request *req = emalloc(sizeof(file_request));
    req->fd = fd;
#if PHP_MAJOR_VERSION >= 7
    req->callback =  &req->_callback;
    req->filename = &req->_filename;
    memcpy(req->callback, cb, sizeof(zval));
    memcpy(req->filename, filename, sizeof(zval));
#else
    req->filename = filename;
    req->callback = cb;
#endif
    req->file_content = fcnt;
    req->once = 0;
    req->type = SW_AIO_READ;
    req->content_length = buf_size;
    req->offset = offset;

    sw_zval_add_ref(&cb);
    sw_zval_add_ref(&filename);

    swHashMap_add_int(php_swoole_aio_request, fd, req, NULL);
    php_swoole_check_aio();
    SW_CHECK_RETURN(SwooleAIO.read(fd, fcnt, buf_size, 0));
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_write)
{
    zval *cb = NULL;
    zval *filename;

    char *fcnt;
    zend_size_t fcnt_len = 0;
    int fd;
    off_t offset = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|lz", &filename, &fcnt, &fcnt_len, &offset, &cb) == FAILURE)
    {
        return;
    }
    convert_to_string(filename);

    char *wt_cnt;
    int open_flag = O_WRONLY | O_CREAT;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        if (posix_memalign((void **) &wt_cnt, sysconf(_SC_PAGESIZE), fcnt_len))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
        open_flag |= O_DIRECT;
    }
    else
    {
        wt_cnt = fcnt;
        wt_cnt = emalloc(fcnt_len);
    }

    file_request *req = swHashMap_find(php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename));

    if (req == NULL)
    {
        fd = open(Z_STRVAL_P(filename), open_flag, 0644);
        if (fd < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "open file failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }

        file_request *req = emalloc(sizeof(file_request));
        req->fd = fd;
#if PHP_MAJOR_VERSION >= 7
        req->callback = &req->_callback;
        req->filename = &req->_filename;
        memcpy(req->callback, cb, sizeof(zval));
        memcpy(req->filename, filename, sizeof(zval));
#else
        req->filename = filename;
        req->callback = cb;
#endif
        req->file_content = wt_cnt;
        req->once = 0;
        req->type = SW_AIO_WRITE;
        req->content_length = fcnt_len;

        if (offset < 0)
        {
            struct stat file_stat;
            if (fstat(fd, &file_stat) < 0)
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "fstat() failed. Error: %s[%d]", strerror(errno), errno);
                RETURN_FALSE;
            }
            offset = file_stat.st_size;
            req->offset = offset + fcnt_len;
        }
        else
        {
            req->offset = 0;
        }

        if (cb != NULL)
        {
            sw_zval_add_ref(&cb);
        }

        swHashMap_add_int(php_swoole_aio_request, fd, req, NULL);
        swHashMap_add(php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename), req, NULL);
    }
    else
    {
        if (offset < 0)
        {
            offset = req->offset;
            req->offset += fcnt_len;
        }
        fd = req->fd;
    }

    //swTrace("buf_len=%d|addr=%p", buf_len, fcnt);
    //swTrace("pagesize=%d|st_size=%d", sysconf(_SC_PAGESIZE), buf_len);

    memcpy(wt_cnt, fcnt, fcnt_len);

    php_swoole_check_aio();
    SW_CHECK_RETURN(SwooleAIO.write(fd, wt_cnt, fcnt_len, offset));
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_readfile)
{
    zval *cb;
    zval *filename;

    int open_flag = O_RDONLY;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        open_flag |=  O_DIRECT;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &filename, &cb) == FAILURE)
    {
        return;
    }
    convert_to_string(filename);

    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "open file[%s] failed. Error: %s[%d]", Z_STRVAL_P(filename), strerror(errno), errno);
        RETURN_FALSE;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "fstat failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "file is empty.");
        RETURN_FALSE;
    }
    if (file_stat.st_size > SW_AIO_MAX_FILESIZE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,    "file_size[size=%ld|max_size=%d] is too big. Please use swoole_async_read.",
                (long int) file_stat.st_size, SW_AIO_MAX_FILESIZE);
        RETURN_FALSE;
    }

    void *fcnt;
    int buf_len;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        buf_len = file_stat.st_size + (sysconf(_SC_PAGESIZE) - (file_stat.st_size % sysconf(_SC_PAGESIZE)));
        if (posix_memalign((void **) &fcnt, sysconf(_SC_PAGESIZE), buf_len))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
    }
    else
    {
        buf_len = file_stat.st_size;
        fcnt = emalloc(buf_len);
        if (fcnt == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "malloc failed. Error: %s[%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
    }

    file_request *req = emalloc(sizeof(file_request));
    req->fd = fd;
#if PHP_MAJOR_VERSION >= 7
    req->callback =  &req->_callback;
    req->filename = &req->_filename;
    memcpy(req->callback, cb, sizeof(zval));
    memcpy(req->filename, filename, sizeof(zval));
#else
    req->filename = filename;
    req->callback = cb;
#endif
    req->file_content = fcnt;
    req->once = 1;
    req->type = SW_AIO_READ;
    req->content_length = file_stat.st_size;
    req->offset = 0;

    sw_zval_add_ref(&cb);
    sw_zval_add_ref(&filename);

    swHashMap_add_int(php_swoole_aio_request, fd, req, NULL);

    php_swoole_check_aio();
    SW_CHECK_RETURN(SwooleAIO.read(fd, fcnt, buf_len, 0));
}

PHP_FUNCTION(swoole_async_writefile)
{
    zval *cb = NULL;
    zval *filename;
    char *fcnt;
    zend_size_t fcnt_len;

#ifdef HAVE_LINUX_NATIVE_AIO
    int open_flag = O_CREAT | O_WRONLY | O_DIRECT;
#else
    int open_flag = O_CREAT | O_WRONLY;
#endif

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "zs|z", &filename, &fcnt, &fcnt_len, &cb) == FAILURE)
    {
        return;
    }
    if (fcnt_len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "file is empty.");
        RETURN_FALSE;
    }
    if (fcnt_len > SW_AIO_MAX_FILESIZE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,    "file_size[size=%d|max_size=%d] is too big. Please use swoole_async_read.",
                fcnt_len, SW_AIO_MAX_FILESIZE);
        RETURN_FALSE;
    }
    convert_to_string(filename);
    int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
    if (fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "open file failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    char *wt_cnt;
#ifdef SW_AIO_LINUX_NATIVE
    fcnt_len = fcnt_len + (sysconf(_SC_PAGESIZE) - (fcnt_len % sysconf(_SC_PAGESIZE)));
    if (posix_memalign((void **)&wt_cnt, sysconf(_SC_PAGESIZE), fcnt_len))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
#else
    wt_cnt = emalloc(fcnt_len);
#endif

    file_request *req = emalloc(sizeof(file_request));

    req->fd = fd;
#if PHP_MAJOR_VERSION >= 7
    req->callback = &req->_callback;
    req->filename = &req->_filename;
    memcpy(req->callback, cb, sizeof(zval));
    memcpy(req->filename, filename, sizeof(zval));
#else
    req->filename = filename;
    req->callback = cb;
#endif
    req->type = SW_AIO_WRITE;
    req->file_content = wt_cnt;
    req->once = 1;
    req->content_length = fcnt_len;
    req->offset = 0;

    sw_zval_add_ref(&filename);
    if (req->callback != NULL)
    {
        sw_zval_add_ref(&req->callback);
    }

    swHashMap_add_int(php_swoole_aio_request, fd, req, NULL);
    memcpy(wt_cnt, fcnt, fcnt_len);

    php_swoole_check_aio();
    SW_CHECK_RETURN(SwooleAIO.write(fd, wt_cnt, fcnt_len, 0));
}

PHP_FUNCTION(swoole_async_set)
{
    zval *zset;
    HashTable *vht;
    zval **v;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &zset) == FAILURE)
    {
        return;
    }

    vht = Z_ARRVAL_P(zset);

    if (sw_zend_hash_find(vht, ZEND_STRS("aio_mode"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        SwooleAIO.mode = (uint8_t) Z_LVAL_PP(v);
    }

    if (sw_zend_hash_find(vht, ZEND_STRS("thread_num"), (void **)&v) == SUCCESS)
    {
        convert_to_long(*v);
        SwooleAIO.thread_num = (uint8_t) Z_LVAL_PP(v);
    }
}

PHP_FUNCTION(swoole_async_dns_lookup)
{
    zval *domain;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &domain, &cb) == FAILURE)
    {
        return;
    }

    if (Z_STRLEN_P(domain) == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "domain name empty.");
        RETURN_FALSE;
    }

    dns_request *req = emalloc(sizeof(dns_request));

#if PHP_MAJOR_VERSION >= 7
    req->callback = &req->_callback;
    req->domain = &req->_domain;
    memcpy(req->callback, cb, sizeof(zval));
    memcpy(req->domain, domain, sizeof(zval));
#else
    req->callback = cb;
    req->domain = domain;
#endif

    sw_zval_add_ref(&req->callback);
    sw_zval_add_ref(&req->domain);

    int buf_size;
    if (Z_STRLEN_P(domain) < SW_IP_MAX_LENGTH)
    {
        buf_size = SW_IP_MAX_LENGTH + 1;
    }
    else
    {
        buf_size = Z_STRLEN_P(domain) + 1;
    }

#ifdef SW_DNS_LOOKUP_USE_THREAD
    void *buf = emalloc(buf_size);
    bzero(buf, buf_size);
    memcpy(buf, Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    php_swoole_check_aio();
    SW_CHECK_RETURN(swAio_dns_lookup(req, buf, buf_size));
#else

    swDNS_request *request = emalloc(sizeof(swDNS_request));
    request->callback = php_swoole_aio_onDNSResponse;
    request->object = req;
    request->domain = Z_STRVAL_P(domain);

    php_swoole_check_reactor();
    swDNSResolver_request(request);
    php_swoole_try_run_reactor();
#endif
}

