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
#include "php_streams.h"
#include "php_network.h"

#include "async.h"

#define PHP_SWOOLE_AIO_MAXEVENTS       128

typedef struct {
	zval *callback;
	zval *filename;
	int fd;
	off_t offset;
	uint16_t type;
	uint8_t once;
	char *file_content;
	uint32_t content_length;
} swoole_async_file_request;

typedef struct {
	zval *callback;
	zval *domain;
} swoole_async_dns_request;

static void php_swoole_check_aio();
static void php_swoole_aio_onComplete(swAio_event *event);
static char php_swoole_aio_init = 0;
static swHashMap php_swoole_open_files = NULL;

static void php_swoole_check_aio()
{
	if (php_swoole_aio_init == 0)
	{
		php_swoole_check_reactor();
		swoole_aio_init(SwooleG.main_reactor, PHP_SWOOLE_AIO_MAXEVENTS);
		swoole_aio_set_callback(php_swoole_aio_onComplete);
		php_swoole_try_run_reactor();
		php_swoole_aio_init = 1;
	}
}

static void php_swoole_aio_onComplete(swAio_event *event)
{
	int isEOF = SW_FALSE;
	int64_t ret;

	zval *retval = NULL, *zcallback = NULL, *zwriten = NULL;
	zval *zcontent = NULL;
	zval **args[2];
	swoole_async_file_request *file_req = NULL;
	swoole_async_dns_request *dns_req = NULL;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (event->type == SW_AIO_DNS_LOOKUP)
	{
		dns_req = (swoole_async_dns_request *) event->req;
		if (dns_req->callback == NULL)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete callback not found[2]");
			return;
		}
		zcallback = dns_req->callback;
	}
	else
	{
		if (zend_hash_find(&php_sw_aio_callback, (char *)&(event->fd), sizeof(event->fd), (void**) &file_req) != SUCCESS)
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
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: ret_length[%d] < req->length[%d].", (int) ret, file_req->content_length);
		}
		file_req->offset += event->ret;
	}

	if (event->type == SW_AIO_READ)
	{
		MAKE_STD_ZVAL(zcontent);
		args[0] = &file_req->filename;
		args[1] = &zcontent;
		ZVAL_STRINGL(zcontent, event->buf, ret, 0);
	}
	else if(event->type == SW_AIO_WRITE)
	{
		MAKE_STD_ZVAL(zwriten);
		args[0] = &file_req->filename;
		args[1] = &zwriten;
		ZVAL_LONG(zwriten, ret);
	}
	else if(event->type == SW_AIO_DNS_LOOKUP)
	{
		MAKE_STD_ZVAL(zcontent);
		args[0] = &dns_req->domain;
		if (ret < 0)
		{
			ZVAL_STRING(zcontent, "", 0);
		}
		else
		{
			ZVAL_STRING(zcontent, event->buf, 0);
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
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: onAsyncComplete handler error");
			return;
		}
	}

	//readfile/writefile
	if (file_req != NULL)
	{
		//只操作一次,完成后释放缓存区并关闭文件
		if (file_req->once == 1)
		{
			close_file:
			zval_ptr_dtor(&file_req->callback);
			zval_ptr_dtor(&file_req->filename);
#ifdef SW_AIO_LINUX_NATIVE
			free(event->buf);
#else
			efree(event->buf);
#endif
			close(event->fd);
			//remove from hashtable
			zend_hash_del(&php_sw_aio_callback, (char *)&(event->fd), sizeof(event->fd));
		}
		else if(file_req->type == SW_AIO_WRITE)
		{
			if (retval != NULL && !Z_BVAL_P(retval))
			{
				swHashMap_del(&php_swoole_open_files, Z_STRVAL_P(file_req->filename), Z_STRLEN_P(file_req->filename));
			}
		}
		else
		{
			if (!Z_BVAL_P(retval) || isEOF)
			{
				goto close_file;
			}
			else if (swoole_aio_read(event->fd, event->buf, event->nbytes, file_req->offset) < 0)
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error),
						event->error);
			}
		}
	}
	else if(dns_req != NULL)
	{
		zval_ptr_dtor(&dns_req->callback);
		zval_ptr_dtor(&dns_req->domain);

		efree(dns_req);
		efree(event->buf);
	}
	if (zcontent != NULL)
	{
		efree(zcontent);
	}
	if (zwriten != NULL)
	{
		zval_ptr_dtor(&zwriten);
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

PHP_FUNCTION(swoole_async_read)
{
	zval *cb;
	zval *filename;
	long trunk_len = 8192;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &filename, &cb, &trunk_len) == FAILURE)
	{
		return;
	}
	convert_to_string(filename);

#ifdef HAVE_LINUX_NATIVE_AIO
	int open_flag =  O_RDONLY | O_DIRECT;
#else
	int open_flag = O_RDONLY;
#endif
	int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
	if (fd < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile: open file[%s] failed. Error: %s[%d]", Z_STRVAL_P(filename), strerror(errno), errno);
		RETURN_FALSE;
	}

	void *fcnt;
#ifdef HAVE_LINUX_NATIVE_AIO
	int buf_len = trunk_len + (sysconf(_SC_PAGESIZE) - (trunk_len % sysconf(_SC_PAGESIZE)));
	if (posix_memalign((void **)&fcnt, sysconf(_SC_PAGESIZE), buf_len))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
#else
	fcnt = emalloc(trunk_len);
	if (fcnt == NULL)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "malloc failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
#endif

	//printf("buf_len=%d|addr=%p\n", buf_len, fcnt);
	//printf("pagesize=%d|st_size=%d\n", sysconf(_SC_PAGESIZE), buf_len);

	swoole_async_file_request req;
	req.fd = fd;
	req.filename = filename;
	req.callback = cb;
	req.file_content = fcnt;
	req.once = 0;
	req.type = SW_AIO_READ;
	req.content_length = trunk_len;
	req.offset = 0;

	Z_ADDREF_PP(&cb);
	Z_ADDREF_PP(&filename);

	if (zend_hash_update(&php_sw_aio_callback, (char * )&fd, sizeof(fd), &req, sizeof(swoole_async_file_request),
			NULL) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile add to hashtable[1] failed");
		RETURN_FALSE;
	}

	php_swoole_check_aio();
	SW_CHECK_RETURN(swoole_aio_read(fd, fcnt, trunk_len, 0));
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_write)
{
	zval *cb = NULL;
	zval *filename;

	char *fcnt;
	int fcnt_len = 0;
	int fd;
	off_t offset;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zsl|z", &filename, &fcnt, &fcnt_len, &offset, &cb) == FAILURE)
	{
		return;
	}
	convert_to_string(filename);

	char *wt_cnt;
#ifdef SW_AIO_LINUX_NATIVE
	if (posix_memalign((void **)&wt_cnt, sysconf(_SC_PAGESIZE), fcnt_len))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
#else
	wt_cnt = fcnt;
	wt_cnt = emalloc(fcnt_len);
#endif

	swoole_async_file_request *req = swHashMap_find(&php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename));

	if (req == NULL)
	{
#ifdef HAVE_LINUX_NATIVE_AIO
		int open_flag = O_WRONLY | O_DIRECT | O_CREAT;
#else
		int open_flag = O_WRONLY | O_CREAT;
#endif
		fd = open(Z_STRVAL_P(filename), open_flag, 0644);
		if (fd < 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_write: open file failed. Error: %s[%d]", strerror(errno), errno);
			RETURN_FALSE;
		}

		swoole_async_file_request new_req;
		new_req.fd = fd;
		new_req.filename = filename;
		new_req.callback = cb;
		new_req.file_content = wt_cnt;
		new_req.once = 0;
		new_req.type = SW_AIO_WRITE;
		new_req.content_length = fcnt_len;
		new_req.offset = 0;

		if (cb != NULL)
		{
			Z_ADDREF_PP(&cb);
		}
		Z_ADDREF_PP(&filename);

		if (zend_hash_update(&php_sw_aio_callback, (char *)&fd, sizeof(fd), (void **) &new_req, sizeof(new_req), (void **) &req) == FAILURE)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_write: add to hashtable[1] failed");
			RETURN_FALSE;
		}
		swHashMap_add(&php_swoole_open_files, Z_STRVAL_P(filename), Z_STRLEN_P(filename), req);
	}
	else
	{
		fd = req->fd;
	}

	//swTrace("buf_len=%d|addr=%p", buf_len, fcnt);
	//swTrace("pagesize=%d|st_size=%d", sysconf(_SC_PAGESIZE), buf_len);

	memcpy(wt_cnt, fcnt, fcnt_len);

	php_swoole_check_aio();
	SW_CHECK_RETURN(swoole_aio_write(fd, wt_cnt, fcnt_len, offset));
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_readfile)
{
	zval *cb;
	zval *filename;

#ifdef HAVE_LINUX_NATIVE_AIO
	int open_flag =  O_RDONLY | O_DIRECT;
#else
	int open_flag = O_RDONLY;
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &filename, &cb) == FAILURE)
	{
		return;
	}
	convert_to_string(filename);

	int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
	if (fd < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile: open file[%s] failed. Error: %s[%d]", Z_STRVAL_P(filename), strerror(errno), errno);
		RETURN_FALSE;
	}
	struct stat file_stat;
	if (fstat(fd, &file_stat) < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile: fstat failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	if (file_stat.st_size <= 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile: file is empty.");
		RETURN_FALSE;
	}
	if (file_stat.st_size > SW_AIO_MAX_FILESIZE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
				"swoole_async_readfile: file_size[size=%ld|max_size=%d] is too big. Please use swoole_async_read.",
				(long int) file_stat.st_size, SW_AIO_MAX_FILESIZE);
		RETURN_FALSE;
	}

	void *fcnt;
#ifdef HAVE_LINUX_NATIVE_AIO
	int buf_len = file_stat.st_size + (sysconf(_SC_PAGESIZE) - (file_stat.st_size % sysconf(_SC_PAGESIZE)));
	if (posix_memalign((void **)&fcnt, sysconf(_SC_PAGESIZE), buf_len))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "posix_memalign failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
#else
	int buf_len = file_stat.st_size;
	fcnt = emalloc(buf_len);
	if (fcnt == NULL)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "malloc failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
#endif

	//printf("buf_len=%d|addr=%p\n", buf_len, fcnt);
	//printf("pagesize=%d|st_size=%d\n", sysconf(_SC_PAGESIZE), buf_len);

	swoole_async_file_request req;
	req.fd = fd;
	req.filename = filename;
	req.callback = cb;
	req.file_content = fcnt;
	req.once = 1;
	req.type = SW_AIO_READ;
	req.content_length = file_stat.st_size;
	req.offset = 0;

	Z_ADDREF_PP(&cb);
	Z_ADDREF_PP(&filename);

	if(zend_hash_update(&php_sw_aio_callback, (char *)&fd, sizeof(fd), &req, sizeof(swoole_async_file_request), NULL) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_readfile add to hashtable failed");
		RETURN_FALSE;
	}

	php_swoole_check_aio();
	SW_CHECK_RETURN(swoole_aio_read(fd, fcnt, buf_len, 0));
}

PHP_FUNCTION(swoole_async_writefile)
{
	zval *cb = NULL;
	zval *filename;
	char *fcnt;
	int fcnt_len;

#ifdef HAVE_LINUX_NATIVE_AIO
	int open_flag =  O_CREAT | O_WRONLY | O_DIRECT;
#else
	int open_flag = O_CREAT | O_WRONLY;
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|z", &filename, &fcnt, &fcnt_len, &cb) == FAILURE)
	{
		return;
	}
	if (fcnt_len <= 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_writefile: file is empty.");
		RETURN_FALSE;
	}
	if (fcnt_len > SW_AIO_MAX_FILESIZE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
				"swoole_async_writefile: file_size[size=%d|max_size=%d] is too big. Please use swoole_async_read.",
				fcnt_len, SW_AIO_MAX_FILESIZE);
		RETURN_FALSE;
	}
	convert_to_string(filename);
	int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
	if (fd < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_writefile: open file failed. Error: %s[%d]", strerror(errno), errno);
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

	memcpy(wt_cnt, fcnt, fcnt_len);

	swoole_async_file_request req;
	req.fd = fd;
	req.filename = filename;
	req.callback = cb;
	req.type = SW_AIO_WRITE;
	req.file_content = wt_cnt;
	req.once = 1;
	req.content_length = fcnt_len;
	req.offset = 0;
	Z_ADDREF_PP(&filename);

	if (req.callback != NULL)
	{
		Z_ADDREF_PP(&req.callback);
	}

	if (zend_hash_update(&php_sw_aio_callback, (char *)&fd, sizeof(fd), &req, sizeof(swoole_async_file_request), NULL) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_writefile add to hashtable failed");
		RETURN_FALSE;
	}

	memcpy(wt_cnt, fcnt, fcnt_len);
	php_swoole_check_aio();
	SW_CHECK_RETURN(swoole_aio_write(fd, wt_cnt, fcnt_len, 0));
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
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_async_dns_lookup: domain name empty.");
		RETURN_FALSE;
	}

	swoole_async_dns_request *req = emalloc(sizeof(swoole_async_dns_request));
	req->callback = cb;
	req->domain = domain;

	Z_ADDREF_PP(&req->callback);
	Z_ADDREF_PP(&req->domain);

	void *buf = emalloc(SW_IP_MAX_LENGTH);
	memcpy(buf, Z_STRVAL_P(domain), Z_STRLEN_P(domain));
	php_swoole_check_aio();
	SW_CHECK_RETURN(swoole_aio_dns_lookup(req, buf, SW_IP_MAX_LENGTH));
}
