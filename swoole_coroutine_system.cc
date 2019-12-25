#include "swoole_coroutine_system.h"

#include "ext/standard/file.h"
#include <sys/file.h>

#include "coroutine_c_api.h"
#include "async.h"

#include <string>

using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;

struct util_socket
{
    php_coro_context context;
    int fd;
    zend_string *buf;
    uint32_t nbytes;
    swTimer_node *timer;
};

static zend_class_entry *swoole_coroutine_system_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, get_error_stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_sleep, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fread, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fgets, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_fwrite, 0, 0, 2)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_gethostbyname, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_dnsLookup, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_getaddrinfo, 0, 0, 1)
    ZEND_ARG_INFO(0, hostname)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, socktype)
    ZEND_ARG_INFO(0, protocol)
    ZEND_ARG_INFO(0, service)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_readFile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_writeFile, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_system_statvfs, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()


static const zend_function_entry swoole_coroutine_system_methods[] =
{
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_system_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dnsLookup, ZEND_FN(swoole_async_dns_lookup_coro), arginfo_swoole_coroutine_system_dnsLookup, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, exec, arginfo_swoole_coroutine_system_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep, arginfo_swoole_coroutine_system_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fread, arginfo_swoole_coroutine_system_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fwrite, arginfo_swoole_coroutine_system_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, fgets, arginfo_swoole_coroutine_system_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo, arginfo_swoole_coroutine_system_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile, arginfo_swoole_coroutine_system_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile, arginfo_swoole_coroutine_system_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs, arginfo_swoole_coroutine_system_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void php_swoole_coroutine_system_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_system, "Swoole\\Coroutine\\System", NULL, "Co\\System", swoole_coroutine_system_methods, NULL);
    SW_SET_CLASS_CREATE(swoole_coroutine_system, sw_zend_create_object_deny);
}

PHP_METHOD(swoole_coroutine_system, sleep)
{
    double seconds;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_DOUBLE(seconds)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(seconds < SW_TIMER_MIN_SEC))
    {
        php_swoole_fatal_error(E_WARNING, "Timer must be greater than or equal to " ZEND_TOSTR(SW_TIMER_MIN_SEC));
        RETURN_FALSE;
    }
    System::sleep(seconds);
    RETURN_TRUE;
}

static void aio_onReadCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->error == 0)
    {
        // TODO: Optimization: reduce memory copy
        ZVAL_STRINGL(&result, (char* )event->buf, event->ret);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(&result);
    efree(event->buf);
    efree(context);
}

static void aio_onFgetsCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->ret != -1)
    {
        ZVAL_STRING(&result, (char* )event->buf);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    php_stream *stream;
    php_stream_from_zval_no_verify(stream, &context->coro_params);

    if (event->flags & SW_AIO_EOF)
    {
        stream->eof = 1;
    }

    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(&result);
    efree(context);
}

static void aio_onWriteCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->ret < 0)
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }
    else
    {
        ZVAL_LONG(&result, event->ret);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(event->buf);
    efree(context);
}

static int co_socket_onReadable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_coro_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    swoole_event_del(sock->fd);

    if (sock->timer)
    {
        swoole_timer_del(sock->timer);
        sock->timer = NULL;
    }

    int n = read(sock->fd, ZSTR_VAL(sock->buf), sock->nbytes);
    if (n < 0)
    {
        ZVAL_FALSE(&result);
        zend_string_free(sock->buf);
    }
    else if (n == 0)
    {
        ZVAL_EMPTY_STRING(&result);
        zend_string_free(sock->buf);
    }
    else
    {
        ZSTR_VAL(sock->buf)[n] = 0;
        ZSTR_LEN(sock->buf) = n;
        ZVAL_STR(&result, sock->buf);
    }
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    zval_ptr_dtor(&result);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(sock);
    return SW_OK;
}

static int co_socket_onWritable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_coro_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    swoole_event_del(sock->fd);

    if (sock->timer)
    {
        swoole_timer_del(sock->timer);
        sock->timer = NULL;
    }

    int n = write(sock->fd, context->private_data, sock->nbytes);
    if (n < 0)
    {
        SwooleG.error = errno;
        ZVAL_FALSE(&result);
    }
    else
    {
        ZVAL_LONG(&result, n);
    }
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(sock);
    return SW_OK;
}

static void co_socket_read(int fd, zend_long length, INTERNAL_FUNCTION_PARAMETERS)
{
    php_swoole_check_reactor();
    if (!swReactor_isset_handler(SwooleTG.reactor, PHP_SWOOLE_FD_SOCKET))
    {
        swReactor_set_handler(SwooleTG.reactor, PHP_SWOOLE_FD_CO_UTIL | SW_EVENT_READ, co_socket_onReadable);
        swReactor_set_handler(SwooleTG.reactor, PHP_SWOOLE_FD_CO_UTIL | SW_EVENT_WRITE, co_socket_onWritable);
    }

    if (swoole_event_add(fd, SW_EVENT_READ, PHP_SWOOLE_FD_CO_UTIL) < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }

    swSocket *_socket = swReactor_get(SwooleTG.reactor, fd);
    util_socket *sock = (util_socket *) emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    sock->fd = fd;
    sock->buf = zend_string_alloc(length + 1, 0);
    sock->nbytes = length <= 0 ? SW_BUFFER_SIZE_STD : length;

    PHPCoroutine::yield_m(return_value, &sock->context);
}

static void co_socket_write(int fd, char* str, size_t l_str, INTERNAL_FUNCTION_PARAMETERS)
{
    int ret = write(fd, str, l_str);
    if (ret < 0)
    {
        if (errno == EAGAIN)
        {
            goto _yield;
        }
        SwooleG.error = errno;
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }

    _yield:
    if (swoole_event_add(fd, SW_EVENT_WRITE, PHP_SWOOLE_FD_SOCKET) < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }

    swSocket *_socket = swReactor_get(SwooleTG.reactor, fd);
    util_socket *sock = (util_socket *) emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    php_coro_context *context = &sock->context;
    context->private_data = str;

    sock->nbytes = l_str;

    PHPCoroutine::yield_m(return_value, context);
}

PHP_METHOD(swoole_coroutine_system, fread)
{
    Coroutine::get_current_safe();

    zval *handle;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async)
    {
        co_socket_read(fd, length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    if (length <= 0)
    {
        struct stat file_stat;
        if (swoole_coroutine_fstat(fd, &file_stat) < 0)
        {
            SwooleG.error = errno;
            RETURN_FALSE;
        }
        off_t _seek = swoole_coroutine_lseek(fd, 0, SEEK_CUR);
        if (_seek < 0)
        {
            SwooleG.error = errno;
            RETURN_FALSE;
        }
        if (_seek >= file_stat.st_size)
        {
            length = SW_BUFFER_SIZE_STD;
        }
        else
        {
            length = file_stat.st_size - _seek;
        }
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = length;
    ev.buf = emalloc(ev.nbytes + 1);
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ((char *) ev.buf)[length] = 0;
    ev.flags = 0;
    ev.object = context;
    ev.handler = swAio_handler_fread;
    ev.callback = aio_onReadCompleted;
    ev.fd = fd;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }
    PHPCoroutine::yield_m(return_value, context);
}

PHP_METHOD(swoole_coroutine_system, fgets)
{
    Coroutine::get_current_safe();

    zval *handle;
    php_stream *stream;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(handle)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async == 1)
    {
        php_swoole_fatal_error(E_WARNING, "only support file resources");
        RETURN_FALSE;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    php_stream_from_res(stream, Z_RES_P(handle));

    FILE *file;
    if (stream->stdiocast)
    {
        file = stream->stdiocast;
    }
    else
    {
        if (php_stream_cast(stream, PHP_STREAM_AS_STDIO, (void**)&file, 1) != SUCCESS || file == NULL)
        {
            RETURN_FALSE;
        }
    }

    if (stream->readbuf == NULL)
    {
        stream->readbuflen = stream->chunk_size;
        stream->readbuf = (uchar *) emalloc(stream->chunk_size);
    }

    ev.nbytes = stream->readbuflen;
    ev.buf = stream->readbuf;
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ev.flags = 0;
    ev.object = context;
    ev.callback = aio_onFgetsCompleted;
    ev.handler = swAio_handler_fgets;
    ev.fd = fd;
    ev.req = (void *) file;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->coro_params = *handle;

    PHPCoroutine::yield_m(return_value, context);
}

PHP_METHOD(swoole_coroutine_system, fwrite)
{
    Coroutine::get_current_safe();

    zval *handle;
    char *str;
    size_t l_str;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_STRING(str, l_str)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async)
    {
        co_socket_write(fd, str, (length <= 0 || (size_t) length > l_str) ? l_str : length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    if (length <= 0 || (size_t) length > l_str)
    {
        length = l_str;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = length;
    ev.buf = estrndup(str, length);

    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ev.flags = 0;
    ev.object = context;
    ev.handler = swAio_handler_fwrite;
    ev.callback = aio_onWriteCompleted;
    ev.fd = fd;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }
    PHPCoroutine::yield_m(return_value, context);
}

PHP_METHOD(swoole_coroutine_system, readFile)
{
    char *filename;
    size_t l_filename;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swString *result = System::read_file(filename, flags & LOCK_EX);
    if (result == NULL)
    {
        RETURN_FALSE;
    }
    else
    {
        RETVAL_STRINGL(result->str, result->length);
        swString_free(result);
    }
}

PHP_METHOD(swoole_coroutine_system, writeFile)
{
    char *filename;
    size_t l_filename;
    char *data;
    size_t l_data;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int _flags = O_CREAT | O_WRONLY;
    if (flags & PHP_FILE_APPEND)
    {
        _flags |= O_APPEND;
    }
    else
    {
        _flags |= O_TRUNC;
    }

    ssize_t retval = System::write_file(filename, data, l_data, flags & LOCK_EX, _flags);
    if (retval < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
    }
}

PHP_FUNCTION(swoole_coroutine_gethostbyname)
{
    Coroutine::get_current_safe();

    char *domain_name;
    size_t l_domain_name;
    zend_long family = AF_INET;
    double timeout = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ld", &domain_name, &l_domain_name, &family, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_domain_name == 0)
    {
        php_swoole_fatal_error(E_WARNING, "domain name is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        php_swoole_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    string address = System::gethostbyname(string(domain_name, l_domain_name), family, timeout);
    if (address.empty())
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_STRINGL(address.c_str(), address.length());
    }
}

PHP_FUNCTION(swoole_clear_dns_cache)
{
    System::clear_dns_cache();
}

PHP_METHOD(swoole_coroutine_system, getaddrinfo)
{
    char *hostname;
    size_t l_hostname;
    zend_long family = AF_INET;
    zend_long socktype = SOCK_STREAM;
    zend_long protocol = IPPROTO_TCP;
    char *service = NULL;
    size_t l_service = 0;
    double timeout = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lllsd", &hostname, &l_hostname, &family, &socktype, &protocol,
            &service, &l_service, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_hostname == 0)
    {
        php_swoole_fatal_error(E_WARNING, "hostname is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        php_swoole_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    string str_service(service ? service : "");
    vector<string> result = System::getaddrinfo(hostname, family, socktype, protocol, str_service, timeout);

    if (result.empty())
    {
        RETURN_FALSE;
    }

    array_init(return_value);
    for (auto i = result.begin(); i != result.end(); i++)
    {
        add_next_index_stringl(return_value, i->c_str(), i->length());
    }
}

PHP_METHOD(swoole_coroutine_system, statvfs)
{
    char *path;
    size_t l_path;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, l_path)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    struct statvfs _stat;
    swoole_coroutine_statvfs(path, &_stat);

    array_init(return_value);
    add_assoc_long(return_value, "bsize", _stat.f_bsize);
    add_assoc_long(return_value, "frsize", _stat.f_frsize);
    add_assoc_long(return_value, "blocks", _stat.f_blocks);
    add_assoc_long(return_value, "bfree", _stat.f_bfree);
    add_assoc_long(return_value, "bavail", _stat.f_bavail);
    add_assoc_long(return_value, "files", _stat.f_files);
    add_assoc_long(return_value, "ffree", _stat.f_ffree);
    add_assoc_long(return_value, "favail", _stat.f_favail);
    add_assoc_long(return_value, "fsid", _stat.f_fsid);
    add_assoc_long(return_value, "flag", _stat.f_flag);
    add_assoc_long(return_value, "namemax", _stat.f_namemax);
}

PHP_METHOD(swoole_coroutine_system, exec)
{
    char *command;
    size_t command_len;
    zend_bool get_error_stream = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(command, command_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(get_error_stream)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_signal_isset_handler(SIGCHLD))
    {
        php_swoole_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_coroutine_exec");
        RETURN_FALSE;
    }

    Coroutine::get_current_safe();
    swoole_coroutine_signal_init();

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, get_error_stream);
    if (fd < 0)
    {
        php_swoole_error(E_WARNING, "Unable to execute '%s'", command);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(1024);
    if (buffer == NULL)
    {
        RETURN_FALSE;
    }

    swSocket_set_nonblock(fd);
    Socket socket(fd, SW_SOCK_UNIX_STREAM);
    while (1)
    {
        ssize_t retval = socket.read(buffer->str + buffer->length, buffer->size - buffer->length);
        if (retval > 0)
        {
            buffer->length += retval;
            if (buffer->length == buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    break;
                }
            }
        }
        else
        {
            break;
        }
    }
    socket.close();

    zval zdata;
    if (buffer->length == 0)
    {
        ZVAL_EMPTY_STRING(&zdata);
    }
    else
    {
        ZVAL_STRINGL(&zdata, buffer->str, buffer->length);
    }
    swString_free(buffer);

    int status;
    pid_t _pid = swoole_coroutine_waitpid(pid, &status, 0);
    if (_pid > 0)
    {
        array_init(return_value);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
        add_assoc_zval(return_value, "output", &zdata);
    }
    else
    {
        zval_ptr_dtor(&zdata);
        RETVAL_FALSE;
    }
}

