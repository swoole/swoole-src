/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "php_swoole_cxx.h"

using namespace swoole;

zend_class_entry *swoole_event_ce;
static zend_object_handlers swoole_event_handlers;

typedef struct
{
    zval zsocket;
    zend_fcall_info_cache fci_cache_read;
    zend_fcall_info_cache fci_cache_write;
} php_event_object;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static void php_swoole_event_onDefer(void *data);
static void php_swoole_event_onEndCallback(void *data);

static PHP_FUNCTION(swoole_event_add);
static PHP_FUNCTION(swoole_event_set);
static PHP_FUNCTION(swoole_event_del);
static PHP_FUNCTION(swoole_event_write);
static PHP_FUNCTION(swoole_event_wait);
static PHP_FUNCTION(swoole_event_rshutdown);
static PHP_FUNCTION(swoole_event_exit);
static PHP_FUNCTION(swoole_event_defer);
static PHP_FUNCTION(swoole_event_cycle);
static PHP_FUNCTION(swoole_event_dispatch);
static PHP_FUNCTION(swoole_event_isset);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_add, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_CALLABLE_INFO(0, read_callback, 1)
    ZEND_ARG_CALLABLE_INFO(0, write_callback, 1)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_set, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_CALLABLE_INFO(0, read_callback, 1)
    ZEND_ARG_CALLABLE_INFO(0, write_callback, 1)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_write, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_defer, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_cycle, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 1)
    ZEND_ARG_INFO(0, before)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_del, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_isset, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_event_methods[] =
{
    ZEND_FENTRY(add, ZEND_FN(swoole_event_add), arginfo_swoole_event_add, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(del, ZEND_FN(swoole_event_del), arginfo_swoole_event_del, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(set, ZEND_FN(swoole_event_set), arginfo_swoole_event_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(isset, ZEND_FN(swoole_event_isset), arginfo_swoole_event_isset, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dispatch, ZEND_FN(swoole_event_dispatch), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer, ZEND_FN(swoole_event_defer), arginfo_swoole_event_defer, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(cycle, ZEND_FN(swoole_event_cycle), arginfo_swoole_event_cycle, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(write, ZEND_FN(swoole_event_write), arginfo_swoole_event_write, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(wait, ZEND_FN(swoole_event_wait), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(rshutdown, ZEND_FN(swoole_event_rshutdown), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exit, ZEND_FN(swoole_event_exit), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void php_swoole_event_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_event, "Swoole\\Event", "swoole_event", NULL, swoole_event_methods);
    SW_SET_CLASS_CREATE(swoole_event, sw_zend_create_object_deny);

    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "add", CG(function_table), "swoole_event_add");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "del", CG(function_table), "swoole_event_del");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "set", CG(function_table), "swoole_event_set");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "isset", CG(function_table), "swoole_event_isset");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "dispatch", CG(function_table), "swoole_event_dispatch");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "defer", CG(function_table), "swoole_event_defer");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "cycle", CG(function_table), "swoole_event_cycle");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "write", CG(function_table), "swoole_event_write");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "wait", CG(function_table), "swoole_event_wait");
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table, "exit", CG(function_table), "swoole_event_exit");
}

static void php_event_object_free(void* data)
{
    php_event_object *peo = (php_event_object*) data;
    if (peo->fci_cache_read.function_handler)
    {
        sw_zend_fci_cache_discard(&peo->fci_cache_read);
    }
    if (peo->fci_cache_write.function_handler)
    {
        sw_zend_fci_cache_discard(&peo->fci_cache_write);
    }
    zval_ptr_dtor((&peo->zsocket));
    efree(peo);
}

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    php_event_object *peo = (php_event_object *) event->socket->object;

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, &peo->fci_cache_read, 1, &peo->zsocket, NULL) != SUCCESS))
    {
        php_swoole_fatal_error(E_WARNING, "%s: onRead callback handler error, fd [%d] will be removed from reactor", ZSTR_VAL(swoole_event_ce->name), swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = NULL;
        SwooleG.main_reactor->defer(SwooleG.main_reactor, php_event_object_free, peo);
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }

    return SW_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    php_event_object *peo = (php_event_object *) event->socket->object;

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, &peo->fci_cache_write, 1, &peo->zsocket, NULL) != SUCCESS))
    {
        php_swoole_fatal_error(E_WARNING, "%s: onWrite callback handler error, fd [%d] will be removed from reactor", ZSTR_VAL(swoole_event_ce->name), swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = NULL;
        SwooleG.main_reactor->defer(SwooleG.main_reactor, php_event_object_free, peo);
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }

    return SW_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    if (!(event->socket->events & SW_EVENT_ERROR))
    {
        if (event->socket->events & SW_EVENT_READ)
        {
            return swReactor_get_handler(reactor, SW_EVENT_READ, event->socket->fdtype)(reactor, event);
        }
        else
        {
            return swReactor_get_handler(reactor, SW_EVENT_WRITE, event->socket->fdtype)(reactor, event);
        }
    }

    int error;
    socklen_t len = sizeof(error);

    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        php_swoole_sys_error(E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed", event->fd);
    }

    if (error != 0)
    {
        php_swoole_fatal_error(E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    php_event_object_free(event->socket->object);
    event->socket->active = 0;

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    return SW_OK;
}

static void php_swoole_event_onDefer(void *data)
{
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) data;

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, fci_cache, 0, NULL, NULL) != SUCCESS))
    {
        php_swoole_error(E_WARNING, "%s::defer callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }

    sw_zend_fci_cache_discard(fci_cache);
    efree(fci_cache);
}

static int reactor_can_exit(swReactor *reactor)
{
    if (Coroutine::count() != 0)
    {
        php_swoole_fatal_error(E_WARNING, "There are also %zu coroutines that have not been released", Coroutine::count());
    }

    return 1;
}

static void php_swoole_event_onEndCallback(void *data)
{
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) data;

    if (UNEXPECTED(sw_zend_call_function_ex2(NULL, (zend_fcall_info_cache *) fci_cache, 0, NULL, NULL) != SUCCESS))
    {
        php_swoole_error(E_WARNING, "%s::defer callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }
}

int php_swoole_reactor_init()
{
    if (!SWOOLE_G(cli))
    {
        php_swoole_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode");
        return SW_ERR;
    }

    if (SwooleG.serv)
    {
        if (swIsTaskWorker() && !SwooleG.serv->task_enable_coroutine)
        {
            php_swoole_fatal_error(E_ERROR, "Unable to use async-io in task processes, please set `task_enable_coroutine` to true");
            return SW_ERR;
        }
        if (swIsManager())
        {
            php_swoole_fatal_error(E_ERROR, "Unable to use async-io in manager process");
            return SW_ERR;
        }
    }
    if (!SwooleG.main_reactor)
    {
        swTraceLog(SW_TRACE_PHP, "init reactor");

        swReactor *reactor = (swReactor *) sw_malloc(sizeof(swReactor));
        if (reactor == NULL)
        {
            php_swoole_fatal_error(E_ERROR, "malloc failed");
            return SW_ERR;
        }
        if (swReactor_create(reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            php_swoole_fatal_error(E_ERROR, "failed to create reactor");
            return SW_ERR;
        }

        reactor->is_empty = swReactor_empty;
        reactor->can_exit = reactor_can_exit;
        reactor->wait_exit = 1;

        SwooleG.main_reactor = reactor;
        php_swoole_register_shutdown_function("Swoole\\Event::rshutdown");
    }
    return SW_OK;
}

void php_swoole_event_wait()
{
    if (PG(last_error_message))
    {
        switch (PG(last_error_type))
        {
        case E_ERROR:
        case E_CORE_ERROR:
        case E_USER_ERROR:
        case E_COMPILE_ERROR:
            return;
        default:
            break;
        }
    }

    if (!SwooleG.main_reactor)
    {
        return;
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.main_reactor->check_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif
    if (!swReactor_empty(SwooleG.main_reactor))
    {
        // Don't disable object slot reuse while running shutdown functions:
        // https://github.com/php/php-src/commit/bd6eabd6591ae5a7c9ad75dfbe7cc575fa907eac
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        zend_bool in_shutdown = EG(flags) & EG_FLAGS_IN_SHUTDOWN;
        EG(flags) &= ~EG_FLAGS_IN_SHUTDOWN;
#endif
        int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
        if (ret < 0)
        {
            php_swoole_sys_error(E_ERROR, "reactor wait failed");
        }
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        if (in_shutdown)
        {
            EG(flags) |= EG_FLAGS_IN_SHUTDOWN;
        }
#endif
    }
    swReactor_destroy(SwooleG.main_reactor);
    sw_free(SwooleG.main_reactor);
    SwooleG.main_reactor = NULL;
}

void php_swoole_event_exit()
{
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->running = 0;
    }
}

int swoole_convert_to_fd(zval *zsocket)
{
    int fd = -1;

    switch (Z_TYPE_P(zsocket))
    {
    case IS_RESOURCE:
    {
        php_stream *stream;
        if ((php_stream_from_zval_no_verify(stream, zsocket)))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **) &fd, 1) == SUCCESS && fd >= 0)
            {
                return fd;
            }
        }
#ifdef SWOOLE_SOCKETS_SUPPORT
        else
        {
            php_socket *php_sock;
            if ((php_sock = (php_socket *) zend_fetch_resource_ex(zsocket, NULL, php_sockets_le_socket())))
            {
                fd = php_sock->bsd_socket;
                return fd;
            }
        }
#endif
        php_swoole_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
        return SW_ERR;
    }
    case IS_LONG:
    {
        fd = Z_LVAL_P(zsocket);
        if (fd < 0)
        {
            php_swoole_fatal_error(E_WARNING, "invalid file descriptor#%d passed", fd);
            return SW_ERR;
        }
        return fd;
    }
    case IS_OBJECT:
    {
        zval *zfd = NULL;
        if (instanceof_function(Z_OBJCE_P(zsocket), swoole_socket_coro_ce))
        {
            zfd = sw_zend_read_property(Z_OBJCE_P(zsocket), zsocket, ZEND_STRL("fd"), 0);
        }
        else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_client_ce))
        {
            zfd = sw_zend_read_property(Z_OBJCE_P(zsocket), zsocket, ZEND_STRL("sock"), 0);
        }
        else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_process_ce))
        {
            zfd = sw_zend_read_property(Z_OBJCE_P(zsocket), zsocket, ZEND_STRL("pipe"), 0);
        }
        if (zfd == NULL || Z_TYPE_P(zfd) != IS_LONG)
        {
            return SW_ERR;
        }
        return Z_LVAL_P(zfd);
    }
    default:
        php_swoole_fatal_error(E_WARNING, "invalid file descriptor passed");
        return SW_ERR;
    }
}

int swoole_convert_to_fd_ex(zval *zsocket, int *async)
{
    int fd;

    *async = 0;
    if (Z_TYPE_P(zsocket) == IS_RESOURCE)
    {
        php_stream *stream;
        if ((php_stream_from_zval_no_verify(stream, zsocket)))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **)&fd, 1) == SUCCESS && fd >= 0)
            {
                *async = (stream->wrapper && (stream->wrapper->wops == php_plain_files_wrapper.wops)) ? 0 : 1;
                return fd;
            }
        }
#ifdef SWOOLE_SOCKETS_SUPPORT
        else
        {
            php_socket *php_sock;
            if ((php_sock = (php_socket *) zend_fetch_resource_ex(zsocket, NULL, php_sockets_le_socket())))
            {
                fd = php_sock->bsd_socket;
                *async = 1;
                return fd;
            }
        }
#endif
    }
    php_swoole_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
    return SW_ERR;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket* swoole_convert_to_socket(int sock)
{
    php_socket *socket_object = (php_socket *) emalloc(sizeof *socket_object);
    bzero(socket_object, sizeof(php_socket));
    socket_object->bsd_socket = sock;
    socket_object->blocking = 1;

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(sock, (struct sockaddr*) &addr, &addr_len) == 0)
    {
        socket_object->type = addr.ss_family;
    }
    else
    {
        php_swoole_sys_error(E_WARNING, "unable to obtain socket family");
        _error:
        efree(socket_object);
        return NULL;
    }

    int t = fcntl(sock, F_GETFL);
    if (t == -1)
    {
        php_swoole_sys_error(E_WARNING, "unable to obtain blocking state");
        goto _error;
    }
    else
    {
        socket_object->blocking = !(t & O_NONBLOCK);
    }
    return socket_object;
}

void swoole_php_socket_free(zval *zsocket)
{
    php_socket *php_sock;
    php_sock = (php_socket *) zend_fetch_resource_ex(zsocket, NULL, php_sockets_le_socket());
    php_sock->bsd_socket = -1;
    sw_zval_free(zsocket);
}
#endif

static void check_reactor()
{
    php_swoole_check_reactor();

    if (!swReactor_isset_handler(SwooleG.main_reactor, SW_FD_USER))
    {
        swReactor_set_handler(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
        swReactor_set_handler(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
        swReactor_set_handler(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
    }
    if (!swReactor_isset_handler(SwooleG.main_reactor, SW_FD_WRITE))
    {
        swReactor_set_handler(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);
    }
}

static PHP_FUNCTION(swoole_event_add)
{
    zval *zfd;
    zend_fcall_info fci_read = empty_fcall_info;
    zend_fcall_info_cache fci_cache_read = empty_fcall_info_cache;
    zend_fcall_info fci_write = empty_fcall_info;
    zend_fcall_info_cache fci_cache_write = empty_fcall_info_cache;
    zend_long event_flag = 0;

    ZEND_PARSE_PARAMETERS_START(1, 4)
        Z_PARAM_ZVAL(zfd)
        Z_PARAM_OPTIONAL
        Z_PARAM_FUNC_EX(fci_read, fci_cache_read, 1, 0)
        Z_PARAM_FUNC_EX(fci_write, fci_cache_write, 1, 0)
        Z_PARAM_LONG(event_flag)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (fci_read.size == 0 && fci_write.size == 0)
    {
        php_swoole_fatal_error(E_WARNING, "both read and write callbacks are emoty");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        php_swoole_fatal_error(E_WARNING, "unknow fd type");
        RETURN_FALSE;
    }
    if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
    {
        php_swoole_fatal_error(E_WARNING, "invalid socket fd [%d]", socket_fd);
        RETURN_FALSE;
    }

    php_event_object *peo = (php_event_object *) ecalloc(1, sizeof(php_event_object));

    Z_TRY_ADDREF_P(zfd);
    peo->zsocket = *zfd;

    if (fci_read.size != 0)
    {
        sw_zend_fci_cache_persist(&fci_cache_read);
        peo->fci_cache_read = fci_cache_read;
    }
    if (fci_write.size != 0)
    {
        sw_zend_fci_cache_persist(&fci_cache_write);
        peo->fci_cache_write = fci_cache_write;
    }

    check_reactor();
    swSocket_set_nonblock(socket_fd); // must be nonblock

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_swoole_fatal_error(E_WARNING, "swoole_event_add failed");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    socket->object = peo;
    socket->active = 1;
    socket->nonblock = 1;

    RETURN_LONG(socket_fd);
}

static PHP_FUNCTION(swoole_event_write)
{
    zval *zfd;
    char *data;
    size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zs", &zfd, &data, &len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (len == 0)
    {
        php_swoole_fatal_error(E_WARNING, "data empty");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        php_swoole_fatal_error(E_WARNING, "unknow type");
        RETURN_FALSE;
    }

    check_reactor();
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, socket_fd, data, len) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_FUNCTION(swoole_event_set)
{
    if (!SwooleG.main_reactor)
    {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_set");
        RETURN_FALSE;
    }

    zval *zfd;
    zend_fcall_info fci_read = empty_fcall_info;
    zend_fcall_info_cache fci_cache_read = empty_fcall_info_cache;
    zend_fcall_info fci_write = empty_fcall_info;
    zend_fcall_info_cache fci_cache_write = empty_fcall_info_cache;
    zend_long event_flag = 0;

    ZEND_PARSE_PARAMETERS_START(1, 4)
        Z_PARAM_ZVAL(zfd)
        Z_PARAM_OPTIONAL
        Z_PARAM_FUNC_EX(fci_read, fci_cache_read, 1, 0)
        Z_PARAM_FUNC_EX(fci_write, fci_cache_write, 1, 0)
        Z_PARAM_LONG(event_flag)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        php_swoole_fatal_error(E_WARNING, "unknow type");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (!socket->active)
    {
        php_swoole_fatal_error(E_WARNING, "socket[%d] is not found in the reactor", socket_fd);
        RETURN_FALSE;
    }

    php_event_object *reactor_fd = (php_event_object *) socket->object;
    if (fci_read.size != 0)
    {
        if (reactor_fd->fci_cache_read.function_handler)
        {
            sw_zend_fci_cache_discard(&reactor_fd->fci_cache_read);
        }
        reactor_fd->fci_cache_read = fci_cache_read;
    }
    if (fci_write.size != 0)
    {
        if (reactor_fd->fci_cache_write.function_handler)
        {
            sw_zend_fci_cache_discard(&reactor_fd->fci_cache_write);
        }
        reactor_fd->fci_cache_write = fci_cache_write;
    }

    if ((event_flag & SW_EVENT_READ) && reactor_fd->fci_cache_read.function_handler == NULL)
    {
        php_swoole_fatal_error(E_WARNING, "%s: unable to find read callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if ((event_flag & SW_EVENT_WRITE) && reactor_fd->fci_cache_write.function_handler == NULL)
    {
        php_swoole_fatal_error(E_WARNING, "%s: unable to find write callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if (SwooleG.main_reactor->set(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_swoole_fatal_error(E_WARNING, "%s::set failed", ZSTR_VAL(swoole_event_ce->name));
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_del)
{
    zval *zfd;

    if (!SwooleG.main_reactor)
    {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_del");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        php_swoole_fatal_error(E_WARNING, "unknow type");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (socket->object)
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, php_event_object_free, socket->object);
        socket->object = NULL;
    }

    int ret = SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd);
    socket->active = 0;
    SW_CHECK_RETURN(ret);
}

static PHP_FUNCTION(swoole_event_defer)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) ecalloc(1, sizeof(zend_fcall_info_cache));

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, *fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(efree(fci_cache); RETURN_FALSE);

    php_swoole_check_reactor();

    sw_zend_fci_cache_persist(fci_cache);
    SwooleG.main_reactor->defer(SwooleG.main_reactor, php_swoole_event_onDefer, fci_cache);

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_cycle)
{
    if (!SwooleG.main_reactor)
    {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call %s", ZSTR_VAL(swoole_event_ce->name));
        RETURN_FALSE;
    }

    zend_fcall_info _fci = empty_fcall_info;
    zend_fcall_info_cache _fci_cache = empty_fcall_info_cache;
    zend_bool before = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_FUNC_EX(_fci, _fci_cache, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(before)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (_fci.size == 0)
    {
        if (SwooleG.main_reactor->idle_task.callback == NULL)
        {
            RETURN_FALSE;
        }
        else
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, sw_zend_fci_cache_free, SwooleG.main_reactor->idle_task.data);
            SwooleG.main_reactor->idle_task.callback = NULL;
            SwooleG.main_reactor->idle_task.data = NULL;
            RETURN_TRUE;
        }
    }

    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));

    *fci_cache = _fci_cache;
    sw_zend_fci_cache_persist(fci_cache);

    if (!before)
    {
        if (SwooleG.main_reactor->idle_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, sw_zend_fci_cache_free, SwooleG.main_reactor->idle_task.data);
        }

        SwooleG.main_reactor->idle_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->idle_task.data = fci_cache;
    }
    else
    {
        if (SwooleG.main_reactor->future_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, sw_zend_fci_cache_free, SwooleG.main_reactor->future_task.data);
        }

        SwooleG.main_reactor->future_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->future_task.data = fci_cache;
        //Registration onBegin callback function
        swReactor_activate_future_task(SwooleG.main_reactor);
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_exit)
{
    php_swoole_event_exit();
}

static PHP_FUNCTION(swoole_event_wait)
{
    if (!SwooleG.main_reactor)
    {
        return;
    }
    php_swoole_event_wait();
}

static PHP_FUNCTION(swoole_event_rshutdown)
{
    /* prevent the program from jumping out of the rshutdown */
    zend_try
    {
        PHP_FN(swoole_event_wait)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    }
    zend_end_try();
}

static PHP_FUNCTION(swoole_event_dispatch)
{
    if (!SwooleG.main_reactor)
    {
        RETURN_FALSE;
    }
    SwooleG.main_reactor->once = 1;

#ifdef HAVE_SIGNALFD
    if (SwooleG.main_reactor->check_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif

    int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
    if (ret < 0)
    {
        php_swoole_sys_error(E_ERROR, "reactor wait failed");
    }

    SwooleG.main_reactor->once = 0;
    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_isset)
{
    if (!SwooleG.main_reactor)
    {
        RETURN_FALSE;
    }

    zval *zfd;
    zend_long events = SW_EVENT_READ | SW_EVENT_WRITE;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|l", &zfd, &events) == FAILURE)
    {
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        php_swoole_fatal_error(E_WARNING, "unknow type");
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (_socket == NULL || _socket->removed)
    {
        RETURN_FALSE;
    }
    if (_socket->events & events)
    {
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

