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

#include "php_swoole.h"

typedef struct
{
    struct
    {
        zval cb_read;
        zval cb_write;
        zval socket;
    } stack;
    zval *cb_read;
    zval *cb_write;
    zval *socket;
} php_reactor_fd;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static void php_swoole_event_onEndCallback(void *_cb);

static void free_event_callback(void* data)
{
    php_reactor_fd *ev_set = (php_reactor_fd*) data;
    if (ev_set->cb_read)
    {
        zval_ptr_dtor((ev_set->cb_read));
        ev_set->cb_read = NULL;
    }
    if (ev_set->cb_write)
    {
        zval_ptr_dtor((ev_set->cb_write));
        ev_set->cb_write = NULL;
    }
    if (ev_set->socket)
    {
        zval_ptr_dtor((ev_set->socket));
        ev_set->socket = NULL;
    }
    efree(ev_set);
}

static void free_callback(void* data)
{
    php_defer_callback *cb = (php_defer_callback *) data;
    zval_ptr_dtor(cb->callback);
    efree(cb);
}

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL;
    zval args[1];
    php_reactor_fd *fd = event->socket->object;

    args[0] = *fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onRead handler error.");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL;
    zval args[1];
    php_reactor_fd *fd = event->socket->object;


    if (!fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    args[0] = *fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onWrite handler error");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    int error;
    socklen_t len = sizeof(error);

    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
    }

    if (error != 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    efree(event->socket->object);
    event->socket->active = 0;

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    return SW_OK;
}

void php_swoole_event_onDefer(void *_cb)
{
    php_defer_callback *defer = _cb;
    zval _retval, *retval = &_retval;

    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: defer handler error");
        return;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(defer->callback);
    efree(defer);
}

static void php_swoole_event_onEndCallback(void *_cb)
{
    php_defer_callback *defer = _cb;
    zval *retval = NULL;

    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: cycle callback handler error.");
        return;
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

void php_swoole_reactor_init()
{
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode.");
        return;
    }

    if (SwooleG.serv)
    {
        if (swIsTaskWorker() && !SwooleG.serv->task_enable_coroutine)
        {
            swoole_php_fatal_error(E_ERROR, "Unable to use async-io in task processes, please set `task_enable_coroutine` to true.");
            return;
        }
        if (swIsManager())
        {
            swoole_php_fatal_error(E_ERROR, "Unable to use async-io in manager process.");
            return;
        }
    }

    if (SwooleG.main_reactor == NULL)
    {
        swTraceLog(SW_TRACE_PHP, "init reactor");

        SwooleG.main_reactor = (swReactor *) sw_malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "malloc failed.");
            return;
        }
        if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "failed to create reactor.");
            return;
        }

        SwooleG.main_reactor->can_exit = php_coroutine_reactor_can_exit;

        //client, swoole_event_exit will set swoole_running = 0
        SwooleWG.in_client = 1;
        SwooleWG.reactor_wait_onexit = 1;
        SwooleWG.reactor_ready = 0;
        //only client side
        php_swoole_register_shutdown_function_prepend("swoole_event_wait");
    }

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);

    SwooleWG.reactor_init = 1;
}

void php_swoole_event_wait()
{
    if (SwooleWG.in_client == 1 && SwooleWG.reactor_ready == 0 && SwooleG.running)
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
        SwooleWG.reactor_ready = 1;

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
            SW_DECLARE_EG_SCOPE(scope);
            SW_SAVE_EG_SCOPE(scope);
            int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
            if (ret < 0)
            {
                swoole_php_fatal_error(E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
            }
            SW_SET_EG_SCOPE(scope);
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
            if (in_shutdown)
            {
                EG(flags) |= EG_FLAGS_IN_SHUTDOWN;
            }
#endif
        }
        php_swoole_clear_all_timer();
        SwooleWG.reactor_exit = 1;
        SwooleG.running = 0;
        SwooleG.main_reactor->running = 0;
    }
}

void php_swoole_event_exit()
{
    if (SwooleWG.in_client == 1)
    {
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        SwooleG.running = 0;
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
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void *) &fd, 1) == SUCCESS && fd >= 0)
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
        swoole_php_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
        return SW_ERR;
    }
    case IS_LONG:
    {
        fd = Z_LVAL_P(zsocket);
        if (fd < 0)
        {
            swoole_php_fatal_error(E_WARNING, "invalid file descriptor#%d passed", fd);
            return SW_ERR;
        }
        return fd;
    }
    case IS_OBJECT:
    {
        zval *zfd = NULL;
        if (instanceof_function(Z_OBJCE_P(zsocket), swoole_socket_coro_ce_ptr))
        {
            zfd = sw_zend_read_property(Z_OBJCE_P(zsocket), zsocket, ZEND_STRL("fd"), 0);
        }
        else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_client_ce_ptr))
        {
            zfd = sw_zend_read_property(Z_OBJCE_P(zsocket), zsocket, ZEND_STRL("sock"), 0);
        }
        else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_process_ce_ptr))
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
        swoole_php_fatal_error(E_WARNING, "invalid file descriptor passed");
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
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&fd, 1) == SUCCESS && fd >= 0)
            {
                *async = stream->wrapper->wops == php_plain_files_wrapper.wops ? 0 : 1;
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
    swoole_php_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
    return SW_ERR;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket* swoole_convert_to_socket(int sock)
{
    php_socket *socket_object = emalloc(sizeof *socket_object);
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
        swoole_php_sys_error(E_WARNING, "unable to obtain socket family");
        error:
        efree(socket_object);
        return NULL;
    }

    int t = fcntl(sock, F_GETFL);
    if (t == -1)
    {
        swoole_php_sys_error(E_WARNING, "unable to obtain blocking state");
        goto error;
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

PHP_FUNCTION(swoole_event_add)
{
    zval *zfd;
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zend_long event_flag = 0;
    char *func_name = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        RETURN_FALSE;
    }

    if ((cb_read == NULL && cb_write == NULL) || (ZVAL_IS_NULL(cb_read) && ZVAL_IS_NULL(cb_write)))
    {
        swoole_php_fatal_error(E_WARNING, "no read or write event callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }
    if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
    {
        swoole_php_fatal_error(E_WARNING, "invalid socket fd [%d].", socket_fd);
        RETURN_FALSE;
    }

    php_reactor_fd *reactor_fd = emalloc(sizeof(php_reactor_fd));
    reactor_fd->socket = zfd;
    sw_copy_to_stack(reactor_fd->socket, reactor_fd->stack.socket);
    Z_TRY_ADDREF_P(reactor_fd->socket);

    if (cb_read!= NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name))
        {
            swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_read = cb_read;
        Z_TRY_ADDREF_P(cb_read);
        sw_copy_to_stack(reactor_fd->cb_read, reactor_fd->stack.cb_read);
    }
    else
    {
        reactor_fd->cb_read = NULL;
    }

    if (cb_write!= NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!sw_zend_is_callable(cb_write, 0, &func_name))
        {
            swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_write = cb_write;
        Z_TRY_ADDREF_P(cb_write);
        sw_copy_to_stack(reactor_fd->cb_write, reactor_fd->stack.cb_write);
    }
    else
    {
        reactor_fd->cb_write = NULL;
    }

    php_swoole_check_reactor();
    swSetNonBlock(socket_fd); //must be nonblock

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    socket->object = reactor_fd;
    socket->active = 1;
    socket->nonblock = 1;

    RETURN_LONG(socket_fd);
}

PHP_FUNCTION(swoole_event_write)
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
        swoole_php_fatal_error(E_WARNING, "data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, socket_fd, data, len) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_event_set)
{
    zval *zfd;
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zend_long event_flag = 0;
    char *func_name = NULL;

    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_set.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (!socket->active)
    {
        swoole_php_fatal_error(E_WARNING, "socket[%d] is not found in the reactor.", socket_fd);
        efree(func_name);
        RETURN_FALSE;
    }

    php_reactor_fd *ev_set = socket->object;
    if (cb_read != NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name))
        {
            swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_read)
            {
                zval_ptr_dtor(ev_set->cb_read);
            }
            ev_set->cb_read = cb_read;
            Z_TRY_ADDREF_P(cb_read);
            sw_copy_to_stack(ev_set->cb_read, ev_set->stack.cb_read);
            efree(func_name);
        }
    }

    if (cb_write != NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
        {
            swoole_php_fatal_error(E_WARNING, "invalid socket fd [%d].", socket_fd);
            RETURN_FALSE;
        }
        if (!sw_zend_is_callable(cb_write, 0, &func_name))
        {
            swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_write)
            {
                zval_ptr_dtor(ev_set->cb_write);
            }
            ev_set->cb_write = cb_write;
            Z_TRY_ADDREF_P(cb_write);
            sw_copy_to_stack(ev_set->cb_write, ev_set->stack.cb_write);
            efree(func_name);
        }
    }

    if ((event_flag & SW_EVENT_READ) && ev_set->cb_read == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && ev_set->cb_write == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: no write callback.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor->set(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_set failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_del)
{
    zval *zfd;

    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_del.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE)
    {
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        swoole_php_fatal_error(E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (socket->object)
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, free_event_callback, socket->object);
        socket->object = NULL;
    }

    int ret = SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd);
    socket->active = 0;
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_event_defer)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_swoole_check_reactor();

    php_defer_callback *defer = emalloc(sizeof(php_defer_callback));
    defer->callback = &defer->_callback;
    memcpy(defer->callback, callback, sizeof(zval));
    Z_TRY_ADDREF_P(callback);
    SwooleG.main_reactor->defer(SwooleG.main_reactor, php_swoole_event_onDefer, defer);
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_cycle)
{
    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_cycle.");
        RETURN_FALSE;
    }

    zval *callback;
    zend_bool before = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|b", &callback, &before) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (ZVAL_IS_NULL(callback))
    {
        if (SwooleG.main_reactor->idle_task.callback == NULL)
        {
            RETURN_FALSE;
        }
        else
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->idle_task.data);
            SwooleG.main_reactor->idle_task.callback = NULL;
            SwooleG.main_reactor->idle_task.data = NULL;
            RETURN_TRUE;
        }
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_defer_callback *cb = emalloc(sizeof(php_defer_callback));

    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
    Z_TRY_ADDREF_P(callback);

    if (before == 0)
    {
        if (SwooleG.main_reactor->idle_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->idle_task.data);
        }

        SwooleG.main_reactor->idle_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->idle_task.data = cb;
    }
    else
    {
        if (SwooleG.main_reactor->future_task.data != NULL)
        {
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_callback, SwooleG.main_reactor->future_task.data);
        }

        SwooleG.main_reactor->future_task.callback = php_swoole_event_onEndCallback;
        SwooleG.main_reactor->future_task.data = cb;
        //Registration onBegin callback function
        swReactor_activate_future_task(SwooleG.main_reactor);
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_exit)
{
    php_swoole_event_exit();
}

PHP_FUNCTION(swoole_event_wait)
{
    if (!SwooleG.main_reactor)
    {
        return;
    }
    php_swoole_event_wait();
}

PHP_FUNCTION(swoole_event_dispatch)
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
        swoole_php_fatal_error(E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
    }

    SwooleG.main_reactor->once = 0;
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_isset)
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
        swoole_php_fatal_error(E_WARNING, "unknow type.");
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
