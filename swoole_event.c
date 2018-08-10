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
#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#endif

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    struct
    {
        zval cb_read;
        zval cb_write;
        zval socket;
    } stack;
#endif
    zval *cb_read;
    zval *cb_write;
    zval *socket;
} php_reactor_fd;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
#endif
    zval *callback;
} php_defer_callback;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static void php_swoole_event_onDefer(void *_cb);
static void php_swoole_event_onEndCallback(void *_cb);

static void free_event_callback(void* data)
{
    php_reactor_fd *ev_set = (php_reactor_fd*) data;
    if (ev_set->cb_read)
    {
        sw_zval_ptr_dtor(&(ev_set->cb_read));
        ev_set->cb_read = NULL;
    }
    if (ev_set->cb_write)
    {
        sw_zval_ptr_dtor(&(ev_set->cb_write));
        ev_set->cb_write = NULL;
    }
    if (ev_set->socket)
    {
        sw_zval_ptr_dtor(&(ev_set->socket));
        ev_set->socket = NULL;
    }
    efree(ev_set);
}

static void free_callback(void* data)
{
    php_defer_callback *cb = (php_defer_callback *) data;
    sw_zval_ptr_dtor(&cb->callback);
    efree(cb);
}

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    php_reactor_fd *fd = event->socket->object;

    SWOOLE_GET_TSRMLS;

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onRead handler error.");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    php_reactor_fd *fd = event->socket->object;

    SWOOLE_GET_TSRMLS;

    if (!fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: onWrite handler error");
        SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    SWOOLE_GET_TSRMLS;

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

static void php_swoole_event_onDefer(void *_cb)
{
    php_defer_callback *defer = _cb;

    SWOOLE_GET_TSRMLS;
    zval *retval;
    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: defer handler error");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&defer->callback);
    efree(defer);
}

static void php_swoole_event_onEndCallback(void *_cb)
{
    php_defer_callback *defer = _cb;

    SWOOLE_GET_TSRMLS;
    zval *retval;
    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event: defer handler error");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

void php_swoole_event_init(void)
{
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);
}

void php_swoole_event_wait()
{
    SWOOLE_GET_TSRMLS;
    if (SwooleWG.in_client == 1 && SwooleWG.reactor_ready == 0 && SwooleG.running)
    {
#if PHP_MAJOR_VERSION >= 7
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
#endif
        SwooleWG.reactor_ready = 1;

#ifdef HAVE_SIGNALFD
        if (SwooleG.main_reactor->check_signalfd)
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif

#ifdef SW_COROUTINE
        if (COROG.active == 0)
        {
            coro_init(TSRMLS_C);
        }
#endif
        if (!swReactor_empty(SwooleG.main_reactor))
        {
            int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
            if (ret < 0)
            {
                swoole_php_fatal_error(E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
            }
        }
        if (SwooleG.timer.map)
        {
            php_swoole_clear_all_timer();
        }
        SwooleWG.reactor_exit = 1;
    }
}

int swoole_convert_to_fd(zval *zfd TSRMLS_DC)
{
    php_stream *stream;
    int socket_fd;

#ifdef SWOOLE_SOCKETS_SUPPORT
    php_socket *php_sock;
#endif
    if (SW_Z_TYPE_P(zfd) == IS_RESOURCE)
    {
        if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, &zfd, -1, NULL, php_file_le_stream()))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1) != SUCCESS || socket_fd < 0)
            {
                return SW_ERR;
            }
        }
        else
        {
#ifdef SWOOLE_SOCKETS_SUPPORT
            if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, &zfd, -1, NULL, php_sockets_le_socket()))
            {
                socket_fd = php_sock->bsd_socket;

            }
            else
            {
                swoole_php_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
                return SW_ERR;
            }
#else
            swoole_php_fatal_error(E_WARNING, "fd argument must be valid PHP stream resource");
            return SW_ERR;
#endif
        }
    }
    else if (SW_Z_TYPE_P(zfd) == IS_LONG)
    {
        socket_fd = Z_LVAL_P(zfd);
        if (socket_fd < 0)
        {
            swoole_php_fatal_error(E_WARNING, "invalid file descriptor passed");
            return SW_ERR;
        }
    }
    else if (SW_Z_TYPE_P(zfd) == IS_OBJECT)
    {
        zval *zsock = NULL;
        if (instanceof_function(Z_OBJCE_P(zfd), swoole_client_class_entry_ptr TSRMLS_CC))
        {
            zsock = sw_zend_read_property(Z_OBJCE_P(zfd), zfd, SW_STRL("sock")-1, 0 TSRMLS_CC);
        }
        else if (instanceof_function(Z_OBJCE_P(zfd), swoole_process_class_entry_ptr TSRMLS_CC))
        {
            zsock = sw_zend_read_property(Z_OBJCE_P(zfd), zfd, SW_STRL("pipe")-1, 0 TSRMLS_CC);
        }
        if (zsock == NULL || ZVAL_IS_NULL(zsock))
        {
            swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client or swoole_process.");
            return -1;
        }
        socket_fd = Z_LVAL_P(zsock);
    }
    else
    {
        return SW_ERR;
    }
    return socket_fd;
}

int swoole_convert_to_fd_ex(zval *zfd, int *async TSRMLS_DC)
{
    php_stream *stream;
    int fd;

#ifdef SWOOLE_SOCKETS_SUPPORT
    php_socket *php_sock;
#endif

    if (SW_Z_TYPE_P(zfd) != IS_RESOURCE)
    {
        swoole_php_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
        return SW_ERR;
    }
    if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, &zfd, -1, NULL, php_file_le_stream()))
    {
        if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&fd, 1) == SUCCESS && fd >= 0)
        {
            *async = stream->wrapper->wops == php_plain_files_wrapper.wops ? 0 : 1;
            return fd;
        }
    }
#ifdef SWOOLE_SOCKETS_SUPPORT
    else if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, &zfd, -1, NULL, php_sockets_le_socket()))
    {
        fd = php_sock->bsd_socket;
        *async = 1;
    }
#endif
    swoole_php_fatal_error(E_WARNING, "invalid file descriptor passed");
    return SW_ERR;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket* swoole_convert_to_socket(int sock)
{
    SWOOLE_GET_TSRMLS;
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
#endif

PHP_FUNCTION(swoole_event_add)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd;
    char *func_name = NULL;
    long event_flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    if ((cb_read == NULL && cb_write == NULL) || (ZVAL_IS_NULL(cb_read) && ZVAL_IS_NULL(cb_write)))
    {
        swoole_php_fatal_error(E_WARNING, "no read or write event callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
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
    sw_zval_add_ref(&reactor_fd->socket);

    if (cb_read!= NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_read = cb_read;
        sw_zval_add_ref(&cb_read);
        sw_copy_to_stack(reactor_fd->cb_read, reactor_fd->stack.cb_read);
    }
    else
    {
        reactor_fd->cb_read = NULL;
    }

    if (cb_write!= NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        reactor_fd->cb_write = cb_write;
        sw_zval_add_ref(&cb_write);
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
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zfd, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
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
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd;

    char *func_name = NULL;
    long event_flag = 0;
    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor no ready, cannot swoole_event_set.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
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
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_read)
            {
                sw_zval_ptr_dtor(&ev_set->cb_read);
            }
            ev_set->cb_read = cb_read;
            sw_zval_add_ref(&cb_read);
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
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            if (ev_set->cb_write)
            {
                sw_zval_ptr_dtor(&ev_set->cb_write);
            }
            ev_set->cb_write = cb_write;
            sw_zval_add_ref(&cb_write);
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
        swoole_php_fatal_error(E_WARNING, "reactor no ready, cannot swoole_event_del.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zfd) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
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
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }

    char *func_name;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_swoole_check_reactor();

    //the event loop is not started
    if (SwooleG.main_reactor->start == 0)
    {
        SW_CHECK_RETURN (php_swoole_add_timer(1, callback, NULL, 0 TSRMLS_CC));
    }

    php_defer_callback *defer = emalloc(sizeof(php_defer_callback));

#if PHP_MAJOR_VERSION >= 7
    defer->callback = &defer->_callback;
    memcpy(defer->callback, callback, sizeof(zval));
#else
    defer->callback = callback;
#endif
    sw_zval_add_ref(&callback);
    SW_CHECK_RETURN(SwooleG.main_reactor->defer(SwooleG.main_reactor, php_swoole_event_onDefer, defer));
}

PHP_FUNCTION(swoole_event_cycle)
{
    if (!SwooleG.main_reactor)
    {
        swoole_php_fatal_error(E_WARNING, "reactor no ready, cannot swoole_event_defer.");
        RETURN_FALSE;
    }

    zval *callback;
    zend_bool before = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|b", &callback, &before) == FAILURE)
    {
        return;
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
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    php_defer_callback *cb = emalloc(sizeof(php_defer_callback));

#if PHP_MAJOR_VERSION >= 7
    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
#else
    cb->callback = callback;
#endif
    sw_zval_add_ref(&callback);

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
    if (SwooleWG.in_client == 1)
    {
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        SwooleG.running = 0;
    }
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

#ifdef SW_COROUTINE
    if (COROG.active == 0)
    {
        coro_init(TSRMLS_C);
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
    long events = SW_EVENT_READ | SW_EVENT_WRITE;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &zfd, &events) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(zfd TSRMLS_CC);
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
