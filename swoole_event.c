<<<<<<< HEAD
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
#include "php_streams.h"
#include "php_network.h"

#ifdef SW_SOCKETS
#if PHP_VERSION_ID >= 50301 && (HAVE_SOCKETS || defined(COMPILE_DL_SOCKETS))
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#else
#error "Enable sockets support, But no sockets extension"
#endif
#endif

typedef struct
{
    zval *cb_read;
    zval *cb_write;
    zval *socket;
} swoole_reactor_fd;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static int swoole_convert_to_fd(zval **fd);

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL;
    zval **args[1];
    swoole_reactor_fd *fd = event->socket->object;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: onRead handler error");
        return SW_ERR;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL;
    zval **args[1];
    swoole_reactor_fd *fd = event->socket->object;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    if (!fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    args[0] = &fd->socket;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: onWrite handler error");
        return SW_ERR;
    }

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    int error;
    socklen_t len = sizeof(error);

    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
    }
    if (error != 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    efree(event->socket->object);
    event->socket->active = 0;

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    return SW_OK;
}

void php_swoole_event_init(void)
{
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
}

static int swoole_convert_to_fd(zval **fd)
{
    php_stream *stream;
    int socket_fd;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

#ifdef SWOOLE_SOCKETS_SUPPORT
    php_socket *php_sock;
#endif
    if (SW_Z_TYPE_PP(fd) == IS_RESOURCE)
    {
        if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, fd, -1, NULL, php_file_le_stream()))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1)
                    != SUCCESS || socket_fd < 0)
            {
                return SW_ERR;
            }
        }
        else
        {
#ifdef SWOOLE_SOCKETS_SUPPORT
            if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, fd, -1, NULL, php_sockets_le_socket()))
            {
                socket_fd = php_sock->bsd_socket;

            }
            else
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
                return SW_ERR;
            }
#else
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "fd argument must be valid PHP stream resource");
            return SW_ERR;
#endif
        }
    }
    else if (SW_Z_TYPE_PP(fd) == IS_LONG)
    {
        socket_fd = Z_LVAL_PP(fd);
        if (socket_fd < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid file descriptor passed");
            return SW_ERR;
        }
    }
    else
    {
        return SW_ERR;
    }
    return socket_fd;
}

PHP_FUNCTION(swoole_event_add)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval **fd;
    char *func_name = NULL;
    long event_flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|zzl", &fd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    if ((cb_read == NULL && cb_write == NULL) || (ZVAL_IS_NULL(cb_read) && ZVAL_IS_NULL(cb_write)))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no read or write event callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swoole_reactor_fd *reactor_fd = emalloc(sizeof(swoole_reactor_fd));

    reactor_fd->socket = *fd;
    reactor_fd->cb_read = cb_read;
    reactor_fd->cb_write = cb_write;

    sw_zval_add_ref(&reactor_fd->socket);

    if (cb_read!= NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        sw_zval_add_ref(&reactor_fd->cb_read);
    }

    if (cb_write!= NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        sw_zval_add_ref(&reactor_fd->cb_write);
    }

    php_swoole_check_reactor();
    swSetNonBlock(socket_fd); //must be nonblock

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    socket->object = reactor_fd;
    socket->active = 1;

    RETURN_LONG(socket_fd);
}

PHP_FUNCTION(swoole_event_write)
{
    zval **fd;
    char *data;
    int len;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_write.");
        RETURN_FALSE;
    }
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Zs", &fd, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

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
    zval **fd;

    char *func_name = NULL;
    long event_flag = 0;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_set.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|zzl", &fd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (!socket->active)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "socket[%d] is not found in the reactor.", socket_fd);
        efree(func_name);
        RETURN_FALSE;
    }
    swoole_reactor_fd *ev_set = socket->object;

    if (cb_read != NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!sw_zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            ev_set->cb_read = cb_read;
            sw_zval_add_ref(&cb_read);
            efree(func_name);
        }
    }

    if (cb_write != NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!sw_zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            ev_set->cb_write = cb_write;
            sw_zval_add_ref(&cb_write);
            efree(func_name);
        }
    }

    if ((event_flag & SW_EVENT_READ) && ev_set->cb_read == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && ev_set->cb_write == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: no write callback.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor->set(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event_set failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_del)
{
    zval **fd;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_del.");
        RETURN_FALSE;
    }
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z", &fd) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    efree(socket->object);
    socket->active = 0;

    SW_CHECK_RETURN(SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd));
}

PHP_FUNCTION(swoole_event_exit)
{
    if (SwooleWG.in_client == 1)
    {
        //stop reactor
        SwooleG.running = 0;
    }
}

PHP_FUNCTION(swoole_event_wait)
{
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot use swoole_event_wait.");
        RETURN_FALSE;
    }
    
    if (SwooleWG.in_client == 1 && SwooleWG.reactor_ready == 0 && SwooleG.running)
    {
        SwooleWG.reactor_ready = 1;

#ifdef HAVE_SIGNALFD
        if (SwooleG.main_reactor->check_signalfd)
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif

        int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
        if (ret < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
        }
    }
}
=======
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
#include "php_streams.h"
#include "php_network.h"

#ifdef SW_SOCKETS
#if PHP_VERSION_ID >= 50301 && (HAVE_SOCKETS || defined(COMPILE_DL_SOCKETS))
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#else
#error "Enable sockets support, But no sockets extension"
#endif
#endif

typedef struct
{
    zval *cb_read;
    zval *cb_write;
    zval *socket;
} swoole_reactor_fd;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static int swoole_convert_to_fd(zval **fd);

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    swoole_reactor_fd *fd = event->socket->object;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    args[0] = &fd->socket;

    if (call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: onRead handler error");
        return SW_ERR;
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{
    zval *retval;
    zval **args[1];
    swoole_reactor_fd *fd = event->socket->object;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    if (!fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    args[0] = &fd->socket;

    if (call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: onWrite handler error");
        return SW_ERR;
    }

    if (retval != NULL)
    {
        zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    int error;
    socklen_t len = sizeof(error);

    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
    }
    if (error != 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    efree(event->socket->object);
    event->socket->active = 0;

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    return SW_OK;
}

void php_swoole_event_init(void)
{
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
}

static int swoole_convert_to_fd(zval **fd)
{
    php_stream *stream;
    int socket_fd;

    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

#ifdef SWOOLE_SOCKETS_SUPPORT
    php_socket *php_sock;
#endif
    if (Z_TYPE_PP(fd) == IS_RESOURCE)
    {
        if (ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, fd, -1, NULL, php_file_le_stream()))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1)
                    != SUCCESS || socket_fd < 0)
            {
                return SW_ERR;
            }
        }
        else
        {
#ifdef SWOOLE_SOCKETS_SUPPORT
            if (ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, fd, -1, NULL, php_sockets_le_socket()))
            {
                socket_fd = php_sock->bsd_socket;

            }
            else
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
                return SW_ERR;
            }
#else
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "fd argument must be valid PHP stream resource");
            return SW_ERR;
#endif
        }
    }
    else if (Z_TYPE_PP(fd) == IS_LONG)
    {
        socket_fd = Z_LVAL_PP(fd);
        if (socket_fd < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid file descriptor passed");
            return SW_ERR;
        }
    }
    else
    {
        return SW_ERR;
    }
    return socket_fd;
}

PHP_FUNCTION(swoole_event_add)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval **fd;
    char *func_name = NULL;
    long event_flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|zzl", &fd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    if ((cb_read == NULL && cb_write == NULL) || (ZVAL_IS_NULL(cb_read) && ZVAL_IS_NULL(cb_write)))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no read or write event callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }
    else if (socket_fd == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid socket fd [%d].", socket_fd);
        RETURN_FALSE;
    }

    swoole_reactor_fd *reactor_fd = emalloc(sizeof(swoole_reactor_fd));

    reactor_fd->socket = *fd;
    reactor_fd->cb_read = cb_read;
    reactor_fd->cb_write = cb_write;

    zval_add_ref(&reactor_fd->socket);

    if (cb_read!= NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        zval_add_ref(&reactor_fd->cb_read);
    }

    if (cb_write!= NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);
        zval_add_ref(&reactor_fd->cb_write);
    }

    php_swoole_check_reactor();
    swSetNonBlock(socket_fd); //must be nonblock

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    socket->object = reactor_fd;
    socket->active = 1;

    RETURN_LONG(socket_fd);
}

PHP_FUNCTION(swoole_event_write)
{
    zval **fd;
    char *data;
    int len;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_write.");
        RETURN_FALSE;
    }
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Zs", &fd, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

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
    zval **fd;

    char *func_name = NULL;
    long event_flag = 0;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_set.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|zzl", &fd, &cb_read, &cb_write, &event_flag) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    if (!socket->active)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "socket[%d] is not found in the reactor.", socket_fd);
        efree(func_name);
        RETURN_FALSE;
    }
    swoole_reactor_fd *ev_set = socket->object;

    if (cb_read != NULL && !ZVAL_IS_NULL(cb_read))
    {
        if (!zend_is_callable(cb_read, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            ev_set->cb_read = cb_read;
            zval_add_ref(&cb_read);
            efree(func_name);
        }
    }

    if (cb_write != NULL && !ZVAL_IS_NULL(cb_write))
    {
        if (!zend_is_callable(cb_write, 0, &func_name TSRMLS_CC))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        else
        {
            ev_set->cb_write = cb_write;
            zval_add_ref(&cb_write);
            efree(func_name);
        }
    }

    if ((event_flag & SW_EVENT_READ) && ev_set->cb_read == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && ev_set->cb_write == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event: no write callback.");
        RETURN_FALSE;
    }

    if (SwooleG.main_reactor->set(SwooleG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_event_set failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_del)
{
    zval **fd;
    
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot swoole_event_del.");
        RETURN_FALSE;
    }
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z", &fd) == FAILURE)
    {
        return;
    }

    int socket_fd = swoole_convert_to_fd(fd);
    if (socket_fd < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, socket_fd);
    efree(socket->object);
    socket->active = 0;

    int ret = SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd);

    if (SwooleG.main_reactor->event_num == 0 && SwooleWG.in_client == 1)
    {
        SwooleG.main_reactor->running = 0;
    }

    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_event_exit)
{
    if (SwooleWG.in_client == 1)
    {
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
    }
}

PHP_FUNCTION(swoole_event_wait)
{
    if (!SwooleG.main_reactor)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "reactor no ready, cannot use swoole_event_wait.");
        RETURN_FALSE;
    }
    
    if (SwooleWG.in_client == 1 && SwooleWG.reactor_ready == 0 && SwooleG.running)
    {
        SwooleWG.reactor_ready = 1;

#ifdef HAVE_SIGNALFD
        if (SwooleG.main_reactor->check_signalfd)
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif

        int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
        if (ret < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
        }
    }
}
>>>>>>> 0f94d97b1c71851cad8d92519f2cb2210006ac7d
