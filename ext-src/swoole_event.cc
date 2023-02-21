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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "swoole_server.h"
#include "swoole_signal.h"

using namespace swoole;
using swoole::network::Socket;

static std::unordered_map<int, Socket *> event_socket_map;

zend_class_entry *swoole_event_ce;
static zend_object_handlers swoole_event_handlers;

struct EventObject {
    zval zsocket;
    zend_fcall_info_cache fci_cache_read;
    zend_fcall_info_cache fci_cache_write;
};

static int event_readable_callback(Reactor *reactor, Event *event);
static int event_writable_callback(Reactor *reactor, Event *event);
static int event_error_callback(Reactor *reactor, Event *event);
static void event_defer_callback(void *data);
static void event_end_callback(void *data);

SW_EXTERN_C_BEGIN
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
SW_EXTERN_C_END

// clang-format off
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
// clang-format on

void php_swoole_event_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_event, "Swoole\\Event", "swoole_event", nullptr, swoole_event_methods);
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

static void event_object_free(void *data) {
    EventObject *peo = (EventObject *) data;
    if (peo->fci_cache_read.function_handler) {
        sw_zend_fci_cache_discard(&peo->fci_cache_read);
    }
    if (peo->fci_cache_write.function_handler) {
        sw_zend_fci_cache_discard(&peo->fci_cache_write);
    }
    zval_ptr_dtor((&peo->zsocket));
    efree(peo);
}

static int event_readable_callback(Reactor *reactor, Event *event) {
    EventObject *peo = (EventObject *) event->socket->object;

    zval argv[1];
    argv[0] = peo->zsocket;

    if (UNEXPECTED(!zend::function::call(&peo->fci_cache_read, 1, argv, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_fatal_error(E_WARNING,
                               "%s: onRead callback handler error, fd [%d] will be removed from reactor",
                               ZSTR_VAL(swoole_event_ce->name),
                               php_swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = nullptr;
        swoole_event_defer(event_object_free, peo);
        swoole_event_del(event->socket);
        return SW_ERR;
    }

    return SW_OK;
}

static int event_writable_callback(Reactor *reactor, Event *event) {
    EventObject *peo = (EventObject *) event->socket->object;

    zval argv[1];
    argv[0] = peo->zsocket;

    if (UNEXPECTED(!zend::function::call(&peo->fci_cache_write, 1, argv, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_fatal_error(E_WARNING,
                               "%s: onWrite callback handler error, fd [%d] will be removed from reactor",
                               ZSTR_VAL(swoole_event_ce->name),
                               php_swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = nullptr;
        swoole_event_defer(event_object_free, peo);
        swoole_event_del(event->socket);
        return SW_ERR;
    }

    return SW_OK;
}

static int event_error_callback(Reactor *reactor, Event *event) {
    if (!(event->socket->events & SW_EVENT_ERROR)) {
        if (event->socket->events & SW_EVENT_READ) {
            return reactor->get_handler(SW_EVENT_READ, event->socket->fd_type)(reactor, event);
        } else {
            return reactor->get_handler(SW_EVENT_WRITE, event->socket->fd_type)(reactor, event);
        }
    }

    int error;
    if (event->socket->get_option(SOL_SOCKET, SO_ERROR, &error) < 0) {
        php_swoole_sys_error(E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed", event->fd);
    }

    if (error != 0) {
        php_swoole_fatal_error(
            E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    event_object_free(event->socket->object);
    swoole_event_del(event->socket);

    return SW_OK;
}

static void event_defer_callback(void *data) {
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) data;

    if (UNEXPECTED(!zend::function::call(fci_cache, 0, nullptr, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s::defer callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }

    sw_zend_fci_cache_discard(fci_cache);
    efree(fci_cache);
}

static void event_end_callback(void *data) {
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) data;
    if (UNEXPECTED(!zend::function::call(fci_cache, 0, nullptr, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s::end callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }
}

int php_swoole_reactor_init() {
    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode");
        return SW_ERR;
    }

    if (sw_server()) {
        if (sw_server()->is_task_worker() && !sw_server()->task_enable_coroutine) {
            php_swoole_fatal_error(
                E_ERROR, "Unable to use async-io in task processes, please set `task_enable_coroutine` to true");
            return SW_ERR;
        }
        if (sw_server()->is_manager()) {
            php_swoole_fatal_error(E_ERROR, "Unable to use async-io in manager process");
            return SW_ERR;
        }
    }
    if (!sw_reactor()) {
        swoole_trace_log(SW_TRACE_PHP, "init reactor");

        if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
            php_swoole_fatal_error(E_ERROR, "Unable to create event-loop reactor");
            return SW_ERR;
        }

        php_swoole_register_shutdown_function("Swoole\\Event::rshutdown");
    }

    if (sw_reactor() && SwooleG.user_exit_condition &&
        !sw_reactor()->isset_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT)) {
        sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT, SwooleG.user_exit_condition);
    }

    return SW_OK;
}

void php_swoole_event_wait() {
    if (php_swoole_is_fatal_error() || !sw_reactor()) {
        return;
    }
#ifdef HAVE_SIGNALFD
    if (sw_reactor()->check_signalfd) {
        swoole_signalfd_setup(sw_reactor());
    }
#endif
    if (!sw_reactor()->if_exit() && !sw_reactor()->bailout) {
        // Don't disable object slot reuse while running shutdown functions:
        // https://github.com/php/php-src/commit/bd6eabd6591ae5a7c9ad75dfbe7cc575fa907eac
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        zend_bool in_shutdown = EG(flags) & EG_FLAGS_IN_SHUTDOWN;
        EG(flags) &= ~EG_FLAGS_IN_SHUTDOWN;
#endif
        if (sw_reactor()->wait(nullptr) < 0) {
            php_swoole_sys_error(E_ERROR, "reactor wait failed");
        }
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        if (in_shutdown) {
            EG(flags) |= EG_FLAGS_IN_SHUTDOWN;
        }
#endif
    }
    swoole_event_free();
}

void php_swoole_event_exit() {
    if (sw_reactor()) {
        php_swoole_timer_clear_all();
        sw_reactor()->running = false;
    }
}

static inline bool zval_is_stream_resource(zval *zsocket) {
    return Z_RES_TYPE_P(zsocket) ==  php_file_le_stream() || Z_RES_TYPE_P(zsocket) == php_file_le_pstream();
}

#if defined(SWOOLE_SOCKETS_SUPPORT) && PHP_MAJOR_VERSION < 8
static inline bool zval_is_socket_resource(zval *zsocket) {
    return Z_RES_TYPE_P(zsocket) ==  php_sockets_le_socket();
}
#endif

int php_swoole_convert_to_fd(zval *zsocket) {
    int fd = -1;

    switch (Z_TYPE_P(zsocket)) {
    case IS_RESOURCE: {
        php_stream *stream;
        if (zval_is_stream_resource(zsocket) && (php_stream_from_zval_no_verify(stream, zsocket))) {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **) &fd, 1) ==
                    SUCCESS &&
                fd >= 0) {
                return fd;
            }
        }
#if defined(SWOOLE_SOCKETS_SUPPORT) && PHP_MAJOR_VERSION < 8
        else if (zval_is_socket_resource(zsocket)) {
            php_socket *php_sock = SW_Z_SOCKET_P(zsocket);
            if (php_sock == nullptr || php_sock->bsd_socket < 0) {
                php_swoole_fatal_error(E_WARNING, "invalid socket resource");
                return SW_ERR;
            }
            return php_sock->bsd_socket;
        }
#endif
        break;
    }
    case IS_LONG: {
        fd = Z_LVAL_P(zsocket);
        if (fd < 0) {
            php_swoole_fatal_error(E_WARNING, "invalid file descriptor#%d passed", fd);
            return SW_ERR;
        }
        return fd;
    }
    case IS_OBJECT: {
        zval *zfd = nullptr;
        if (instanceof_function(Z_OBJCE_P(zsocket), swoole_socket_coro_ce)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_FD), 0);
        } else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_client_ce)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_SOCK), 0);
        } else if (instanceof_function(Z_OBJCE_P(zsocket), swoole_process_ce)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_PIPE), 0);
#if PHP_MAJOR_VERSION >= 8 && defined(SWOOLE_SOCKETS_SUPPORT)
        } else if (instanceof_function(Z_OBJCE_P(zsocket), socket_ce)) {
            php_socket *php_sock = SW_Z_SOCKET_P(zsocket);
            if (IS_INVALID_SOCKET(php_sock)) {
                php_swoole_fatal_error(E_WARNING, "contains a closed socket");
                return SW_ERR;
            }
            return php_sock->bsd_socket;
#endif
        }
        if (zfd == nullptr || Z_TYPE_P(zfd) != IS_LONG) {
            break;
        }
        return Z_LVAL_P(zfd);
    }
    default:
        break;
    }
    php_swoole_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
    swoole_set_last_error(SW_ERROR_EVENT_SOCKET_INVALID);
    return SW_ERR;
}

int php_swoole_convert_to_fd_ex(zval *zsocket, int *async) {
    int fd;

    *async = 0;
    if (Z_TYPE_P(zsocket) == IS_RESOURCE) {
        php_stream *stream;
        if ((php_stream_from_zval_no_verify(stream, zsocket))) {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **) &fd, 1) ==
                    SUCCESS &&
                fd >= 0) {
                *async = (stream->wrapper && (stream->wrapper->wops == php_plain_files_wrapper.wops)) ? 0 : 1;
                return fd;
            }
        }
#ifdef SWOOLE_SOCKETS_SUPPORT
        else {
            php_socket *php_sock;
            if ((php_sock = SW_Z_SOCKET_P(zsocket))) {
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
php_socket *php_swoole_convert_to_socket(int sock) {
    php_socket *socket_object;
#if PHP_VERSION_ID < 80000
    socket_object = (php_socket *) emalloc(sizeof *socket_object);
    sw_memset_zero(socket_object, sizeof(*socket_object));
    socket_object->bsd_socket = sock;
    socket_object->blocking = 1;

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(sock, (struct sockaddr *) &addr, &addr_len) == 0) {
        socket_object->type = addr.ss_family;
    } else {
        php_swoole_sys_error(E_WARNING, "unable to obtain socket family");
    _error:
        efree(socket_object);
        return nullptr;
    }

    int t = fcntl(sock, F_GETFL);
    if (t == -1) {
        php_swoole_sys_error(E_WARNING, "unable to obtain blocking state");
        goto _error;
    } else {
        socket_object->blocking = !(t & O_NONBLOCK);
    }
#else
    zval zsocket;
    object_init_ex(&zsocket, socket_ce);
    socket_object = Z_SOCKET_P(&zsocket);
    socket_import_file_descriptor(sock, socket_object);
#endif
    return socket_object;
}
#endif

static void event_check_reactor() {
    php_swoole_check_reactor();

    if (!swoole_event_isset_handler(SW_FD_USER)) {
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_READ, event_readable_callback);
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_WRITE, event_writable_callback);
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_ERROR, event_error_callback);
    }
}

static Socket *event_get_socket(int socket_fd) {
    auto i = event_socket_map.find(socket_fd);
    if (i == event_socket_map.end()) {
        return nullptr;
    }
    return i->second;
}

static PHP_FUNCTION(swoole_event_add) {
    zval *zfd;
    zend_fcall_info fci_read = empty_fcall_info;
    zend_fcall_info_cache fci_cache_read = empty_fcall_info_cache;
    zend_fcall_info fci_write = empty_fcall_info;
    zend_fcall_info_cache fci_cache_write = empty_fcall_info_cache;
    zend_long events = SW_EVENT_READ;

    ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_OPTIONAL
    Z_PARAM_FUNC_EX(fci_read, fci_cache_read, 1, 0)
    Z_PARAM_FUNC_EX(fci_write, fci_cache_write, 1, 0)
    Z_PARAM_LONG(events)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (fci_read.size == 0 && fci_write.size == 0) {
        php_swoole_fatal_error(E_WARNING, "both read and write callbacks are empty");
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }
    if (socket_fd == 0 && (events & SW_EVENT_WRITE)) {
        php_swoole_fatal_error(E_WARNING, "invalid socket fd [%d]", socket_fd);
        RETURN_FALSE;
    }
    if (event_socket_map.find(socket_fd) != event_socket_map.end()) {
        php_swoole_fatal_error(E_WARNING, "already exist");
        RETURN_FALSE;
    }
    if (!(events & (SW_EVENT_WRITE | SW_EVENT_READ))) {
        php_swoole_fatal_error(E_WARNING, "invalid events");
        RETURN_FALSE;
    }

    EventObject *peo = (EventObject *) ecalloc(1, sizeof(*peo));

    Z_TRY_ADDREF_P(zfd);
    peo->zsocket = *zfd;

    if (fci_read.size != 0) {
        sw_zend_fci_cache_persist(&fci_cache_read);
        peo->fci_cache_read = fci_cache_read;
    }
    if (fci_write.size != 0) {
        sw_zend_fci_cache_persist(&fci_cache_write);
        peo->fci_cache_write = fci_cache_write;
    }

    event_check_reactor();

    Socket *socket = swoole::make_socket(socket_fd, SW_FD_USER);
    if (!socket) {
        RETURN_FALSE;
    }

    socket->set_nonblock();
    socket->object = peo;

    if (swoole_event_add(socket, events) < 0) {
        php_swoole_fatal_error(E_WARNING, "swoole_event_add failed");
        socket->free();
        event_object_free(peo);
        RETURN_FALSE;
    }

    event_socket_map[socket_fd] = socket;

    RETURN_LONG(socket_fd);
}

static PHP_FUNCTION(swoole_event_write) {
    zval *zfd;
    char *data;
    size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zs", &zfd, &data, &len) == FAILURE) {
        RETURN_FALSE;
    }

    if (len == 0) {
        php_swoole_fatal_error(E_WARNING, "data empty");
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (socket == nullptr) {
        php_swoole_fatal_error(E_WARNING, "socket[%d] is not found in the reactor", socket_fd);
        RETURN_FALSE;
    }

    event_check_reactor();
    if (swoole_event_write(socket, data, len) < 0) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_FUNCTION(swoole_event_set) {
    if (!sw_reactor()) {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_set");
        RETURN_FALSE;
    }

    zval *zfd;
    zend_fcall_info fci_read = empty_fcall_info;
    zend_fcall_info_cache fci_cache_read = empty_fcall_info_cache;
    zend_fcall_info fci_write = empty_fcall_info;
    zend_fcall_info_cache fci_cache_write = empty_fcall_info_cache;
    zend_long events = 0;

    ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_OPTIONAL
    Z_PARAM_FUNC_EX(fci_read, fci_cache_read, 1, 0)
    Z_PARAM_FUNC_EX(fci_write, fci_cache_write, 1, 0)
    Z_PARAM_LONG(events)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (socket == nullptr) {
        php_swoole_fatal_error(E_WARNING, "socket[%d] is not found in the reactor", socket_fd);
        RETURN_FALSE;
    }

    EventObject *reactor_fd = (EventObject *) socket->object;
    if (fci_read.size != 0) {
        if (reactor_fd->fci_cache_read.function_handler) {
            sw_zend_fci_cache_discard(&reactor_fd->fci_cache_read);
        }
        sw_zend_fci_cache_persist(&fci_cache_read);
        reactor_fd->fci_cache_read = fci_cache_read;
    }
    if (fci_write.size != 0) {
        if (reactor_fd->fci_cache_write.function_handler) {
            sw_zend_fci_cache_discard(&reactor_fd->fci_cache_write);
        }
        sw_zend_fci_cache_persist(&fci_cache_write);
        reactor_fd->fci_cache_write = fci_cache_write;
    }

    if ((events & SW_EVENT_READ) && reactor_fd->fci_cache_read.function_handler == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find read callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if ((events & SW_EVENT_WRITE) && reactor_fd->fci_cache_write.function_handler == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find write callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if (swoole_event_set(socket, events) < 0) {
        php_swoole_fatal_error(E_WARNING, "%s::set failed", ZSTR_VAL(swoole_event_ce->name));
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_del) {
    zval *zfd;

    if (!sw_reactor()) {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_del");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zfd) == FAILURE) {
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (!socket) {
        RETURN_FALSE;
    }
    swoole_event_defer(event_object_free, socket->object);
    int retval = swoole_event_del(socket);
    event_socket_map.erase(socket_fd);
    socket->fd = -1;
    socket->free();
    RETURN_BOOL(retval == SW_OK);
}

static PHP_FUNCTION(swoole_event_defer) {
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) ecalloc(1, sizeof(zend_fcall_info_cache));

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_FUNC(fci, *fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(efree(fci_cache); RETURN_FALSE);

    php_swoole_check_reactor();

    sw_zend_fci_cache_persist(fci_cache);
    swoole_event_defer(event_defer_callback, fci_cache);

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_cycle) {
    if (!sw_reactor()) {
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

    if (_fci.size == 0) {
        if (sw_reactor()->idle_task.callback == nullptr) {
            RETURN_FALSE;
        } else {
            swoole_event_defer(sw_zend_fci_cache_free, sw_reactor()->idle_task.data);
            sw_reactor()->idle_task.callback = nullptr;
            sw_reactor()->idle_task.data = nullptr;
            RETURN_TRUE;
        }
    }

    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));

    *fci_cache = _fci_cache;
    sw_zend_fci_cache_persist(fci_cache);

    if (!before) {
        if (sw_reactor()->idle_task.data != nullptr) {
            swoole_event_defer(sw_zend_fci_cache_free, sw_reactor()->idle_task.data);
        }

        sw_reactor()->idle_task.callback = event_end_callback;
        sw_reactor()->idle_task.data = fci_cache;
    } else {
        if (sw_reactor()->future_task.data != nullptr) {
            swoole_event_defer(sw_zend_fci_cache_free, sw_reactor()->future_task.data);
        }

        sw_reactor()->future_task.callback = event_end_callback;
        sw_reactor()->future_task.data = fci_cache;
        // Registration onBegin callback function
        sw_reactor()->activate_future_task();
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_exit) {
    php_swoole_event_exit();
}

static PHP_FUNCTION(swoole_event_wait) {
    if (!sw_reactor()) {
        return;
    }
    php_swoole_event_wait();
}

static PHP_FUNCTION(swoole_event_rshutdown) {
    /* prevent the program from jumping out of the rshutdown */
    zend_try {
        if (php_swoole_is_fatal_error() || !sw_reactor()) {
            return;
        }
        // when throw Exception, do not show the info
        if (!sw_reactor()->bailout) {
            php_swoole_fatal_error(E_DEPRECATED, "Event::wait() in shutdown function is deprecated");
        }
        php_swoole_event_wait();
    }
    zend_end_try();
}

static PHP_FUNCTION(swoole_event_dispatch) {
    if (!sw_reactor()) {
        RETURN_FALSE;
    }
    sw_reactor()->once = true;

#ifdef HAVE_SIGNALFD
    if (sw_reactor()->check_signalfd) {
        swoole_signalfd_setup(sw_reactor());
    }
#endif

    if (sw_reactor()->wait(nullptr) < 0) {
        php_swoole_sys_error(E_ERROR, "reactor wait failed");
    }
    sw_reactor()->once = false;
    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_isset) {
    if (!sw_reactor()) {
        RETURN_FALSE;
    }

    zval *zfd;
    zend_long events = SW_EVENT_READ | SW_EVENT_WRITE;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|l", &zfd, &events) == FAILURE) {
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }

    Socket *_socket = event_get_socket(socket_fd);
    if (_socket == nullptr || _socket->removed) {
        RETURN_FALSE;
    }
    if (_socket->events & events) {
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}
