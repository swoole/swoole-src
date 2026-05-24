/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
*/

#ifdef _WIN32

#include "php_swoole_cxx.h"
#include "swoole_iocp.h"

using swoole::Reactor;
#ifdef SW_USE_IOCP
using swoole::Iocp;
#endif

int php_swoole_reactor_init() {
    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode");
        return SW_ERR;
    }

    if (!sw_reactor()) {
        swoole_trace_log(SW_TRACE_PHP, "init Windows reactor");

        if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
            php_swoole_fatal_error(E_ERROR, "Unable to create event-loop reactor");
            return SW_ERR;
        }

#ifdef SW_USE_IOCP
        if (!Iocp::init(sw_reactor())) {
            php_swoole_fatal_error(E_ERROR, "Unable to create IOCP instance");
            return SW_ERR;
        }
#endif

        php_swoole_register_shutdown_function("swoole_event_rshutdown");
    }

#ifdef SW_USE_IOCP
    if (!SwooleTG.iocp && !Iocp::init(sw_reactor())) {
        php_swoole_fatal_error(E_ERROR, "Unable to create IOCP instance");
        return SW_ERR;
    }
#endif

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
    if (swoole_coroutine_is_in()) {
        php_swoole_fatal_error(E_ERROR, "Unable to call Event::wait() in coroutine");
        return;
    }
    if (!sw_reactor()->if_exit() && !sw_reactor()->bailout) {
        swoole_trace_log(SW_TRACE_PHP, "wait Windows reactor");
        if (sw_reactor()->wait() < 0) {
            php_swoole_sys_error(E_ERROR, "reactor wait failed");
        }
    }
    swoole_event_free();
}

PHP_FUNCTION(swoole_event_rshutdown) {
    zend_try {
        if (!php_swoole_is_fatal_error() && sw_reactor()) {
            php_swoole_event_wait();
        }
    }
    zend_end_try();
}

#endif
