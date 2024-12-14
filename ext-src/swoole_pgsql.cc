/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#include "php_swoole_pgsql.h"
#include "php_swoole_private.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

#ifdef SW_USE_PGSQL

using swoole::Reactor;
using swoole::Coroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::translate_events_to_poll;

static SW_THREAD_LOCAL bool swoole_pgsql_blocking = true;

static int swoole_pgsql_socket_poll(PGconn *conn, swEventType event, double timeout = -1) {
    if (swoole_pgsql_blocking) {
        struct pollfd fds[1];
        fds[0].fd = PQsocket(conn);
        fds[0].events |= translate_events_to_poll(event);

        int result = 0;
        do {
             result = poll(fds, 1, timeout);
        } while (result < 0 && errno == EINTR);

        return result > 0 ? 1 : errno == ETIMEDOUT ? 0 : -1;
    }

    Socket sock(PQsocket(conn), SW_SOCK_RAW);
    sock.get_socket()->nonblock = 1;
    bool retval = sock.poll(event, timeout);
    sock.move_fd();
    return retval ? 1 : sock.errCode == ETIMEDOUT ? 0 : -1;
}

static int swoole_pgsql_flush(PGconn *conn) {
    int flush_ret = -1;

    do {
        int ret = swoole_pgsql_socket_poll(conn, SW_EVENT_WRITE);
        if (sw_unlikely(ret < 0)) {
            return -1;
        }
        swoole_trace_log(SW_TRACE_CO_PGSQL, "PQflush(conn=%p)", conn);
        flush_ret = PQflush(conn);
    } while (flush_ret == 1);

    return flush_ret;
}

static PGresult *swoole_pgsql_get_result(PGconn *conn) {
    PGresult *result, *last_result = nullptr;
    int poll_ret = swoole_pgsql_socket_poll(conn, SW_EVENT_READ);
    if (sw_unlikely(poll_ret == SW_ERR)) {
        return nullptr;
    }

    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQgetResult(conn=%p)", conn);
    while ((result = PQgetResult(conn))) {
        PQclear(last_result);
        last_result = result;
    }

    return last_result;
}

PGconn *swoole_pgsql_connectdb(const char *conninfo) {
    PGconn *conn = PQconnectStart(conninfo);
    if (conn == nullptr) {
        return nullptr;
    }

    int fd = PQsocket(conn);
    if (sw_unlikely(fd < 0)) {
        return conn;
    }

    if (!swoole_pgsql_blocking && Coroutine::get_current()) {
        PQsetnonblocking(conn, 1);
    } else {
        PQsetnonblocking(conn, 0);
    }

    SW_LOOP {
        int r = PQconnectPoll(conn);
        if (r == PGRES_POLLING_OK || r == PGRES_POLLING_FAILED) {
            break;
        }
        swEventType event;

        switch (r) {
        case PGRES_POLLING_READING:
            event = SW_EVENT_READ;
            break;
        case PGRES_POLLING_WRITING:
            event = SW_EVENT_WRITE;
            break;
        default:
            // should not be here including PGRES_POLLING_ACTIVE
            abort();
            break;
        }

        if (swoole_pgsql_socket_poll(conn, event) <= 0) {
            break;
        }
    }

    return conn;
}

PGresult *swoole_pgsql_prepare(
    PGconn *conn, const char *stmt_name, const char *query, int n_params, const Oid *param_types) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendPrepare(conn=%p, stmt_name='%s')", conn, stmt_name);
    int ret = PQsendPrepare(conn, stmt_name, query, n_params, param_types);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec_prepared(PGconn *conn,
                                     const char *stmt_name,
                                     int n_params,
                                     const char *const *param_values,
                                     const int *param_lengths,
                                     const int *param_formats,
                                     int result_format) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQueryPrepared(conn=%p, stmt_name='%s')", conn, stmt_name);
    int ret = PQsendQueryPrepared(conn, stmt_name, n_params, param_values, param_lengths, param_formats, result_format);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec(PGconn *conn, const char *query) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQuery(conn=%p, query='%s')", conn, query);
    int ret = PQsendQuery(conn, query);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec_params(PGconn *conn,
                                   const char *command,
                                   int n_params,
                                   const Oid *param_types,
                                   const char *const *param_values,
                                   const int *param_lengths,
                                   const int *param_formats,
                                   int result_format) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQueryParams(conn=%p, command='%s')", conn, command);
    int ret = PQsendQueryParams(
        conn, command, n_params, param_types, param_values, param_lengths, param_formats, result_format);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

void swoole_pgsql_set_blocking(bool blocking) {
    swoole_pgsql_blocking = blocking;
}

void php_swoole_pgsql_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("PGSQL_ATTR_DISABLE_PREPARES")) ==
        nullptr) {
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_ATTR_DISABLE_PREPARES", PDO_PGSQL_ATTR_DISABLE_PREPARES);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_IDLE", (zend_long) PGSQL_TRANSACTION_IDLE);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_ACTIVE", (zend_long) PGSQL_TRANSACTION_ACTIVE);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_INTRANS", (zend_long) PGSQL_TRANSACTION_INTRANS);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_INERROR", (zend_long) PGSQL_TRANSACTION_INERROR);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_UNKNOWN", (zend_long) PGSQL_TRANSACTION_UNKNOWN);
    }
    php_pdo_unregister_driver(&swoole_pdo_pgsql_driver);
    php_pdo_register_driver(&swoole_pdo_pgsql_driver);
}

void php_swoole_pgsql_mshutdown(void) {
    php_pdo_unregister_driver(&swoole_pdo_pgsql_driver);
}

#endif
