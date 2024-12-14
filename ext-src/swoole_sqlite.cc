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
 | Author: NathanFreeman  <mariasocute@163.com>                         |
 +----------------------------------------------------------------------+
*/
#include "php_swoole_private.h"
#include "php_swoole_cxx.h"
#include "swoole_coroutine.h"
#include "php_swoole_sqlite.h"

#ifdef SW_USE_SQLITE
using swoole::Coroutine;

static SW_THREAD_LOCAL bool swoole_sqlite_blocking = true;

void swoole_sqlite_set_blocking(bool blocking) {
    if (blocking) {
        swoole_sqlite_blocking = blocking;
        return;
    }

    int thread_safe_mode = sqlite3_threadsafe();
    if (!thread_safe_mode) {
        swoole_warning("hook sqlite coroutine failed because thread safe mode is single-thread.");
        return;
    }
    swoole_sqlite_blocking = blocking;
}

int swoole_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_open_v2");

    if (!swoole_sqlite_blocking && Coroutine::get_current()) {
        flags |= SQLITE_OPEN_FULLMUTEX;
    }

    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_open_v2(filename, ppDb, flags, zVfs); });

    return result;
}

int swoole_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_prepare_v2");
    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail); });

    return result;
}

int swoole_sqlite3_exec(
    sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *argument, char **errmsg) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_exec");
    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_exec(db, sql, callback, argument, errmsg); });

    return result;
}

int swoole_sqlite3_close(sqlite3 *db) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_close");
    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_close(db); });

    return result;
}

int swoole_sqlite3_close_v2(sqlite3 *db) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_close_v2");
    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_close_v2(db); });

    return result;
}

int swoole_sqlite3_step(sqlite3_stmt *stmt) {
    swoole_trace_log(SW_TRACE_CO_SQLITE, "sqlite3_step");
    int result = 0;
    php_swoole_async(swoole_sqlite_blocking, [&]() { result = sqlite3_step(stmt); });

    return result;
}

void php_swoole_sqlite_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("SQLITE_ATTR_OPEN_FLAGS")) == nullptr) {
#ifdef SQLITE_DETERMINISTIC
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_DETERMINISTIC", (zend_long) SQLITE_DETERMINISTIC);
#endif

        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_ATTR_OPEN_FLAGS", (zend_long) PDO_SQLITE_ATTR_OPEN_FLAGS);
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_OPEN_READONLY", (zend_long) SQLITE_OPEN_READONLY);
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_OPEN_READWRITE", (zend_long) SQLITE_OPEN_READWRITE);
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_OPEN_CREATE", (zend_long) SQLITE_OPEN_CREATE);
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_ATTR_READONLY_STATEMENT", (zend_long) PDO_SQLITE_ATTR_READONLY_STATEMENT);
        REGISTER_PDO_CLASS_CONST_LONG("SQLITE_ATTR_EXTENDED_RESULT_CODES",
                                      (zend_long) PDO_SQLITE_ATTR_EXTENDED_RESULT_CODES);
    }

    php_pdo_unregister_driver(&swoole_pdo_sqlite_driver);
    php_pdo_register_driver(&swoole_pdo_sqlite_driver);
}

void php_swoole_sqlite_mshutdown(void) {
    php_pdo_unregister_driver(&swoole_pdo_sqlite_driver);
}
#endif
