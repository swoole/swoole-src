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
#ifndef SWOOLE_SRC_PHP_SWOOLE_SQLITE_H
#define SWOOLE_SRC_PHP_SWOOLE_SQLITE_H
#include "php_swoole.h"

#ifdef SW_USE_SQLITE

BEGIN_EXTERN_C()

#include "ext/pdo/php_pdo_driver.h"

#if PHP_VERSION_ID >= 80000 && PHP_VERSION_ID < 80100
#include "thirdparty/php80/pdo_sqlite/php_pdo_sqlite_int.h"
#elif PHP_VERSION_ID >= 80100 && PHP_VERSION_ID < 80200
#include "thirdparty/php81/pdo_sqlite/php_pdo_sqlite_int.h"
#elif PHP_VERSION_ID >= 80200 && PHP_VERSION_ID < 80300
#include "thirdparty/php81/pdo_sqlite/php_pdo_sqlite_int.h"
#elif PHP_VERSION_ID >= 80300 && PHP_VERSION_ID < 80400
#include "thirdparty/php83/pdo_sqlite/php_pdo_sqlite_int.h"
#else
#include "thirdparty/php84/pdo_sqlite/php_pdo_sqlite_int.h"
#endif

extern const pdo_driver_t swoole_pdo_sqlite_driver;
void swoole_sqlite_set_blocking(bool blocking);

int swoole_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
int swoole_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int swoole_sqlite3_exec(
    sqlite3 *, const char *sql, int (*callback)(void *, int, char **, char **), void *, char **errmsg);
int swoole_sqlite3_close(sqlite3 *db);
int swoole_sqlite3_close_v2(sqlite3 *db);
int swoole_sqlite3_step(sqlite3_stmt *stmt);

#ifdef SW_USE_SQLITE_HOOK
#define sqlite3_open_v2 swoole_sqlite3_open_v2
#define sqlite3_prepare_v2 swoole_sqlite3_prepare_v2
#define sqlite3_exec swoole_sqlite3_exec
#define sqlite3_close swoole_sqlite3_close
#define sqlite3_close_v2 swoole_sqlite3_close_v2
#define sqlite3_step swoole_sqlite3_step
#endif
END_EXTERN_C()
#endif
#endif
