/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
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

#ifndef PHP_SWOOLE_PGSQL_H
#define PHP_SWOOLE_PGSQL_H

#include "php_swoole.h"

#ifdef SW_USE_PGSQL

BEGIN_EXTERN_C()

#include "ext/pdo/php_pdo_driver.h"

#if PHP_VERSION_ID >= 80000 && PHP_VERSION_ID < 80100
#include "thirdparty/php80/pdo_pgsql/php_pdo_pgsql_int.h"
#elif PHP_VERSION_ID >= 80100 && PHP_VERSION_ID < 80200
#include "thirdparty/php81/pdo_pgsql/php_pdo_pgsql_int.h"
#elif PHP_VERSION_ID >= 80200 && PHP_VERSION_ID < 80300
#include "thirdparty/php81/pdo_pgsql/php_pdo_pgsql_int.h"
#elif PHP_VERSION_ID >= 80300 && PHP_VERSION_ID < 80400
#include "thirdparty/php83/pdo_pgsql/php_pdo_pgsql_int.h"
#else
#include "thirdparty/php84/pdo_pgsql/php_pdo_pgsql_int.h"
#endif


extern const pdo_driver_t swoole_pdo_pgsql_driver;

#include <libpq-fe.h>
#include <libpq/libpq-fs.h>

void swoole_pgsql_set_blocking(bool blocking);

PGconn *swoole_pgsql_connectdb(const char *conninfo);
PGresult *swoole_pgsql_prepare(PGconn *conn, const char *stmt_name, const char *query, int n_params, const Oid *param_types);
PGresult *swoole_pgsql_exec_prepared(PGconn *conn, const char *stmt_name, int n_params,
    const char *const *param_values, const int *param_lengths, const int *param_formats, int result_format);
PGresult *swoole_pgsql_exec(PGconn *conn, const char *query);
PGresult *swoole_pgsql_exec_params(PGconn *conn, const char *command, int n_params,
    const Oid *param_types, const char *const *param_values, const int *param_lengths, const int *param_formats, int result_format);

#ifdef SW_USE_PGSQL_HOOK
#define PQconnectdb  swoole_pgsql_connectdb
#define PQprepare  swoole_pgsql_prepare
#define PQexecPrepared  swoole_pgsql_exec_prepared
#define PQexec  swoole_pgsql_exec
#define PQexecParams  swoole_pgsql_exec_params
#endif

END_EXTERN_C()

#endif
#endif
