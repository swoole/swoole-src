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
#ifndef SWOOLE_SRC_PHP_SWOOLE_FIREBIRD_H
#define SWOOLE_SRC_PHP_SWOOLE_FIREBIRD_H

#include "php_swoole.h"

#ifdef SW_USE_FIREBIRD

BEGIN_EXTERN_C()

#include "ext/pdo/php_pdo_driver.h"

#include "thirdparty/php84/pdo_firebird/php_pdo_firebird_int.h"

extern const pdo_driver_t swoole_pdo_firebird_driver;
void swoole_firebird_set_blocking(bool blocking);

ISC_STATUS swoole_isc_attach_database(
    ISC_STATUS *, short, const ISC_SCHAR *, isc_db_handle *, short, const ISC_SCHAR *);
ISC_STATUS swoole_isc_detach_database(ISC_STATUS *, isc_db_handle *);
ISC_STATUS swoole_isc_dsql_execute(ISC_STATUS *, isc_tr_handle *, isc_stmt_handle *, unsigned short, const XSQLDA *);
ISC_STATUS swoole_isc_dsql_execute2(
    ISC_STATUS *, isc_tr_handle *, isc_stmt_handle *, unsigned short, const XSQLDA *, const XSQLDA *);
ISC_STATUS swoole_isc_dsql_sql_info(ISC_STATUS *, isc_stmt_handle *, short, const ISC_SCHAR *, short, ISC_SCHAR *);
ISC_STATUS swoole_isc_dsql_free_statement(ISC_STATUS *, isc_stmt_handle *, unsigned short);
ISC_STATUS swoole_isc_start_transaction(ISC_STATUS *, isc_tr_handle *, short, isc_db_handle *, size_t, char *);
ISC_STATUS swoole_isc_commit_retaining(ISC_STATUS *, isc_tr_handle *);
ISC_STATUS swoole_isc_commit_transaction(ISC_STATUS *, isc_tr_handle *);
ISC_STATUS swoole_isc_rollback_transaction(ISC_STATUS *, isc_tr_handle *);
ISC_STATUS swoole_isc_dsql_allocate_statement(ISC_STATUS *, isc_db_handle *, isc_stmt_handle *);
ISC_STATUS swoole_isc_dsql_prepare(
    ISC_STATUS *, isc_tr_handle *, isc_stmt_handle *, unsigned short, const ISC_SCHAR *, unsigned short, XSQLDA *);
ISC_STATUS swoole_isc_dsql_fetch(ISC_STATUS *, isc_stmt_handle *, unsigned short, const XSQLDA *);
ISC_STATUS swoole_isc_open_blob(ISC_STATUS *, isc_db_handle *, isc_tr_handle *, isc_blob_handle *, ISC_QUAD *);
ISC_STATUS swoole_isc_blob_info(ISC_STATUS *, isc_blob_handle *, short, const ISC_SCHAR *, short, ISC_SCHAR *);
ISC_STATUS swoole_isc_get_segment(ISC_STATUS *, isc_blob_handle *, unsigned short *, unsigned short, ISC_SCHAR *);
ISC_STATUS swoole_isc_put_segment(ISC_STATUS *, isc_blob_handle *, unsigned short, const ISC_SCHAR *);
ISC_STATUS swoole_isc_close_blob(ISC_STATUS *, isc_blob_handle *);
ISC_STATUS swoole_isc_create_blob(ISC_STATUS *, isc_db_handle *, isc_tr_handle *, isc_blob_handle *, ISC_QUAD *);
ISC_STATUS swoole_isc_dsql_set_cursor_name(ISC_STATUS *, isc_stmt_handle *, const ISC_SCHAR *, unsigned short);
ISC_STATUS swoole_fb_ping(ISC_STATUS *, isc_db_handle *);
int swoole_isc_version(isc_db_handle *, ISC_VERSION_CALLBACK, void *);

#ifdef SW_USE_FIREBIRD_HOOK
#define isc_attach_database swoole_isc_attach_database
#define isc_detach_database swoole_isc_detach_database
#define isc_dsql_execute swoole_isc_dsql_execute
#define isc_dsql_execute2 swoole_isc_dsql_execute2
#define isc_dsql_sql_info swoole_isc_dsql_sql_info
#define isc_dsql_free_statement swoole_isc_dsql_free_statement
#define isc_start_transaction swoole_isc_start_transaction
#define isc_commit_retaining swoole_isc_commit_retaining
#define isc_commit_transaction swoole_isc_commit_transaction
#define isc_rollback_transaction swoole_isc_rollback_transaction
#define isc_dsql_allocate_statement swoole_isc_dsql_allocate_statement
#define isc_dsql_prepare swoole_isc_dsql_prepare
#define isc_dsql_fetch swoole_isc_dsql_fetch
#define isc_open_blob swoole_isc_open_blob
#define isc_blob_info swoole_isc_blob_info
#define isc_get_segment swoole_isc_get_segment
#define isc_put_segment swoole_isc_put_segment
#define isc_create_blob swoole_isc_create_blob
#define isc_close_blob swoole_isc_close_blob
#define isc_dsql_set_cursor_name swoole_isc_dsql_set_cursor_name
#define fb_ping swoole_fb_ping
#define isc_version swoole_isc_version
#endif
END_EXTERN_C()
#endif
#endif
