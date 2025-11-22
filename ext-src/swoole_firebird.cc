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

#ifdef SW_USE_FIREBIRD
#include "php_swoole_firebird.h"

using swoole::Coroutine;

static SW_THREAD_LOCAL bool swoole_firebird_blocking = true;

void swoole_firebird_set_blocking(bool blocking) {
    swoole_firebird_blocking = blocking;
}

ISC_STATUS swoole_isc_attach_database(
    ISC_STATUS *_0, short _1, const ISC_SCHAR *_2, isc_db_handle *_3, short _4, const ISC_SCHAR *_5) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_attach_database");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_attach_database(_0, _1, _2, _3, _4, _5); });

    return result;
}

ISC_STATUS swoole_isc_detach_database(ISC_STATUS *_0, isc_db_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_detach_database");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_detach_database(_0, _1); });

    return result;
}

ISC_STATUS swoole_isc_dsql_execute(
    ISC_STATUS *_0, isc_tr_handle *_1, isc_stmt_handle *_2, unsigned short _3, const XSQLDA *_4) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_execute");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_execute(_0, _1, _2, _3, _4); });

    return result;
}

ISC_STATUS swoole_isc_dsql_execute2(
    ISC_STATUS *_0, isc_tr_handle *_1, isc_stmt_handle *_2, unsigned short _3, const XSQLDA *_4, const XSQLDA *_5) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_execute2");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_execute2(_0, _1, _2, _3, _4, _5); });

    return result;
}

ISC_STATUS swoole_isc_dsql_sql_info(
    ISC_STATUS *_0, isc_stmt_handle *_1, short _2, const ISC_SCHAR *_3, short _4, ISC_SCHAR *_5) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_sql_info");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_sql_info(_0, _1, _2, _3, _4, _5); });

    return result;
}

ISC_STATUS swoole_isc_dsql_free_statement(ISC_STATUS *_0, isc_stmt_handle *_1, unsigned short _2) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_free_statement");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_free_statement(_0, _1, _2); });

    return result;
}

ISC_STATUS swoole_isc_start_transaction(
    ISC_STATUS *_0, isc_tr_handle *_1, short _2, isc_db_handle *_3, size_t _4, char *_5) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_start_transaction");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_start_transaction(_0, _1, _2, _3, _4, _5); });

    return result;
}

ISC_STATUS swoole_isc_commit_retaining(ISC_STATUS *_0, isc_tr_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_commit_retaining");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_commit_retaining(_0, _1); });

    return result;
}

ISC_STATUS swoole_isc_commit_transaction(ISC_STATUS *_0, isc_tr_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_commit_transaction");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_commit_transaction(_0, _1); });

    return result;
}

ISC_STATUS swoole_isc_rollback_transaction(ISC_STATUS *_0, isc_tr_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_rollback_transaction");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_rollback_transaction(_0, _1); });

    return result;
}

ISC_STATUS swoole_isc_dsql_allocate_statement(ISC_STATUS *_0, isc_db_handle *_1, isc_stmt_handle *_2) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_allocate_statement");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_allocate_statement(_0, _1, _2); });

    return result;
}

ISC_STATUS swoole_isc_dsql_prepare(ISC_STATUS *_0,
                                   isc_tr_handle *_1,
                                   isc_stmt_handle *_2,
                                   unsigned short _3,
                                   const ISC_SCHAR *_4,
                                   unsigned short _5,
                                   XSQLDA *_6) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_prepare");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_prepare(_0, _1, _2, _3, _4, _5, _6); });

    return result;
}

ISC_STATUS swoole_isc_dsql_fetch(ISC_STATUS *_0, isc_stmt_handle *_1, unsigned short _2, const XSQLDA *_3) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_fetch");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_fetch(_0, _1, _2, _3); });

    return result;
}

ISC_STATUS swoole_isc_open_blob(
    ISC_STATUS *_0, isc_db_handle *_1, isc_tr_handle *_2, isc_blob_handle *_3, ISC_QUAD *_4) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_open_blob");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_open_blob(_0, _1, _2, _3, _4); });

    return result;
}

ISC_STATUS swoole_isc_blob_info(
    ISC_STATUS *_0, isc_blob_handle *_1, short _2, const ISC_SCHAR *_3, short _4, ISC_SCHAR *_5) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_blob_info");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_blob_info(_0, _1, _2, _3, _4, _5); });

    return result;
}

ISC_STATUS swoole_isc_get_segment(
    ISC_STATUS *_0, isc_blob_handle *_1, unsigned short *_2, unsigned short _3, ISC_SCHAR *_4) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_get_segment");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_get_segment(_0, _1, _2, _3, _4); });

    return result;
}

ISC_STATUS swoole_isc_put_segment(ISC_STATUS *_0, isc_blob_handle *_1, unsigned short _2, const ISC_SCHAR *_3) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_put_segment");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_put_segment(_0, _1, _2, _3); });

    return result;
}

ISC_STATUS swoole_isc_create_blob(
    ISC_STATUS *_0, isc_db_handle *_1, isc_tr_handle *_2, isc_blob_handle *_3, ISC_QUAD *_4) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_create_blob");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_create_blob(_0, _1, _2, _3, _4); });

    return result;
}

ISC_STATUS swoole_isc_close_blob(ISC_STATUS *_0, isc_blob_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_close_blob");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_close_blob(_0, _1); });

    return result;
}

ISC_STATUS swoole_isc_dsql_set_cursor_name(ISC_STATUS *_0,
                                           isc_stmt_handle *_1,
                                           const ISC_SCHAR *_2,
                                           unsigned short _3) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_dsql_set_cursor_name");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_dsql_set_cursor_name(_0, _1, _2, _3); });

    return result;
}

ISC_STATUS swoole_fb_ping(ISC_STATUS *_0, isc_db_handle *_1) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "fb_ping");

    ISC_STATUS result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = fb_ping(_0, _1); });

    return result;
}

int swoole_isc_version(isc_db_handle *_0, ISC_VERSION_CALLBACK _1, void *_2) {
    swoole_trace_log(SW_TRACE_CO_FIREBIRD, "isc_version");

    int result;
    php_swoole_async(swoole_firebird_blocking, [&]() { result = isc_version(_0, _1, _2); });

    return result;
}

void php_swoole_firebird_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("FB_ATTR_DATE_FORMAT")) == nullptr) {
        REGISTER_PDO_CLASS_CONST_LONG("FB_ATTR_DATE_FORMAT", (zend_long) PDO_FB_ATTR_DATE_FORMAT);
        REGISTER_PDO_CLASS_CONST_LONG("FB_ATTR_TIME_FORMAT", (zend_long) PDO_FB_ATTR_TIME_FORMAT);
        REGISTER_PDO_CLASS_CONST_LONG("FB_ATTR_TIMESTAMP_FORMAT", (zend_long) PDO_FB_ATTR_TIMESTAMP_FORMAT);
    }

    php_pdo_unregister_driver(&swoole_pdo_firebird_driver);
    php_pdo_register_driver(&swoole_pdo_firebird_driver);
}

void php_swoole_firebird_mshutdown() {
    php_pdo_unregister_driver(&swoole_pdo_firebird_driver);
}
#endif
