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
#include "php_swoole_oracle.h"

#ifdef SW_USE_ORACLE

static SW_THREAD_LOCAL bool swoole_oracle_blocking = true;
void swoole_oracle_set_blocking(bool blocking) {
    swoole_oracle_blocking = blocking;
}

sword swoole_oci_session_begin(OCISvcCtx *svchp, OCIError *errhp, OCISession *usrhp, ub4 credt, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_session_begin");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCISessionBegin(svchp, errhp, usrhp, credt, mode); });

    return result;
}

sword swoole_oci_server_detach(OCIServer *srvhp, OCIError *errhp, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_server_detach");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCIServerDetach(srvhp, errhp, mode); });

    return result;
}

sword swoole_oci_stmt_prepare(
    OCIStmt *stmtp, OCIError *errhp, const OraText *stmt, ub4 stmt_len, ub4 language, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_stmt_prepare");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking,
                     [&]() { result = OCIStmtPrepare(stmtp, errhp, stmt, stmt_len, language, mode); });

    return result;
}

sword swoole_oci_stmt_execute(OCISvcCtx *svchp,
                              OCIStmt *stmtp,
                              OCIError *errhp,
                              ub4 iters,
                              ub4 rowoff,
                              const OCISnapshot *snap_in,
                              OCISnapshot *snap_out,
                              ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_stmt_execute");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking,
                     [&]() { result = OCIStmtExecute(svchp, stmtp, errhp, iters, rowoff, snap_in, snap_out, mode); });

    return result;
}

sword swoole_oci_stmt_fetch(OCIStmt *stmtp, OCIError *errhp, ub4 nrows, ub2 orientation, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_stmt_fetch");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCIStmtFetch(stmtp, errhp, nrows, orientation, mode); });

    return result;
}

sword swoole_oci_stmt_fetch2(OCIStmt *stmtp, OCIError *errhp, ub4 nrows, ub2 orientation, sb4 scrollOffset, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_stmt_fetch2");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking,
                     [&]() { result = OCIStmtFetch2(stmtp, errhp, nrows, orientation, scrollOffset, mode); });

    return result;
}

sword swoole_oci_trans_commit(OCISvcCtx *svchp, OCIError *errhp, ub4 flags) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_trans_commit");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCITransCommit(svchp, errhp, flags); });

    return result;
}

sword swoole_oci_trans_rollback(OCISvcCtx *svchp, OCIError *errhp, ub4 flags) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_trans_rollback");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCITransRollback(svchp, errhp, flags); });

    return result;
}

sword swoole_oci_ping(OCISvcCtx *svchp, OCIError *errhp, ub4 mode) {
    swoole_trace_log(SW_TRACE_CO_ORACLE, "oci_ping");
    sword result = 0;
    php_swoole_async(swoole_oracle_blocking, [&]() { result = OCIPing(svchp, errhp, mode); });

    return result;
}

const ub4 SWOOLE_PDO_OCI_INIT_MODE = OCI_DEFAULT | OCI_THREADED
#ifdef OCI_OBJECT
                                     | OCI_OBJECT
#endif
    ;

OCIEnv *swoole_pdo_oci_Env = NULL;

void php_swoole_oracle_rinit() {
    if (!swoole_pdo_oci_Env) {
#ifdef HAVE_OCIENVCREATE
        OCIEnvCreate(&swoole_pdo_oci_Env, SWOOLE_PDO_OCI_INIT_MODE, NULL, NULL, NULL, NULL, 0, NULL);
#else
        OCIInitialize(SWOOLE_PDO_OCI_INIT_MODE, NULL, NULL, NULL, NULL);
        OCIEnvInit(&swoole_pdo_oci_Env, OCI_DEFAULT, 0, NULL);
#endif
    }
}

void php_swoole_oracle_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("OCI_ATTR_ACTION")) == nullptr) {
        REGISTER_PDO_CLASS_CONST_LONG("OCI_ATTR_ACTION", (zend_long) PDO_OCI_ATTR_ACTION);
        REGISTER_PDO_CLASS_CONST_LONG("OCI_ATTR_CLIENT_INFO", (zend_long) PDO_OCI_ATTR_CLIENT_INFO);
        REGISTER_PDO_CLASS_CONST_LONG("OCI_ATTR_CLIENT_IDENTIFIER", (zend_long) PDO_OCI_ATTR_CLIENT_IDENTIFIER);
        REGISTER_PDO_CLASS_CONST_LONG("OCI_ATTR_MODULE", (zend_long) PDO_OCI_ATTR_MODULE);
        REGISTER_PDO_CLASS_CONST_LONG("OCI_ATTR_CALL_TIMEOUT", (zend_long) PDO_OCI_ATTR_CALL_TIMEOUT);
    }

    php_pdo_unregister_driver(&swoole_pdo_oci_driver);
    php_pdo_register_driver(&swoole_pdo_oci_driver);
}

void php_swoole_oracle_mshutdown(void) {
    php_pdo_unregister_driver(&swoole_pdo_oci_driver);

    if (!swoole_pdo_oci_Env) {
        OCIHandleFree((dvoid *) swoole_pdo_oci_Env, OCI_HTYPE_ENV);
    }
}
#endif
