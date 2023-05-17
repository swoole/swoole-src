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

#ifndef PHP_SWOOLE_ORACLE_H
#define PHP_SWOOLE_ORACLE_H
#include "php_swoole.h"

#ifdef SW_USE_ORACLE

BEGIN_EXTERN_C()

#include "ext/pdo/php_pdo_driver.h"
#if PHP_VERSION_ID > 80100
#include "thirdparty/php81/pdo_oci/php_pdo_oci_int.h"
#else
#include "thirdparty/php80/pdo_oci/php_pdo_oci_int.h"
#endif

#define SW_PREFIX "SW_"

extern const pdo_driver_t swoole_pdo_oci_driver;

void swoole_oracle_set_blocking(bool blocking);
sword swoole_oci_session_begin(OCISvcCtx *svchp, OCIError *errhp, OCISession *usrhp, ub4 credt, ub4 mode);
sword swoole_oci_server_detach(OCIServer *srvhp, OCIError *errhp, ub4 mode);
sword swoole_oci_stmt_prepare(
    OCIStmt *stmtp, OCIError *errhp, const OraText *stmt, ub4 stmt_len, ub4 language, ub4 mode);
sword swoole_oci_stmt_execute(OCISvcCtx *svchp,
                              OCIStmt *stmtp,
                              OCIError *errhp,
                              ub4 iters,
                              ub4 rowoff,
                              const OCISnapshot *snap_in,
                              OCISnapshot *snap_out,
                              ub4 mode);
sword swoole_oci_stmt_fetch(OCIStmt *stmtp, OCIError *errhp, ub4 nrows, ub2 orientation, ub4 mode);
sword swoole_oci_stmt_fetch2(OCIStmt *stmtp, OCIError *errhp, ub4 nrows, ub2 orientation, sb4 scrollOffset, ub4 mode);
sword swoole_oci_trans_commit(OCISvcCtx *svchp, OCIError *errhp, ub4 flags);
sword swoole_oci_trans_rollback(OCISvcCtx *svchp, OCIError *errhp, ub4 flags);
sword swoole_oci_ping(OCISvcCtx *svchp, OCIError *errhp, ub4 mode);

#ifdef SW_USE_ORACLE_HOOK
#define SW_OCISessionBegin swoole_oci_session_begin
#define SW_OCIServerDetach swoole_oci_server_detach
#define SW_OCIStmtPrepare swoole_oci_stmt_prepare
#define SW_OCIStmtExecute swoole_oci_stmt_execute
#define SW_OCIStmtFetch swoole_oci_stmt_fetch
#define SW_OCIStmtFetch2 swoole_oci_stmt_fetch2
#define SW_OCITransCommit swoole_oci_trans_commit
#define SW_OCITransRollback swoole_oci_trans_rollback
#define SW_OCIPing swoole_oci_ping
#else
#define SW_OCISessionBegin OCISessionBegin
#define SW_OCIServerDetach OCIServerDetach
#define SW_OCIStmtPrepare OCIStmtPrepare
#define SW_OCIStmtExecute OCIStmtExecute
#define SW_OCIStmtFetch OCIStmtFetch
#define SW_OCIStmtFetch2 OCIStmtFetch2
#define SW_OCITransCommit OCITransCommit
#define SW_OCITransRollback OCITransRollback
#define SW_OCIPing OCIPing
#endif

END_EXTERN_C()
#endif
#endif
