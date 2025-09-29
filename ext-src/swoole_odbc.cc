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

#include "php_swoole_odbc.h"
#include "php_swoole_cxx.h"
#include "php_swoole_private.h"
#include "php_swoole_cxx.h"
#include "swoole_coroutine_system.h"

#ifdef SW_USE_ODBC

static SW_THREAD_LOCAL bool swoole_odbc_blocking = true;

#ifdef SQL_ATTR_CONNECTION_POOLING
zend_ulong pdo_odbc_pool_on = SQL_CP_OFF;
zend_ulong pdo_odbc_pool_mode = SQL_CP_ONE_PER_HENV;
#endif

void swoole_odbc_set_blocking(bool blocking) {
    swoole_odbc_blocking = blocking;
}

RETCODE swoole_odbc_SQLConnect(SQLHDBC ConnectionHandle,
                               SQLCHAR *ServerName,
                               SQLSMALLINT NameLength1,
                               SQLCHAR *UserName,
                               SQLSMALLINT NameLength2,
                               SQLCHAR *Authentication,
                               SQLSMALLINT NameLength3) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLConnect(server=%s)", ServerName);
    php_swoole_async(swoole_odbc_blocking, [&]() {
        rc = SQLConnect(ConnectionHandle, ServerName, NameLength1, UserName, NameLength2, Authentication, NameLength3);
    });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLDriverConnect(SQLHDBC hdbc,
                                               SQLHWND hwnd,
                                               SQLCHAR *szConnStrIn,
                                               SQLSMALLINT cbConnStrIn,
                                               SQLCHAR *szConnStrOut,
                                               SQLSMALLINT cbConnStrOutMax,
                                               SQLSMALLINT *pcbConnStrOut,
                                               SQLUSMALLINT fDriverCompletion) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLDriverConnect");
    php_swoole_async(swoole_odbc_blocking, [&]() {
        rc = SQLDriverConnect(
            hdbc, hwnd, szConnStrIn, cbConnStrIn, szConnStrOut, cbConnStrOutMax, pcbConnStrOut, fDriverCompletion);
    });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLExecDirect");
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLExecDirect(StatementHandle, StatementText, TextLength); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLGetInfo(SQLHDBC ConnectionHandle,
                                         SQLUSMALLINT InfoType,
                                         SQLPOINTER InfoValue,
                                         SQLSMALLINT BufferLength,
                                         SQLSMALLINT *StringLength) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLGetInfo");
    rc = SQLGetInfo(ConnectionHandle, InfoType, InfoValue, BufferLength, StringLength);
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLGetDiagRec(SQLSMALLINT HandleType,
                                            SQLHANDLE Handle,
                                            SQLSMALLINT RecNumber,
                                            SQLCHAR *Sqlstate,
                                            SQLINTEGER *NativeError,
                                            SQLCHAR *MessageText,
                                            SQLSMALLINT BufferLength,
                                            SQLSMALLINT *TextLength) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLGetInfo");
    rc = SQLGetDiagRec(HandleType, Handle, RecNumber, Sqlstate, NativeError, MessageText, BufferLength, TextLength);
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLPrepare(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLPrepare(StatementText=%s)", StatementText);
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLPrepare(StatementHandle, StatementText, TextLength); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLExecute(SQLHSTMT StatementHandle) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLExecute");
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLExecute(StatementHandle); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLCloseCursor(SQLHSTMT StatementHandle) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLCloseCursor");
    rc = SQLCloseCursor(StatementHandle);
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLPutData(SQLHSTMT StatementHandle, SQLPOINTER Data, SQLLEN StrLen_or_Ind) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLPutData");
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLPutData(StatementHandle, Data, StrLen_or_Ind); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLGetData(SQLHSTMT StatementHandle,
                                         SQLUSMALLINT ColumnNumber,
                                         SQLSMALLINT TargetType,
                                         SQLPOINTER TargetValue,
                                         SQLLEN BufferLength,
                                         SQLLEN *StrLen_or_Ind) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLPutData");
    php_swoole_async(swoole_odbc_blocking, [&]() {
        rc = SQLGetData(StatementHandle, ColumnNumber, TargetType, TargetValue, BufferLength, StrLen_or_Ind);
    });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLMoreResults(SQLHSTMT hstmt) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLMoreResults");
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLMoreResults(hstmt); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLDescribeCol(SQLHSTMT StatementHandle,
                                             SQLUSMALLINT ColumnNumber,
                                             SQLCHAR *ColumnName,
                                             SQLSMALLINT BufferLength,
                                             SQLSMALLINT *NameLength,
                                             SQLSMALLINT *DataType,
                                             SQLULEN *ColumnSize,
                                             SQLSMALLINT *DecimalDigits,
                                             SQLSMALLINT *Nullable) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLMoreResults");
    php_swoole_async(swoole_odbc_blocking, [&]() {
        rc = SQLDescribeCol(StatementHandle,
                            ColumnNumber,
                            ColumnName,
                            BufferLength,
                            NameLength,
                            DataType,
                            ColumnSize,
                            DecimalDigits,
                            Nullable);
    });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLRowCount(SQLHSTMT StatementHandle, SQLLEN *RowCount) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLRowCount");
    rc = SQLRowCount(StatementHandle, RowCount);
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLFreeHandle");
    rc = SQLFreeHandle(HandleType, Handle);
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLEndTran(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT CompletionType) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLEndTran(CompletionType=%d)", CompletionType);
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLEndTran(HandleType, Handle, CompletionType); });
    return rc;
}

SQLRETURN SQL_API swoole_odbc_SQLDisconnect(SQLHDBC ConnectionHandle) {
    RETCODE rc;
    swoole_trace_log(SW_TRACE_CO_ODBC, "SQLDisconnect");
    php_swoole_async(swoole_odbc_blocking, [&]() { rc = SQLDisconnect(ConnectionHandle); });
    return rc;
}

int php_swoole_odbc_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("ODBC_ATTR_USE_CURSOR_LIBRARY")) ==
        nullptr) {
#ifdef SQL_ATTR_CONNECTION_POOLING
        const char *pooling_val = NULL;
#endif

#ifdef SQL_ATTR_CONNECTION_POOLING
        /* ugh, we don't really like .ini stuff in PDO, but since ODBC connection
         * pooling is process wide, we can't set it from within the scope of a
         * request without affecting others, which goes against our isolated request
         * policy.  So, we use cfg_get_string here to check it this once.
         * */
        if (FAILURE == cfg_get_string("pdo_odbc.connection_pooling", (char **) &pooling_val) || pooling_val == NULL) {
            pooling_val = "strict";
        }
        if (strcasecmp(pooling_val, "strict") == 0 || strcmp(pooling_val, "1") == 0) {
            pdo_odbc_pool_on = SQL_CP_ONE_PER_HENV;
            pdo_odbc_pool_mode = SQL_CP_STRICT_MATCH;
        } else if (strcasecmp(pooling_val, "relaxed") == 0) {
            pdo_odbc_pool_on = SQL_CP_ONE_PER_HENV;
            pdo_odbc_pool_mode = SQL_CP_RELAXED_MATCH;
        } else if (*pooling_val == '\0' || strcasecmp(pooling_val, "off") == 0) {
            pdo_odbc_pool_on = SQL_CP_OFF;
        } else {
            php_error_docref(NULL,
                             E_CORE_ERROR,
                             "Error in pdo_odbc.connection_pooling configuration. Value must be one of \"strict\", "
                             "\"relaxed\", or \"off\"");
            return FAILURE;
        }

        if (pdo_odbc_pool_on != SQL_CP_OFF) {
            SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void *) pdo_odbc_pool_on, 0);
        }
#endif

        REGISTER_PDO_CLASS_CONST_LONG("ODBC_ATTR_USE_CURSOR_LIBRARY", PDO_ODBC_ATTR_USE_CURSOR_LIBRARY);
        REGISTER_PDO_CLASS_CONST_LONG("ODBC_ATTR_ASSUME_UTF8", PDO_ODBC_ATTR_ASSUME_UTF8);
        REGISTER_PDO_CLASS_CONST_LONG("ODBC_SQL_USE_IF_NEEDED", SQL_CUR_USE_IF_NEEDED);
        REGISTER_PDO_CLASS_CONST_LONG("ODBC_SQL_USE_DRIVER", SQL_CUR_USE_DRIVER);
        REGISTER_PDO_CLASS_CONST_LONG("ODBC_SQL_USE_ODBC", SQL_CUR_USE_ODBC);
    }

    php_pdo_unregister_driver(&swoole_pdo_odbc_driver);
    php_pdo_register_driver(&swoole_pdo_odbc_driver);

    return SUCCESS;
}

void php_swoole_odbc_mshutdown(void) {
    php_pdo_unregister_driver(&swoole_pdo_odbc_driver);
}

#endif
