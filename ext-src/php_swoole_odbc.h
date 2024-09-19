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

#ifndef PHP_SWOOLE_ODBC_H
#define PHP_SWOOLE_ODBC_H

#include "php_swoole.h"

#ifdef SW_USE_ODBC
BEGIN_EXTERN_C()

#include "ext/pdo/php_pdo_driver.h"

#if PHP_VERSION_ID >= 80000 && PHP_VERSION_ID < 80100
#include "thirdparty/php80/pdo_odbc/php_pdo_odbc_int.h"
#elif PHP_VERSION_ID >= 80100 && PHP_VERSION_ID < 80200
#include "thirdparty/php81/pdo_odbc/php_pdo_odbc_int.h"
#elif PHP_VERSION_ID >= 80200 && PHP_VERSION_ID < 80300
#include "thirdparty/php81/pdo_odbc/php_pdo_odbc_int.h"
#elif PHP_VERSION_ID >= 80300 && PHP_VERSION_ID < 80400
#include "thirdparty/php83/pdo_odbc/php_pdo_odbc_int.h"
#else
#include "thirdparty/php84/pdo_odbc/php_pdo_odbc_int.h"
#endif

extern const pdo_driver_t swoole_pdo_odbc_driver;

#include "php_version.h"
#define PHP_PDO_ODBC_VERSION PHP_VERSION

RETCODE swoole_odbc_SQLConnect(SQLHDBC ConnectionHandle,
                               SQLCHAR *ServerName,
                               SQLSMALLINT NameLength1,
                               SQLCHAR *UserName,
                               SQLSMALLINT NameLength2,
                               SQLCHAR *Authentication,
                               SQLSMALLINT NameLength3);

SQLRETURN SQL_API swoole_odbc_SQLDriverConnect(SQLHDBC hdbc,
                                               SQLHWND hwnd,
                                               SQLCHAR *szConnStrIn,
                                               SQLSMALLINT cbConnStrIn,
                                               SQLCHAR *szConnStrOut,
                                               SQLSMALLINT cbConnStrOutMax,
                                               SQLSMALLINT *pcbConnStrOut,
                                               SQLUSMALLINT fDriverCompletion);

SQLRETURN SQL_API swoole_odbc_SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength);

SQLRETURN  SQL_API swoole_odbc_SQLGetInfo(SQLHDBC ConnectionHandle,
                              SQLUSMALLINT InfoType, SQLPOINTER InfoValue,
                              SQLSMALLINT BufferLength, SQLSMALLINT *StringLength);

SQLRETURN  SQL_API swoole_odbc_SQLGetDiagRec(SQLSMALLINT HandleType,
                                            SQLHANDLE Handle,
                                            SQLSMALLINT RecNumber,
                                            SQLCHAR *Sqlstate,
                                            SQLINTEGER *NativeError,
                                            SQLCHAR *MessageText,
                                            SQLSMALLINT BufferLength,
                                            SQLSMALLINT *TextLength);

SQLRETURN SQL_API swoole_odbc_SQLPrepare(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength);

SQLRETURN SQL_API swoole_odbc_SQLExecute(SQLHSTMT StatementHandle);

SQLRETURN SQL_API swoole_odbc_SQLCloseCursor(SQLHSTMT StatementHandle);

SQLRETURN SQL_API swoole_odbc_SQLPutData(SQLHSTMT StatementHandle, SQLPOINTER Data, SQLLEN StrLen_or_Ind);

SQLRETURN  SQL_API swoole_odbc_SQLGetData(SQLHSTMT StatementHandle,
                                  SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType,
                                  SQLPOINTER TargetValue, SQLLEN BufferLength,
                                  SQLLEN *StrLen_or_Ind);

SQLRETURN SQL_API swoole_odbc_SQLRowCount(SQLHSTMT StatementHandle, SQLLEN *RowCount);

SQLRETURN  SQL_API swoole_odbc_SQLDescribeCol(SQLHSTMT StatementHandle,
                                  SQLUSMALLINT ColumnNumber, SQLCHAR *ColumnName,
                                  SQLSMALLINT BufferLength, SQLSMALLINT *NameLength,
                                  SQLSMALLINT *DataType, SQLULEN *ColumnSize,
                                  SQLSMALLINT *DecimalDigits, SQLSMALLINT *Nullable);

SQLRETURN SQL_API swoole_odbc_SQLMoreResults(
    SQLHSTMT           hstmt);

SQLRETURN SQL_API swoole_odbc_SQLEndTran(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT CompletionType);

SQLRETURN SQL_API swoole_odbc_SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle);

SQLRETURN SQL_API swoole_odbc_SQLDisconnect(SQLHDBC ConnectionHandle);

void swoole_odbc_set_blocking(bool blocking);

#ifdef SW_USE_ODBC_HOOK

#define SQLConnect swoole_odbc_SQLConnect
#define SQLDriverConnect swoole_odbc_SQLDriverConnect
#define SQLExecDirect swoole_odbc_SQLExecDirect
#define SQLGetInfo swoole_odbc_SQLGetInfo
#define SQLGetDiagRec swoole_odbc_SQLGetDiagRec
#define SQLPrepare swoole_odbc_SQLPrepare
#define SQLExecute swoole_odbc_SQLExecute
#define SQLCloseCursor  swoole_odbc_SQLCloseCursor
#define SQLGetData swoole_odbc_SQLGetData
#define SQLPutData swoole_odbc_SQLPutData
#define SQLRowCount swoole_odbc_SQLRowCount
#define SQLDescribeCol swoole_odbc_SQLDescribeCol
#define SQLEndTran swoole_odbc_SQLEndTran
#define SQLFreeHandle swoole_odbc_SQLFreeHandle
#define SQLDisconnect swoole_odbc_SQLDisconnect

#endif
END_EXTERN_C()
#endif
#endif
