/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Edin Kadribasic <edink@emini.dk>                             |
  +----------------------------------------------------------------------+
*/
#include "php_swoole_pgsql.h"

#ifdef SW_USE_PGSQL
#if PHP_VERSION_ID >= 80500
#include "ext/pdo/php_pdo.h"
#include "ext/pdo/php_pdo_error.h"
#include "pdo_pgsql_arginfo.h"

PHP_METHOD(Swoole_Pdo_Pgsql, escapeIdentifier)
{
	zend_string *from = NULL;
	char *tmp;
	pdo_dbh_t *dbh;
	pdo_pgsql_db_handle *H;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &from) == FAILURE) {
		RETURN_THROWS();
	}

	dbh = Z_PDO_DBH_P(ZEND_THIS);
	PDO_CONSTRUCT_CHECK;
	PDO_DBH_CLEAR_ERR();

	/* Obtain db Handle */
	H = (pdo_pgsql_db_handle *)dbh->driver_data;
	if (H->server == NULL) {
		zend_throw_error(NULL, "PostgreSQL connection has already been closed");
		RETURN_THROWS();
	}

	tmp = PQescapeIdentifier(H->server, ZSTR_VAL(from), ZSTR_LEN(from));
	if (!tmp) {
		pdo_pgsql_error(dbh, PGRES_FATAL_ERROR, NULL);
		PDO_HANDLE_DBH_ERR();
		RETURN_THROWS();
	}

	RETVAL_STRING(tmp);
	PQfreemem(tmp);
}

/* Returns true if the copy worked fine or false if error */
PHP_METHOD(Swoole_Pdo_Pgsql, copyFromArray)
{
	pgsqlCopyFromArray_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Returns true if the copy worked fine or false if error */
PHP_METHOD(Swoole_Pdo_Pgsql, copyFromFile)
{
	pgsqlCopyFromFile_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Returns true if the copy worked fine or false if error */
PHP_METHOD(Swoole_Pdo_Pgsql, copyToFile)
{
	pgsqlCopyToFile_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Returns true if the copy worked fine or false if error */
PHP_METHOD(Swoole_Pdo_Pgsql, copyToArray)
{
	pgsqlCopyToArray_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Creates a new large object, returning its identifier.  Must be called inside a transaction. */
PHP_METHOD(Swoole_Pdo_Pgsql, lobCreate)
{
	pgsqlLOBCreate_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Opens an existing large object stream.  Must be called inside a transaction. */
PHP_METHOD(Swoole_Pdo_Pgsql, lobOpen)
{
	pgsqlLOBOpen_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Deletes the large object identified by oid.  Must be called inside a transaction. */
PHP_METHOD(Swoole_Pdo_Pgsql, lobUnlink)
{
	pgsqlLOBUnlink_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Get asynchronous notification */
PHP_METHOD(Swoole_Pdo_Pgsql, getNotify)
{
	pgsqlGetNotify_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Get backend(server) pid */
PHP_METHOD(Swoole_Pdo_Pgsql, getPid)
{
	pgsqlGetPid_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Sets a callback to receive DB notices (after client_min_messages has been set */
PHP_METHOD(Swoole_Pdo_Pgsql, setNoticeCallback)
{
	zend_fcall_info fci = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS(), "F!", &fci, &fcc)) {
		RETURN_THROWS();
	}

	pdo_dbh_t *dbh = Z_PDO_DBH_P(ZEND_THIS);
	PDO_CONSTRUCT_CHECK_WITH_CLEANUP(cleanup);

	{
		pdo_pgsql_db_handle *H = (pdo_pgsql_db_handle *)dbh->driver_data;
		pdo_pgsql_cleanup_notice_callback(H);
		if (ZEND_FCC_INITIALIZED(fcc)) {
			H->notice_callback = emalloc(sizeof(zend_fcall_info_cache));
			zend_fcc_dup(H->notice_callback, &fcc);
		}
	}

	return;

cleanup:
	zend_release_fcall_info_cache(&fcc);
	RETURN_THROWS();
}
#endif
#endif
