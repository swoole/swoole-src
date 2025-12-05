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
  | Author: Wez Furlong <wez@php.net>                                    |
  +----------------------------------------------------------------------+
*/

#define SW_USE_SQLITE_HOOK
#include "php_swoole_sqlite.h"
#include "php_swoole_call_stack.h"

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/pdo/php_pdo.h"
#include "ext/pdo/php_pdo_driver.h"
#include "php_pdo_sqlite.h"
#include "php_pdo_sqlite_int.h"
#include "zend_exceptions.h"

int _pdo_sqlite_error(pdo_dbh_t *dbh, pdo_stmt_t *stmt, const char *file, int line) /* {{{ */
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;
	pdo_error_type *pdo_err = stmt ? &stmt->error_code : &dbh->error_code;
	pdo_sqlite_error_info *einfo = &H->einfo;

	einfo->errcode = sqlite3_errcode(H->db);
	einfo->file = file;
	einfo->line = line;

	if (einfo->errcode != SQLITE_OK) {
		if (einfo->errmsg) {
			pefree(einfo->errmsg, dbh->is_persistent);
		}
		einfo->errmsg = pestrdup((char*)sqlite3_errmsg(H->db), dbh->is_persistent);
	} else { /* no error */
		strncpy(*pdo_err, PDO_ERR_NONE, sizeof(*pdo_err));
		return 0;
	}
	switch (einfo->errcode) {
		case SQLITE_NOTFOUND:
			strncpy(*pdo_err, "42S02", sizeof(*pdo_err));
			break;

		case SQLITE_INTERRUPT:
			strncpy(*pdo_err, "01002", sizeof(*pdo_err));
			break;

		case SQLITE_NOLFS:
			strncpy(*pdo_err, "HYC00", sizeof(*pdo_err));
			break;

		case SQLITE_TOOBIG:
			strncpy(*pdo_err, "22001", sizeof(*pdo_err));
			break;

		case SQLITE_CONSTRAINT:
			strncpy(*pdo_err, "23000", sizeof(*pdo_err));
			break;

		case SQLITE_ERROR:
		default:
			strncpy(*pdo_err, "HY000", sizeof(*pdo_err));
			break;
	}

	if (!dbh->methods) {
		pdo_throw_exception(einfo->errcode, einfo->errmsg, pdo_err);
	}

	return einfo->errcode;
}
/* }}} */

static void pdo_sqlite_fetch_error_func(pdo_dbh_t *dbh, pdo_stmt_t *stmt, zval *info)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;
	pdo_sqlite_error_info *einfo = &H->einfo;

	if (einfo->errcode) {
		add_next_index_long(info, einfo->errcode);
		add_next_index_string(info, einfo->errmsg);
	}
}

static void sqlite_handle_closer(pdo_dbh_t *dbh) /* {{{ */
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	if (H) {
		pdo_sqlite_error_info *einfo = &H->einfo;

		if (H->db) {
#ifdef HAVE_SQLITE3_CLOSE_V2
			sqlite3_close_v2(H->db);
#else
			sqlite3_close(H->db);
#endif
			H->db = NULL;
		}
		if (einfo->errmsg) {
			pefree(einfo->errmsg, dbh->is_persistent);
			einfo->errmsg = NULL;
		}
		pefree(H, dbh->is_persistent);
		dbh->driver_data = NULL;
	}
}
/* }}} */

static bool sqlite_handle_preparer(pdo_dbh_t *dbh, zend_string *sql, pdo_stmt_t *stmt, zval *driver_options)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;
	pdo_sqlite_stmt *S = ecalloc(1, sizeof(pdo_sqlite_stmt));
	int i;
	const char *tail;

	S->H = H;
	stmt->driver_data = S;
	stmt->methods = &swoole_sqlite_stmt_methods;
	stmt->supports_placeholders = PDO_PLACEHOLDER_POSITIONAL|PDO_PLACEHOLDER_NAMED;

	if (PDO_CURSOR_FWDONLY != pdo_attr_lval(driver_options, PDO_ATTR_CURSOR, PDO_CURSOR_FWDONLY)) {
		H->einfo.errcode = SQLITE_ERROR;
		pdo_sqlite_error(dbh);
		return false;
	}

	i = sqlite3_prepare_v2(H->db, ZSTR_VAL(sql), ZSTR_LEN(sql), &S->stmt, &tail);
	if (i == SQLITE_OK) {
		return true;
	}

	pdo_sqlite_error(dbh);

	return false;
}

static zend_long sqlite_handle_doer(pdo_dbh_t *dbh, const zend_string *sql)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	if (sqlite3_exec(H->db, ZSTR_VAL(sql), NULL, NULL, NULL) != SQLITE_OK) {
		pdo_sqlite_error(dbh);
		return -1;
	} else {
		return sqlite3_changes(H->db);
	}
}

static zend_string *pdo_sqlite_last_insert_id(pdo_dbh_t *dbh, const zend_string *name)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	return zend_i64_to_str(sqlite3_last_insert_rowid(H->db));
}

/* NB: doesn't handle binary strings... use prepared stmts for that */
static zend_string* sqlite_handle_quoter(pdo_dbh_t *dbh, const zend_string *unquoted, enum pdo_param_type paramtype)
{
	char *quoted;
	if (ZSTR_LEN(unquoted) > (INT_MAX - 3) / 2) {
		return NULL;
	}

	if (UNEXPECTED(zend_str_has_nul_byte(unquoted))) {
		if (dbh->error_mode == PDO_ERRMODE_EXCEPTION) {
			zend_throw_exception_ex(
				php_pdo_get_exception(), 0,
				"SQLite PDO::quote does not support null bytes");
		} else if (dbh->error_mode == PDO_ERRMODE_WARNING) {
			php_error_docref(NULL, E_WARNING,
				"SQLite PDO::quote does not support null bytes");
		}
		return NULL;
	}

	quoted = safe_emalloc(2, ZSTR_LEN(unquoted), 3);
	/* TODO use %Q format? */
	sqlite3_snprintf(2*ZSTR_LEN(unquoted) + 3, quoted, "'%q'", ZSTR_VAL(unquoted));
	zend_string *quoted_str = zend_string_init(quoted, strlen(quoted), 0);
	efree(quoted);
	return quoted_str;
}

static bool sqlite_handle_begin(pdo_dbh_t *dbh)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	const char *begin_statement = "BEGIN";
	switch (H->transaction_mode) {
		case PDO_SQLITE_TRANSACTION_MODE_DEFERRED:
			begin_statement = "BEGIN DEFERRED TRANSACTION";
			break;
		case PDO_SQLITE_TRANSACTION_MODE_IMMEDIATE:
			begin_statement = "BEGIN IMMEDIATE TRANSACTION";
			break;
		case PDO_SQLITE_TRANSACTION_MODE_EXCLUSIVE:
			begin_statement = "BEGIN EXCLUSIVE TRANSACTION";
			break;
	}

	if (sqlite3_exec(H->db, begin_statement, NULL, NULL, NULL) != SQLITE_OK) {
		pdo_sqlite_error(dbh);
		return false;
	}
	return true;
}

static bool sqlite_handle_commit(pdo_dbh_t *dbh)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	if (sqlite3_exec(H->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		pdo_sqlite_error(dbh);
		return false;
	}
	return true;
}

static bool sqlite_handle_rollback(pdo_dbh_t *dbh)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	if (sqlite3_exec(H->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
		pdo_sqlite_error(dbh);
		return false;
	}
	return true;
}

static int pdo_sqlite_get_attribute(pdo_dbh_t *dbh, zend_long attr, zval *return_value)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;

	switch (attr) {
		case PDO_ATTR_CLIENT_VERSION:
		case PDO_ATTR_SERVER_VERSION:
			ZVAL_STRING(return_value, (char *)sqlite3_libversion());
			break;
		case PDO_SQLITE_ATTR_TRANSACTION_MODE:
			ZVAL_LONG(return_value, H->transaction_mode);
			break;

		default:
			return 0;
	}

	return 1;
}

static bool pdo_sqlite_in_transaction(pdo_dbh_t *dbh)
{
	pdo_sqlite_db_handle* H = (pdo_sqlite_db_handle*) dbh->driver_data;
	/* It's not possible in sqlite3 to explicitly turn autocommit off other
	 * than manually starting a transaction. Manual transactions always are
	 * the mode of operation when autocommit is off. */
	return H->db && sqlite3_get_autocommit(H->db) == 0;
}

static bool pdo_sqlite_set_attr(pdo_dbh_t *dbh, zend_long attr, zval *val)
{
	pdo_sqlite_db_handle *H = (pdo_sqlite_db_handle *)dbh->driver_data;
	zend_long lval;

	switch (attr) {
		case PDO_ATTR_TIMEOUT:
			if (!pdo_get_long_param(&lval, val)) {
				return false;
			}
			sqlite3_busy_timeout(H->db, lval * 1000);
			return true;
		case PDO_SQLITE_ATTR_EXTENDED_RESULT_CODES:
			if (!pdo_get_long_param(&lval, val)) {
				return false;
			}
			sqlite3_extended_result_codes(H->db, lval);
			return true;
		case PDO_SQLITE_ATTR_TRANSACTION_MODE:
			if (!pdo_get_long_param(&lval, val)) {
				return false;
			}
			switch (lval) {
				case PDO_SQLITE_TRANSACTION_MODE_DEFERRED:
				case PDO_SQLITE_TRANSACTION_MODE_IMMEDIATE:
				case PDO_SQLITE_TRANSACTION_MODE_EXCLUSIVE:
					H->transaction_mode = lval;
					return true;
				default:
					return false;
			}
	}
	return false;
}

static void pdo_sqlite_request_shutdown(pdo_dbh_t *dbh)
{
}

static const struct pdo_dbh_methods sqlite_methods = {
	sqlite_handle_closer,
	sqlite_handle_preparer,
	sqlite_handle_doer,
	sqlite_handle_quoter,
	sqlite_handle_begin,
	sqlite_handle_commit,
	sqlite_handle_rollback,
	pdo_sqlite_set_attr,
	pdo_sqlite_last_insert_id,
	pdo_sqlite_fetch_error_func,
	pdo_sqlite_get_attribute,
	NULL,	/* check_liveness: not needed */
	NULL,
	pdo_sqlite_request_shutdown,
	pdo_sqlite_in_transaction,
	NULL,
#if PHP_VERSION_ID >= 80400
	pdo_sqlite_scanner
#endif
};

static char *make_filename_safe(const char *filename)
{
	if (!filename) {
		return NULL;
	}
	if (*filename && strncasecmp(filename, "file:", 5) == 0) {
		if (PG(open_basedir) && *PG(open_basedir)) {
			return NULL;
		}
		return estrdup(filename);
	}
	if (*filename && strcmp(filename, ":memory:")) {
		char *fullpath = expand_filepath(filename, NULL);

		if (!fullpath) {
			return NULL;
		}

		if (php_check_open_basedir(fullpath)) {
			efree(fullpath);
			return NULL;
		}
		return fullpath;
	}
	return estrdup(filename);
}

#define ZVAL_NULLABLE_STRING(zv, str) do { \
	zval *zv_ = zv; \
	const char *str_ = str; \
	if (str_) { \
		ZVAL_STRING(zv_, str_); \
	} else { \
		ZVAL_NULL(zv_); \
	} \
} while (0)

static int pdo_sqlite_handle_factory(pdo_dbh_t *dbh, zval *driver_options) /* {{{ */
{
	pdo_sqlite_db_handle *H;
	int i, ret = 0;
	zend_long timeout = 60, flags;
	char *filename;

	H = pecalloc(1, sizeof(pdo_sqlite_db_handle), dbh->is_persistent);

	H->einfo.errcode = 0;
	H->einfo.errmsg = NULL;
	dbh->driver_data = H;

	/* skip all but this one param event */
	dbh->skip_param_evt = 0x7F ^ (1 << PDO_PARAM_EVT_EXEC_PRE);

	filename = make_filename_safe(dbh->data_source);

	if (!filename) {
		zend_throw_exception_ex(php_pdo_get_exception(), 0,
			"open_basedir prohibits opening %s",
			dbh->data_source);
		goto cleanup;
	}

	flags = pdo_attr_lval(driver_options, PDO_SQLITE_ATTR_OPEN_FLAGS, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

	if (!(PG(open_basedir) && *PG(open_basedir))) {
		flags |= SQLITE_OPEN_URI;
	}
	i = sqlite3_open_v2(filename, &H->db, flags, NULL);

	efree(filename);

	if (i != SQLITE_OK) {
		pdo_sqlite_error(dbh);
		goto cleanup;
	}

	if (driver_options) {
		timeout = pdo_attr_lval(driver_options, PDO_ATTR_TIMEOUT, timeout);
	}
	sqlite3_busy_timeout(H->db, timeout * 1000);

	dbh->alloc_own_columns = 1;
	dbh->max_escaped_char_length = 2;

	ret = 1;

cleanup:
	dbh->methods = &sqlite_methods;

	return ret;
}
/* }}} */

const pdo_driver_t swoole_pdo_sqlite_driver = {
	PDO_DRIVER_HEADER(sqlite),
	pdo_sqlite_handle_factory
};
