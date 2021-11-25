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
  | Author: Zhenyu Wu  <936321732@qq.com>                                |
  |         Tianfeng Han <rango@swoole.com>                              |
  +----------------------------------------------------------------------+
 */


#include "php_swoole_cxx.h"

#ifdef SW_USE_PGSQL

#include <libpq-fe.h>

BEGIN_EXTERN_C()
#if PHP_VERSION_ID >= 80000
#include "stubs/php_swoole_postgresql_coro_arginfo.h"
#else
#include "stubs/php_swoole_postgresql_coro_legacy_arginfo.h"
#endif
END_EXTERN_C()

namespace swoole {
namespace postgresql {

enum QueryType { NORMAL_QUERY, META_DATA, PREPARE };

struct Object {
    PGconn *conn;
    network::Socket *socket;
    Coroutine *co;
    PGresult *result;
    zval *return_value;
    zval *object;
    zval _object;
    ConnStatusType status;
    enum QueryType request_type;
    int row;
    bool connected;
    bool ignore_notices;
    bool log_notices;

    bool yield(zval *_return_value, EventType event, double timeout);
    bool wait_write_ready();
};
}  // namespace postgresql
}  // namespace swoole

#define PGSQL_ASSOC 1 << 0
#define PGSQL_NUM 1 << 1
#define PGSQL_BOTH (PGSQL_ASSOC | PGSQL_NUM)

/* from postgresql/src/include/catalog/pg_type.h */
#define BOOLOID 16
#define BYTEAOID 17
#define INT2OID 21
#define INT4OID 23
#define INT8OID 20
#define TEXTOID 25
#define OIDOID 26
#define FLOAT4OID 700
#define FLOAT8OID 701

// extension part

using swoole::Coroutine;
using swoole::Event;
using swoole::Reactor;
using swoole::coroutine::System;
using swoole::network::Socket;
using PGObject = swoole::postgresql::Object;
using PGQueryType = swoole::postgresql::QueryType;

static zend_class_entry *swoole_postgresql_coro_ce;
static zend_object_handlers swoole_postgresql_coro_handlers;
static int le_result;

struct PostgreSQLObject {
    PGObject object;
    zend_object std;
};

static sw_inline PostgreSQLObject *php_swoole_postgresql_coro_fetch_object(zend_object *obj) {
    return (PostgreSQLObject *) ((char *) obj - swoole_postgresql_coro_handlers.offset);
}

static sw_inline PGObject *php_swoole_postgresql_coro_get_object(zval *zobject) {
    return &php_swoole_postgresql_coro_fetch_object(Z_OBJ_P(zobject))->object;
}

static int swoole_postgresql_coro_close(zval *zobject);

static void php_swoole_postgresql_coro_free_object(zend_object *object) {
    PostgreSQLObject *postgresql_coro = php_swoole_postgresql_coro_fetch_object(object);
    if (postgresql_coro->object.conn) {
        zval zobject;
        ZVAL_OBJ(&zobject, object);
        swoole_postgresql_coro_close(&zobject);
    }
    zend_object_std_dtor(&postgresql_coro->std);
}

static zend_object *php_swoole_postgresql_coro_create_object(zend_class_entry *ce) {
    PostgreSQLObject *postgresql_coro = (PostgreSQLObject *) zend_object_alloc(sizeof(*postgresql_coro), ce);
    zend_object_std_init(&postgresql_coro->std, ce);
    object_properties_init(&postgresql_coro->std, ce);
    postgresql_coro->std.handlers = &swoole_postgresql_coro_handlers;

    Coroutine::get_current_safe();

    do {
        PGObject *object = &postgresql_coro->object;
        object->object = &object->_object;
        ZVAL_OBJ(object->object, &postgresql_coro->std);
    } while (0);

    return &postgresql_coro->std;
}


static PHP_METHOD(swoole_postgresql_coro, __construct);
static PHP_METHOD(swoole_postgresql_coro, __destruct);
static PHP_METHOD(swoole_postgresql_coro, connect);
static PHP_METHOD(swoole_postgresql_coro, escape);
static PHP_METHOD(swoole_postgresql_coro, escapeLiteral);
static PHP_METHOD(swoole_postgresql_coro, escapeIdentifier);
static PHP_METHOD(swoole_postgresql_coro, query);
static PHP_METHOD(swoole_postgresql_coro, prepare);
static PHP_METHOD(swoole_postgresql_coro, execute);
static PHP_METHOD(swoole_postgresql_coro, fetchAll);
static PHP_METHOD(swoole_postgresql_coro, affectedRows);
static PHP_METHOD(swoole_postgresql_coro, numRows);
static PHP_METHOD(swoole_postgresql_coro, fieldCount);
static PHP_METHOD(swoole_postgresql_coro, metaData);
static PHP_METHOD(swoole_postgresql_coro, fetchObject);
static PHP_METHOD(swoole_postgresql_coro, fetchAssoc);
static PHP_METHOD(swoole_postgresql_coro, fetchArray);
static PHP_METHOD(swoole_postgresql_coro, fetchRow);

static void php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAMETERS, zend_long result_type, int into_object);

static void _free_result(zend_resource *rsrc);
static int swoole_pgsql_coro_onReadable(Reactor *reactor, Event *event);
static int swoole_pgsql_coro_onWritable(Reactor *reactor, Event *event);
static int swoole_pgsql_coro_onError(Reactor *reactor, Event *event);
static int swoole_postgresql_coro_close(zval *zobject);
static int query_result_parse(PGObject *object);
static int prepare_result_parse(PGObject *object);
static int meta_data_result_parse(PGObject *object);
static void _php_pgsql_free_params(char **params, int num_params);

// clang-format off
static const zend_function_entry swoole_postgresql_coro_methods[] =
{
    PHP_ME(swoole_postgresql_coro, __construct,      arginfo_class_Swoole_Coroutine_PostgreSQL___construct,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, connect,          arginfo_class_Swoole_Coroutine_PostgreSQL_connect,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, query,            arginfo_class_Swoole_Coroutine_PostgreSQL_query,            ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, prepare,          arginfo_class_Swoole_Coroutine_PostgreSQL_prepare,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, execute,          arginfo_class_Swoole_Coroutine_PostgreSQL_execute,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchAll,         arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAll,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, affectedRows,     arginfo_class_Swoole_Coroutine_PostgreSQL_affectedRows,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, numRows,          arginfo_class_Swoole_Coroutine_PostgreSQL_numRows,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fieldCount,       arginfo_class_Swoole_Coroutine_PostgreSQL_fieldCount,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, metaData,         arginfo_class_Swoole_Coroutine_PostgreSQL_metaData,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, escape,           arginfo_class_Swoole_Coroutine_PostgreSQL_escape,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, escapeLiteral,    arginfo_class_Swoole_Coroutine_PostgreSQL_escapeLiteral,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, escapeIdentifier, arginfo_class_Swoole_Coroutine_PostgreSQL_escapeIdentifier, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchObject,      arginfo_class_Swoole_Coroutine_PostgreSQL_fetchObject,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchAssoc,       arginfo_class_Swoole_Coroutine_PostgreSQL_fetchAssoc,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchArray,       arginfo_class_Swoole_Coroutine_PostgreSQL_fetchArray,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchRow,         arginfo_class_Swoole_Coroutine_PostgreSQL_fetchRow,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, __destruct,       arginfo_class_Swoole_Coroutine_PostgreSQL___destruct,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_postgresql_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_postgresql_coro,
                        "Swoole\\Coroutine\\PostgreSQL",
                        NULL,
                        "Co\\PostgreSQL",
                        swoole_postgresql_coro_methods);
#ifdef SW_SET_CLASS_NOT_SERIALIZABLE
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_postgresql_coro);
#else
    SW_SET_CLASS_SERIALIZABLE(swoole_postgresql_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
#endif
    SW_SET_CLASS_CLONEABLE(swoole_postgresql_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_postgresql_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_postgresql_coro,
                               php_swoole_postgresql_coro_create_object,
                               php_swoole_postgresql_coro_free_object,
                               PostgreSQLObject,
                               std);

    le_result = zend_register_list_destructors_ex(_free_result, NULL, "pgsql result", module_number);
    zend_declare_property_null(swoole_postgresql_coro_ce, ZEND_STRL("error"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_postgresql_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_postgresql_coro_ce, ZEND_STRL("resultStatus"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_postgresql_coro_ce, ZEND_STRL("resultDiag"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_postgresql_coro_ce, ZEND_STRL("notices"), ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SW_PGSQL_ASSOC", PGSQL_ASSOC);
    SW_REGISTER_LONG_CONSTANT("SW_PGSQL_NUM", PGSQL_NUM);
    SW_REGISTER_LONG_CONSTANT("SW_PGSQL_BOTH", PGSQL_BOTH);
}

static char *_php_pgsql_trim_message(const char *message, size_t *len) {
    size_t i = strlen(message);
    if (i > 2 && (message[i - 2] == '\r' || message[i - 2] == '\n') && message[i - 1] == '.') {
        --i;
    }
    while (i > 1 && (message[i - 1] == '\r' || message[i - 1] == '\n')) {
        --i;
    }
    if (len) {
        *len = i;
    }
    return estrndup(message, i);
}

static void _php_pgsql_notice_handler(void *resource_id, const char *message) {
    zval *notices;
    char *trimed_message;
    size_t trimed_message_len;
    PGObject *object = (PGObject *) resource_id;

    if (!object->ignore_notices) {
        notices = sw_zend_read_and_convert_property_array(
            swoole_postgresql_coro_ce, &object->_object, ZEND_STRL("notices"), 0);

        trimed_message = _php_pgsql_trim_message(message, &trimed_message_len);
        if (object->log_notices) {
            php_error_docref(NULL, E_NOTICE, "%s", trimed_message);
        }
        add_next_index_stringl(notices, trimed_message, trimed_message_len);
        efree(trimed_message);
    }
}

static PHP_METHOD(swoole_postgresql_coro, __construct) {}

static PHP_METHOD(swoole_postgresql_coro, connect) {
    zval *conninfo;
    double timeout = Socket::default_connect_timeout;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(conninfo)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (object->conn) {
        RETURN_FALSE;
    }

    zend::String dsn(conninfo);
    char *p = dsn.val();
    for (size_t i = 0; i < dsn.len(); i++) {
        if (*p == ';') {
            *p = ' ';
        }
        p++;
    }

    PGconn *pgsql = PQconnectStart(dsn.val());
    if (!pgsql) {
        RETURN_FALSE;
    }

    int fd = PQsocket(pgsql);
    if (sw_unlikely(fd < 0)) {
        RETURN_FALSE;
    }

    php_swoole_check_reactor();

    if (!swoole_event_isset_handler(PHP_SWOOLE_FD_POSTGRESQL)) {
        swoole_event_set_handler(PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_READ, swoole_pgsql_coro_onReadable);
        swoole_event_set_handler(PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_WRITE, swoole_pgsql_coro_onWritable);
        swoole_event_set_handler(PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_ERROR, swoole_pgsql_coro_onError);
    }

    object->socket = swoole::make_socket(fd, (enum swFdType) PHP_SWOOLE_FD_POSTGRESQL);
    object->socket->object = object;
    object->conn = pgsql;
    object->status = CONNECTION_STARTED;
    object->connected = false;

    ON_SCOPE_EXIT {
        if (!object->connected) {
            object->conn = NULL;
        }
    };

    PQsetnonblocking(pgsql, 1);
    PQsetNoticeProcessor(pgsql, _php_pgsql_notice_handler, object);

    if (pgsql == NULL || PQstatus(pgsql) == CONNECTION_BAD) {
        swoole_warning("Unable to connect to PostgreSQL server: [%s]", PQhost(pgsql));
        if (pgsql) {
            PQfinish(pgsql);
        }
        RETURN_FALSE;
    }

    if (!object->yield(return_value, SW_EVENT_WRITE, timeout)) {
        const char *feedback;

        switch (PQstatus(pgsql)) {
        case CONNECTION_STARTED:
            feedback = "connection time out...please make sure your host,dbname,user and password is correct ";
            break;
        case CONNECTION_MADE:
            feedback = "Connected to server..";
            break;
        default:
            feedback = " time out..";
            break;
        }

        char *err_msg = PQerrorMessage(object->conn);
        if (pgsql == NULL || PQstatus(pgsql) == CONNECTION_STARTED) {
            swoole_warning(" [%s, %s] ", feedback, err_msg);
        } else if (PQstatus(pgsql) == CONNECTION_MADE) {
            PQfinish(pgsql);
        }
        zend_update_property_string(swoole_postgresql_coro_ce,
                                    SW_Z8_OBJ_P(ZEND_THIS),
                                    ZEND_STRL("error"),
                                    swoole_strerror(swoole_get_last_error()));
        RETURN_FALSE;
    }

    ZVAL_BOOL(return_value, object->connected);
}

static void connect_callback(PGObject *object, Reactor *reactor, Event *event) {
    PGconn *conn = object->conn;
    ConnStatusType status = PQstatus(conn);
    int events = 0;
    char *err_msg;

    swoole_event_del(object->socket);

    if (status != CONNECTION_OK) {
        PostgresPollingStatusType flag = PQconnectPoll(conn);
        switch (flag) {
        case PGRES_POLLING_READING:
            events = SW_EVENT_READ;
            break;
        case PGRES_POLLING_WRITING:
            events = SW_EVENT_WRITE;
            break;
        case PGRES_POLLING_OK:
            object->connected = true;
            events = 0;
            break;
        case PGRES_POLLING_FAILED:
            events = 0;
            err_msg = PQerrorMessage(conn);
            zend_update_property_string(
                swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"), err_msg);
            break;
        default:
            swoole_warning("PQconnectPoll unexpected status");
            break;
        }

        if (events) {
            event->socket->fd = PQsocket(conn);
            swoole_event_add(event->socket, events);
            return;
        }
    }

    if (object->connected == 1) {
        zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"));
    }
    object->co->resume();
}

static int swoole_pgsql_coro_onWritable(Reactor *reactor, Event *event) {
    PGObject *object = (PGObject *) event->socket->object;

    if (!object->connected) {
        connect_callback(object, reactor, event);
        return SW_OK;
    }

    if (object->co) {
        object->co->resume();
        return SW_OK;
    } else {
        return reactor->default_write_handler(reactor, event);
    }
}

static int swoole_pgsql_coro_onReadable(Reactor *reactor, Event *event) {
    PGObject *object = (PGObject *) (event->socket->object);

    if (!object->connected) {
        connect_callback(object, reactor, event);
        return SW_OK;
    }

    switch (object->request_type) {
    case PGQueryType::NORMAL_QUERY:
        query_result_parse(object);
        break;
    case PGQueryType::META_DATA:
        meta_data_result_parse(object);
        break;
    case PGQueryType::PREPARE:
        prepare_result_parse(object);
        break;
    }

    return SW_OK;
}

static int meta_data_result_parse(PGObject *object) {
    int i, num_rows;
    zval elem;
    PGresult *pg_result;
    zend_bool extended = 0;
    pg_result = PQgetResult(object->conn);

    if (PQresultStatus(pg_result) != PGRES_TUPLES_OK || (num_rows = PQntuples(pg_result)) == 0) {
        php_swoole_fatal_error(E_WARNING, "Table doesn't exists");
        return 0;
    }

    array_init(object->return_value);
    array_init(&elem);
    for (i = 0; i < num_rows; i++) {
        object->result = pg_result;
        char *name;
        /* pg_attribute.attnum */
        add_assoc_long_ex(&elem, "num", sizeof("num") - 1, atoi(PQgetvalue(pg_result, i, 1)));
        /* pg_type.typname */
        add_assoc_string_ex(&elem, "type", sizeof("type") - 1, PQgetvalue(pg_result, i, 2));
        /* pg_attribute.attlen */
        add_assoc_long_ex(&elem, "len", sizeof("len") - 1, atoi(PQgetvalue(pg_result, i, 3)));
        /* pg_attribute.attnonull */
        add_assoc_bool_ex(&elem, "not null", sizeof("not null") - 1, !strcmp(PQgetvalue(pg_result, i, 4), "t"));
        /* pg_attribute.atthasdef */
        add_assoc_bool_ex(&elem, "has default", sizeof("has default") - 1, !strcmp(PQgetvalue(pg_result, i, 5), "t"));
        /* pg_attribute.attndims */
        add_assoc_long_ex(&elem, "array dims", sizeof("array dims") - 1, atoi(PQgetvalue(pg_result, i, 6)));
        /* pg_type.typtype */
        add_assoc_bool_ex(&elem, "is enum", sizeof("is enum") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "e"));
        if (extended) {
            /* pg_type.typtype */
            add_assoc_bool_ex(&elem, "is base", sizeof("is base") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "b"));
            add_assoc_bool_ex(
                &elem, "is composite", sizeof("is composite") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "c"));
            add_assoc_bool_ex(&elem, "is pesudo", sizeof("is pesudo") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "p"));
            /* pg_description.description */
            add_assoc_string_ex(&elem, "description", sizeof("description") - 1, PQgetvalue(pg_result, i, 8));
        }
        /* pg_attribute.attname */
        name = PQgetvalue(pg_result, i, 0);
        add_assoc_zval(object->return_value, name, &elem);
    }
    zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"));
    zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultDiag"));
    object->co->resume();
    return SW_OK;
}

static void set_error_diag(const PGObject *object, const PGresult *pgsql_result) {
    const unsigned int error_codes[] = {PG_DIAG_SEVERITY,
                                        PG_DIAG_SQLSTATE,
                                        PG_DIAG_MESSAGE_PRIMARY,
                                        PG_DIAG_MESSAGE_DETAIL,
                                        PG_DIAG_MESSAGE_HINT,
                                        PG_DIAG_STATEMENT_POSITION,
                                        PG_DIAG_INTERNAL_POSITION,
                                        PG_DIAG_INTERNAL_QUERY,
                                        PG_DIAG_CONTEXT,
                                        PG_DIAG_SCHEMA_NAME,
                                        PG_DIAG_TABLE_NAME,
                                        PG_DIAG_COLUMN_NAME,
                                        PG_DIAG_DATATYPE_NAME,
                                        PG_DIAG_CONSTRAINT_NAME,
                                        PG_DIAG_SOURCE_FILE,
                                        PG_DIAG_SOURCE_LINE,
                                        PG_DIAG_SOURCE_FUNCTION};

    const char *error_names[] = {"severity",
                                 "sqlstate",
                                 "message_primary",
                                 "message_detail",
                                 "message_hint",
                                 "statement_position",
                                 "internal_position",
                                 "internal_query",
                                 "content",
                                 "schema_name",
                                 "table_name",
                                 "column_name",
                                 "datatype_name",
                                 "constraint_name",
                                 "source_file",
                                 "source_line",
                                 "source_function"};

    long unsigned int i;
    char *error_result;

    zval result_diag;
    array_init_size(&result_diag, sizeof(error_codes) / sizeof(int));

    for (i = 0; i < sizeof(error_codes) / sizeof(int); i++) {
        error_result = PQresultErrorField(pgsql_result, error_codes[i]);

        if (error_result != nullptr) {
            add_assoc_string(&result_diag, error_names[i], error_result);
        } else {
            add_assoc_null(&result_diag, error_names[i]);
        }
    }

    zend_update_property(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultDiag"), &result_diag);
    zval_dtor(&result_diag);
}

static int query_result_parse(PGObject *object) {
    PGresult *pgsql_result;
    ExecStatusType status;

    int error = 0;
    char *err_msg;
    int res;

    pgsql_result = PQgetResult(object->conn);
    status = PQresultStatus(pgsql_result);

    zend_update_property_long(
        swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultStatus"), status);

    switch (status) {
    case PGRES_EMPTY_QUERY:
    case PGRES_BAD_RESPONSE:
    case PGRES_NONFATAL_ERROR:
    case PGRES_FATAL_ERROR:
        err_msg = PQerrorMessage(object->conn);
        set_error_diag(object, pgsql_result);
        PQclear(pgsql_result);
        ZVAL_FALSE(object->return_value);
        zend_update_property_string(
            swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"), err_msg);
        object->co->resume();
        break;
    case PGRES_COMMAND_OK: /* successful command that did not return rows */
    default:
        object->result = pgsql_result;
        object->row = 0;
        /* Wait to finish sending buffer */
        res = PQflush(object->conn);
        ZVAL_RES(object->return_value, zend_register_resource(pgsql_result, le_result));
        zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"));
        zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultDiag"));
        object->co->resume();
        if (error != 0) {
            php_swoole_fatal_error(E_WARNING, "socket error. Error: %s [%d]", strerror(error), error);
        }
        break;
    }
    (void) res;

    return SW_OK;
}

static int prepare_result_parse(PGObject *object) {
    int error = 0;
    char *err_msg;
    int res;

    PGresult *pgsql_result = PQgetResult(object->conn);
    ExecStatusType status = PQresultStatus(pgsql_result);

    zend_update_property_long(
        swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultStatus"), status);

    switch (status) {
    case PGRES_EMPTY_QUERY:
    case PGRES_BAD_RESPONSE:
    case PGRES_NONFATAL_ERROR:
    case PGRES_FATAL_ERROR:
        err_msg = PQerrorMessage(object->conn);
        set_error_diag(object, pgsql_result);
        PQclear(pgsql_result);
        ZVAL_FALSE(object->return_value);
        zend_update_property_string(
            swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"), err_msg);
        object->co->resume();
        if (error != 0) {
            php_swoole_fatal_error(E_WARNING, "socket error. Error: %s [%d]", strerror(error), error);
        }
        break;
    case PGRES_COMMAND_OK: /* successful command that did not return rows */
        /* Wait to finish sending buffer */
        // res = PQflush(object->conn);
        PQclear(pgsql_result);
        ZVAL_TRUE(object->return_value);
        zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("error"));
        zend_update_property_null(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object->object), ZEND_STRL("resultDiag"));
        object->co->resume();
        if (error != 0) {
            php_swoole_fatal_error(E_WARNING, "socket error. Error: %s [%d]", strerror(error), error);
        }
        break;
    default:
        PQclear(pgsql_result);
        ZVAL_FALSE(object->return_value);
        zend_update_property_string(swoole_postgresql_coro_ce,
                                    SW_Z8_OBJ_P(object->object),
                                    ZEND_STRL("error"),
                                    "Bad result returned to prepare");
        object->co->resume();
        if (error != 0) {
            php_swoole_fatal_error(E_WARNING, "socket error. Error: %s [%d]", strerror(error), error);
        }
        break;
    }
    (void) res;

    return SW_OK;
}

bool PGObject::wait_write_ready() {
    int retval = 0;
    while ((retval = PQflush(conn)) == 1) {
        zval return_value;
        if (!yield(&return_value, SW_EVENT_WRITE, Socket::default_write_timeout)) {
            return false;
        }
    }

    if (retval == -1) {
        char *err_msg = PQerrorMessage(conn);
        zend_update_property_string(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(object), ZEND_STRL("error"), err_msg);
        return false;
    }

    return true;
}

bool PGObject::yield(zval *_return_value, EventType event, double timeout) {
    co = swoole::Coroutine::get_current_safe();
    if (swoole_event_add(socket, event) < 0) {
        php_swoole_fatal_error(E_WARNING, "swoole_event_add failed");
        RETVAL_FALSE;
        return false;
    }

    ON_SCOPE_EXIT {
        co = nullptr;
        if (!socket->removed && swoole_event_del(socket) < 0) {
            php_swoole_fatal_error(E_WARNING, "swoole_event_del failed");
        }
    };

    return_value = _return_value;

    if (!co->yield_ex(timeout)) {
        ZVAL_FALSE(_return_value);

        if (co->is_canceled()) {
            zend_update_property_string(swoole_postgresql_coro_ce,
                                        SW_Z8_OBJ_P(object),
                                        ZEND_STRL("error"),
                                        swoole_strerror(SW_ERROR_CO_CANCELED));
        } else if (co->is_timedout()) {
            zend_update_property_string(swoole_postgresql_coro_ce,
                                        SW_Z8_OBJ_P(object),
                                        ZEND_STRL("error"),
                                        swoole_strerror(SW_ERROR_CO_TIMEDOUT));
        }

        return false;
    }

    return true;
}

static PHP_METHOD(swoole_postgresql_coro, query) {
    zval *query;
    PGconn *pgsql;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(query)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    object->request_type = PGQueryType::NORMAL_QUERY;
    pgsql = object->conn;
    object->object = ZEND_THIS;

    while ((pgsql_result = PQgetResult(pgsql))) {
        PQclear(pgsql_result);
    }

    if (PQsendQuery(pgsql, Z_STRVAL_P(query)) == 0) {
        char *err_msg = PQerrorMessage(pgsql);
        zend_update_property_string(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("error"), err_msg);
        RETURN_FALSE;
    }

    if (!object->wait_write_ready()) {
        RETURN_FALSE;
    }

    object->yield(return_value, SW_EVENT_READ, Socket::default_read_timeout);
}

static PHP_METHOD(swoole_postgresql_coro, prepare) {
    zval *query, *stmtname;
    PGconn *pgsql;
    int is_non_blocking;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(stmtname)
    Z_PARAM_ZVAL(query)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    object->request_type = PGQueryType::PREPARE;
    pgsql = object->conn;
    object->object = ZEND_THIS;

    is_non_blocking = PQisnonblocking(pgsql);

    if (is_non_blocking == 0 && PQsetnonblocking(pgsql, 1) == -1) {
        php_swoole_fatal_error(E_NOTICE, "Cannot set connection to nonblocking mode");
        RETURN_FALSE;
    }

    while ((pgsql_result = PQgetResult(pgsql))) {
        PQclear(pgsql_result);
    }

    if (!PQsendPrepare(pgsql, Z_STRVAL_P(stmtname), Z_STRVAL_P(query), 0, NULL)) {
        if (is_non_blocking) {
            RETURN_FALSE;
        } else {
            /*if ((PGG(auto_reset_persistent) & 2) && PQstatus(pgsql) != CONNECTION_OK) {
             PQreset(pgsql);
             }*/
            if (!PQsendPrepare(pgsql, Z_STRVAL_P(stmtname), Z_STRVAL_P(query), 0, NULL)) {
                RETURN_FALSE;
            }
        }
    }

    if (!object->wait_write_ready()) {
        RETURN_FALSE;
    }
    object->yield(return_value, SW_EVENT_READ, Socket::default_read_timeout);
}

static PHP_METHOD(swoole_postgresql_coro, execute) {
    zval *pv_param_arr, *tmp;
    int num_params = 0;
    char **params = NULL;
    zval *stmtname;
    PGconn *pgsql;
    int is_non_blocking;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(stmtname)
    Z_PARAM_ZVAL(pv_param_arr)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    object->request_type = PGQueryType::NORMAL_QUERY;
    pgsql = object->conn;
    object->object = ZEND_THIS;

    is_non_blocking = PQisnonblocking(pgsql);

    if (is_non_blocking == 0 && PQsetnonblocking(pgsql, 1) == -1) {
        php_swoole_fatal_error(E_NOTICE, "Cannot set connection to nonblocking mode");
        RETURN_FALSE;
    }

    while ((pgsql_result = PQgetResult(pgsql))) {
        PQclear(pgsql_result);
    }

    num_params = zend_hash_num_elements(Z_ARRVAL_P(pv_param_arr));
    if (num_params > 0) {
        int i = 0;
        params = (char **) safe_emalloc(sizeof(char *), num_params, 0);

        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(pv_param_arr), tmp) {
            if (Z_TYPE_P(tmp) == IS_NULL) {
                params[i] = NULL;
            } else {
                zval tmp_val;
                ZVAL_COPY(&tmp_val, tmp);
                convert_to_string(&tmp_val);
                if (Z_TYPE(tmp_val) != IS_STRING) {
                    php_swoole_fatal_error(E_WARNING, "Error converting parameter");
                    zval_ptr_dtor(&tmp_val);
                    _php_pgsql_free_params(params, num_params);
                    RETURN_FALSE;
                }
                params[i] = estrndup(Z_STRVAL(tmp_val), Z_STRLEN(tmp_val));
                zval_ptr_dtor(&tmp_val);
            }
            i++;
        }
        ZEND_HASH_FOREACH_END();
    }

    if (PQsendQueryPrepared(pgsql, Z_STRVAL_P(stmtname), num_params, (const char *const *) params, NULL, NULL, 0)) {
        _php_pgsql_free_params(params, num_params);
    } else if (is_non_blocking) {
        _php_pgsql_free_params(params, num_params);
        RETURN_FALSE;
    } else {
        /*
        if ((PGG(auto_reset_persistent) & 2) && PQstatus(pgsql) != CONNECTION_OK) {
            PQreset(pgsql);
        }
        */
        if (!PQsendQueryPrepared(
                pgsql, Z_STRVAL_P(stmtname), num_params, (const char *const *) params, NULL, NULL, 0)) {
            _php_pgsql_free_params(params, num_params);
            RETURN_FALSE;
        }
    }
    if (!object->wait_write_ready()) {
        RETURN_FALSE;
    }
    object->yield(return_value, SW_EVENT_READ, Socket::default_read_timeout);
}

static void _php_pgsql_free_params(char **params, int num_params) {
    if (num_params > 0) {
        for (int i = 0; i < num_params; i++) {
            if (params[i]) {
                efree(params[i]);
            }
        }
        efree(params);
    }
}

/* {{{ void php_pgsql_get_field_value */
static inline void php_pgsql_get_field_value(
    zval *value, PGresult *pgsql_result, zend_long result_type, int row, int column) {
    if (PQgetisnull(pgsql_result, row, column)) {
        ZVAL_NULL(value);
    } else {
        char *element = PQgetvalue(pgsql_result, row, column);
        if (element) {
            const size_t element_len = PQgetlength(pgsql_result, row, column);
            Oid pgsql_type = PQftype(pgsql_result, column);

            switch (pgsql_type) {
            case BOOLOID:
                ZVAL_BOOL(value, *element == 't');
                break;
            case FLOAT4OID:
            case FLOAT8OID:
                if (element_len == sizeof("Infinity") - 1 && strcmp(element, "Infinity") == 0) {
                    ZVAL_DOUBLE(value, ZEND_INFINITY);
                } else if (element_len == sizeof("-Infinity") - 1 && strcmp(element, "-Infinity") == 0) {
                    ZVAL_DOUBLE(value, -ZEND_INFINITY);
                } else if (element_len == sizeof("NaN") - 1 && strcmp(element, "NaN") == 0) {
                    ZVAL_DOUBLE(value, ZEND_NAN);
                } else {
                    ZVAL_DOUBLE(value, zend_strtod(element, NULL));
                }
                break;
            case OIDOID:
            case INT2OID:
            case INT4OID:
#if SIZEOF_ZEND_LONG >= 8
            case INT8OID:
#endif
            {
                zend_long long_value;
#if PHP_VERSION_ID < 80100
                ZEND_ATOL(long_value, element);
#else
                long_value = ZEND_ATOL(element);
#endif
                ZVAL_LONG(value, long_value);
                break;
            }
            case BYTEAOID: {
                size_t tmp_len;
                char *tmp_ptr = (char *) PQunescapeBytea((unsigned char *) element, &tmp_len);
                if (!tmp_ptr) {
                    /* PQunescapeBytea returned an error */
                    ZVAL_NULL(value);
                } else {
                    ZVAL_STRINGL(value, tmp_ptr, tmp_len);
                    PQfreemem(tmp_ptr);
                }
                break;
            }
            default:
                ZVAL_STRINGL(value, element, element_len);
            }
        } else {
            ZVAL_NULL(value);
        }
    }
}
/* }}} */

/* {{{ php_pgsql_result2array
 */
int swoole_pgsql_result2array(PGresult *pg_result, zval *ret_array, long result_type) {
    zval row;
    const char *field_name;
    size_t num_fields, unknown_columns;
    int pg_numrows, pg_row;
    uint32_t i;
    assert(Z_TYPE_P(ret_array) == IS_ARRAY);

    if ((pg_numrows = PQntuples(pg_result)) <= 0) {
        return FAILURE;
    }
    for (pg_row = 0; pg_row < pg_numrows; pg_row++) {
        array_init(&row);
        unknown_columns = 0;
        for (i = 0, num_fields = PQnfields(pg_result); i < num_fields; i++) {
            if (result_type & PGSQL_ASSOC) {
                zval value;
                php_pgsql_get_field_value(&value, pg_result, result_type, pg_row, i);
                field_name = PQfname(pg_result, i);
                if (0 == strcmp("?column?", field_name)) {
                    if (unknown_columns > 0) {
                        field_name = (std::string(field_name) + std::to_string(unknown_columns)).c_str();
                    }
                    ++unknown_columns;
                }
                add_assoc_zval(&row, field_name, &value);
            }
            if (result_type & PGSQL_NUM) {
                zval value;
                php_pgsql_get_field_value(&value, pg_result, result_type, pg_row, i);
                add_next_index_zval(&row, &value);
            }
        }
        add_index_zval(ret_array, pg_row, &row);
    }
    return SUCCESS;
}

static PHP_METHOD(swoole_postgresql_coro, fetchAll) {
    zval *result;
    PGresult *pgsql_result;
    zend_long result_type = PGSQL_ASSOC;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_RESOURCE(result)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(result_type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((pgsql_result = (PGresult *) zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL) {
        RETURN_FALSE;
    }

    array_init(return_value);
    if (swoole_pgsql_result2array(pgsql_result, return_value, result_type) == FAILURE) {
        zval_dtor(return_value);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_postgresql_coro, affectedRows) {
    zval *result;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(result)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((pgsql_result = (PGresult *) zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL) {
        RETURN_FALSE;
    }

    RETVAL_LONG(atoi(PQcmdTuples(pgsql_result)));
}

// query's num
static PHP_METHOD(swoole_postgresql_coro, numRows) {
    zval *result;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(result)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((pgsql_result = (PGresult *) zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL) {
        RETURN_FALSE;
    }

    RETVAL_LONG(PQntuples(pgsql_result));
}

// query's field count
static PHP_METHOD(swoole_postgresql_coro, fieldCount) {
    zval *result;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(result)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if ((pgsql_result = (PGresult *) zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL) {
        RETURN_FALSE;
    }

    RETVAL_LONG(PQnfields(pgsql_result));
}

static PHP_METHOD(swoole_postgresql_coro, metaData) {
    char *table_name;
    size_t table_name_len;
    zend_bool extended = 0;
    PGconn *pgsql;

    PGresult *pg_result;
    char *src, *tmp_name, *tmp_name2 = NULL;
    char *escaped;
    smart_str querystr = {0};
    size_t new_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(table_name, table_name_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    object->request_type = PGQueryType::META_DATA;
    pgsql = object->conn;
    object->object = ZEND_THIS;

    while ((pg_result = PQgetResult(pgsql))) {
        PQclear(pg_result);
    }

    if (table_name_len == 0) {
        php_swoole_fatal_error(E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }

    src = estrdup(table_name);
    tmp_name = php_strtok_r(src, ".", &tmp_name2);
    if (!tmp_name) {
        efree(src);
        php_swoole_fatal_error(E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }
    if (!tmp_name2 || !*tmp_name2) {
        /* Default schema */
        tmp_name2 = tmp_name;
        tmp_name = (char *) "public";
    }

    if (extended) {
        smart_str_appends(
            &querystr,
            "SELECT a.attname, a.attnum, t.typname, a.attlen, a.attnotNULL, a.atthasdef, a.attndims, t.typtype, "
            "d.description "
            "FROM pg_class as c "
            " JOIN pg_attribute a ON (a.attrelid = c.oid) "
            " JOIN pg_type t ON (a.atttypid = t.oid) "
            " JOIN pg_namespace n ON (c.relnamespace = n.oid) "
            " LEFT JOIN pg_description d ON (d.objoid=a.attrelid AND d.objsubid=a.attnum AND c.oid=d.objoid) "
            "WHERE a.attnum > 0  AND c.relname = '");
    } else {
        smart_str_appends(
            &querystr,
            "SELECT a.attname, a.attnum, t.typname, a.attlen, a.attnotnull, a.atthasdef, a.attndims, t.typtype "
            "FROM pg_class as c "
            " JOIN pg_attribute a ON (a.attrelid = c.oid) "
            " JOIN pg_type t ON (a.atttypid = t.oid) "
            " JOIN pg_namespace n ON (c.relnamespace = n.oid) "
            "WHERE a.attnum > 0 AND c.relname = '");
    }
    escaped = (char *) safe_emalloc(strlen(tmp_name2), 2, 1);
    new_len = PQescapeStringConn(pgsql, escaped, tmp_name2, strlen(tmp_name2), NULL);
    if (new_len) {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' AND n.nspname = '");
    escaped = (char *) safe_emalloc(strlen(tmp_name), 2, 1);
    new_len = PQescapeStringConn(pgsql, escaped, tmp_name, strlen(tmp_name), NULL);
    if (new_len) {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' ORDER BY a.attnum;");
    smart_str_0(&querystr);
    efree(src);

    // pg_result = PQexec(pgsql, ZSTR_VAL(querystr.s));

    int ret = PQsendQuery(pgsql, ZSTR_VAL(querystr.s));
    if (ret == 0) {
        char *err_msg = PQerrorMessage(pgsql);
        swoole_warning("error:[%s]", err_msg);
    }
    smart_str_free(&querystr);
    object->yield(return_value, SW_EVENT_READ, Socket::default_read_timeout);
}

/* {{{ void php_pgsql_fetch_hash */
static void php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAMETERS, zend_long result_type, int into_object) {
    zval *result, *zrow = NULL;
    PGresult *pgsql_result;
    PGObject *pg_result;
    int i, num_fields, pgsql_row, use_row;
    zend_long row = -1;
    char *field_name;
    zval *ctor_params = NULL;
    zend_class_entry *ce = NULL;

    if (into_object) {
        zend_string *class_name = NULL;

        if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|z!Sz", &result, &zrow, &class_name, &ctor_params) == FAILURE) {
            RETURN_FALSE;
        }
        if (!class_name) {
            ce = zend_standard_class_def;
        } else {
            ce = zend_fetch_class(class_name, ZEND_FETCH_CLASS_AUTO);
        }
        if (!ce) {
            php_swoole_fatal_error(E_WARNING, "Could not find class '%s'", ZSTR_VAL(class_name));
            return;
        }
        result_type = PGSQL_ASSOC;
    } else {
        if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|z!l", &result, &zrow, &result_type) == FAILURE) {
            RETURN_FALSE;
        }
    }
    if (zrow == NULL) {
        row = -1;
    } else {
        row = zval_get_long(zrow);
        if (row < 0) {
            php_swoole_fatal_error(E_WARNING, "The row parameter must be greater or equal to zero");
            RETURN_FALSE;
        }
    }
    use_row = ZEND_NUM_ARGS() > 1 && row != -1;

    if (!(result_type & PGSQL_BOTH)) {
        php_swoole_fatal_error(E_WARNING, "Invalid result type");
        RETURN_FALSE;
    }

    if ((pgsql_result = (PGresult *) zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL) {
        RETURN_FALSE;
    }

    pg_result = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!pg_result || !pg_result->conn) {
        RETURN_FALSE;
    }

    if (use_row) {
        if (row < 0 || row >= PQntuples(pgsql_result)) {
            php_swoole_fatal_error(E_WARNING,
                                   "Unable to jump to row " ZEND_LONG_FMT " on PostgreSQL result index " ZEND_LONG_FMT,
                                   row,
                                   Z_LVAL_P(result));
            RETURN_FALSE;
        }
        pgsql_row = (int) row;
        pg_result->row = pgsql_row;
    } else {
        /* If 2nd param is NULL, use internal row counter to access next row */
        pgsql_row = pg_result->row;
        if (pgsql_row < 0 || pgsql_row >= PQntuples(pgsql_result)) {
            RETURN_FALSE;
        }
        pg_result->row++;
    }

    array_init(return_value);
    for (i = 0, num_fields = PQnfields(pgsql_result); i < num_fields; i++) {
        if (result_type & PGSQL_NUM) {
            zval value;
            php_pgsql_get_field_value(&value, pgsql_result, result_type, pgsql_row, i);
            add_index_zval(return_value, i, &value);
        }

        if (result_type & PGSQL_ASSOC) {
            zval value;
            php_pgsql_get_field_value(&value, pgsql_result, result_type, pgsql_row, i);
            field_name = PQfname(pgsql_result, i);
            add_assoc_zval(return_value, field_name, &value);
        }
    }

    if (into_object) {
        zval dataset;
        zend_fcall_info fci;
        zend_fcall_info_cache fcc;
        zval retval;

        ZVAL_COPY_VALUE(&dataset, return_value);
        object_and_properties_init(return_value, ce, NULL);
        if (!ce->default_properties_count && !ce->__set) {
            Z_OBJ_P(return_value)->properties = Z_ARR(dataset);
        } else {
            zend_merge_properties(return_value, Z_ARRVAL(dataset));
            zval_ptr_dtor(&dataset);
        }

        if (ce->constructor) {
            fci.size = sizeof(fci);
            ZVAL_UNDEF(&fci.function_name);
            fci.object = Z_OBJ_P(return_value);
            fci.retval = &retval;
            fci.params = NULL;
            fci.param_count = 0;

            if (ctor_params && Z_TYPE_P(ctor_params) != IS_NULL) {
                if (zend_fcall_info_args(&fci, ctor_params) == FAILURE) {
                    /* Two problems why we throw exceptions here: PHP is typeless
                     * and hence passing one argument that's not an array could be
                     * by mistake and the other way round is possible, too. The
                     * single value is an array. Also we'd have to make that one
                     * argument passed by reference.
                     */
                    zend_throw_exception(zend_ce_exception, "Parameter ctor_params must be an array", 0);
                    return;
                }
            }

#if PHP_VERSION_ID < 70300
            fcc.initialized = 1;
#endif
            fcc.function_handler = ce->constructor;
#if PHP_VERSION_ID >= 70100
            fcc.calling_scope = zend_get_executed_scope();
#else
            fcc.calling_scope = EG(scope);
#endif
            fcc.called_scope = Z_OBJCE_P(return_value);
            fcc.object = Z_OBJ_P(return_value);

            if (zend_call_function(&fci, &fcc) == FAILURE) {
                zend_throw_exception_ex(zend_ce_exception,
                                        0,
                                        "Could not execute %s::%s()",
                                        ZSTR_VAL(ce->name),
                                        ZSTR_VAL(ce->constructor->common.function_name));
            } else {
                zval_ptr_dtor(&retval);
            }
            if (fci.params) {
                efree(fci.params);
            }
        } else if (ctor_params) {
            zend_throw_exception_ex(zend_ce_exception,
                                    0,
                                    "Class %s does not have a constructor hence you cannot use ctor_params",
                                    ZSTR_VAL(ce->name));
        }
    }
}
/* }}} */

/* {{{ proto array fetchRow(resource result [, int row [, int result_type]])
   Get a row as an enumerated array */
static PHP_METHOD(swoole_postgresql_coro, fetchRow) {
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_NUM, 0);
}
/* }}} */

/* {{{ proto array fetchAssoc(resource result [, int row])
   Fetch a row as an assoc array */
static PHP_METHOD(swoole_postgresql_coro, fetchAssoc) {
    /* pg_fetch_assoc() is added from PHP 4.3.0. It should raise error, when
       there is 3rd parameter */
    if (ZEND_NUM_ARGS() > 2) WRONG_PARAM_COUNT;
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_ASSOC, 0);
}
/* }}} */

/* {{{ proto array fetchArray(resource result [, int row [, int result_type]])
   Fetch a row as an array */
static PHP_METHOD(swoole_postgresql_coro, fetchArray) {
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_BOTH, 0);
}
/* }}} */

/* {{{ proto object fetchObject(resource result [, int row [, string class_name [, NULL|array ctor_params]]])
   Fetch a row as an object */
static PHP_METHOD(swoole_postgresql_coro, fetchObject) {
    /* fetchObject() allowed result_type used to be. 3rd parameter
       must be allowed for compatibility */
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_ASSOC, 1);
}

static void _free_result(zend_resource *rsrc) {
    PGresult *pg_result = (PGresult *) rsrc->ptr;
    PQclear(pg_result);
}

static int swoole_pgsql_coro_onError(Reactor *reactor, Event *event) {
    PGObject *object = (PGObject *) (event->socket->object);
    zval *zobject = object->object;

    zend_update_property_string(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("error"), "onerror");
    object->connected = false;
    ZVAL_FALSE(object->return_value);
    object->co->resume();

    return SW_OK;
}

static PHP_METHOD(swoole_postgresql_coro, __destruct) {}

static int swoole_postgresql_coro_close(zval *zobject) {
    PGObject *object = php_swoole_postgresql_coro_get_object(zobject);
    if (!object || !object->conn) {
        php_swoole_fatal_error(E_WARNING, "object is not instanceof swoole_postgresql_coro");
        return FAILURE;
    }

    if (sw_reactor()) {
        swSocket *_socket = object->socket;
        if (!_socket->removed) {
            sw_reactor()->del(_socket);
        }
        _socket->object = nullptr;
        _socket->free();
    }

    PGresult *res;
    if (object->connected) {
        while ((res = PQgetResult(object->conn))) {
            PQclear(res);
        }
        /**
         * PQfinish will close fd
         */
        PQfinish(object->conn);
        /**
         * fd marked -1, prevent double close
         */
        object->socket->fd = -1;
        object->conn = nullptr;
        object->connected = false;
    }
    object->co = nullptr;
    return SUCCESS;
}

static PHP_METHOD(swoole_postgresql_coro, escape) {
    char *str;
    size_t l_str;
    PGconn *pgsql;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(str, l_str)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    pgsql = object->conn;

    zend_string *result = zend_string_alloc(l_str * 2, 0);
    int error = 0;
    size_t new_len = PQescapeStringConn(object->conn, result->val, str, l_str, &error);

    if (new_len == 0 || error) {
        zend_update_property_string(
            swoole_postgresql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("error"), PQerrorMessage(pgsql));
        zend_update_property_long(swoole_postgresql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), error);
        zend_string_free(result);
        RETURN_FALSE;
    } else {
        result->val[new_len] = 0;
        result->len = new_len;
        RETURN_STR(result);
    }
}

static PHP_METHOD(swoole_postgresql_coro, escapeLiteral) {
    char *str, *tmp;
    size_t l_str;
    PGconn *pgsql;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(str, l_str)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    pgsql = object->conn;

    tmp = PQescapeLiteral(pgsql, str, l_str);
    if (tmp == nullptr) {
        zend_update_property_string(
            swoole_postgresql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("error"), PQerrorMessage(pgsql));

        RETURN_FALSE;
    }

    RETVAL_STRING(tmp);
    PQfreemem(tmp);
}

static PHP_METHOD(swoole_postgresql_coro, escapeIdentifier) {
    char *str, *tmp;
    size_t l_str;
    PGconn *pgsql;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(str, l_str)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    PGObject *object = php_swoole_postgresql_coro_get_object(ZEND_THIS);
    if (!object || !object->conn) {
        RETURN_FALSE;
    }
    pgsql = object->conn;

    tmp = PQescapeIdentifier(pgsql, str, l_str);
    if (tmp == nullptr) {
        zend_update_property_string(
            swoole_postgresql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("error"), PQerrorMessage(pgsql));

        RETURN_FALSE;
    }

    RETVAL_STRING(tmp);
    PQfreemem(tmp);
}

#endif
