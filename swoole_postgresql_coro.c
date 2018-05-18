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
  +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#ifdef SW_USE_POSTGRESQL
#include "swoole_postgresql_coro.h"
#include "swoole_coroutine.h"

static PHP_METHOD(swoole_postgresql_coro, __construct);
static PHP_METHOD(swoole_postgresql_coro, __destruct);
static PHP_METHOD(swoole_postgresql_coro, connect);
static PHP_METHOD(swoole_postgresql_coro, query);
static PHP_METHOD(swoole_postgresql_coro, fetchAll);
static PHP_METHOD(swoole_postgresql_coro, affectedRows);
static PHP_METHOD(swoole_postgresql_coro, numRows);
static PHP_METHOD(swoole_postgresql_coro,metaData);
static PHP_METHOD(swoole_postgresql_coro,fetchObject);
static PHP_METHOD(swoole_postgresql_coro,fetchAssoc);
static PHP_METHOD(swoole_postgresql_coro,fetchArray);
static PHP_METHOD(swoole_postgresql_coro,fetchRow);

static void php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAMETERS, zend_long result_type, int into_object);

static void _destroy_pgsql_link(zend_resource *rsrc);
static void _free_result(zend_resource *rsrc);
static int swoole_pgsql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_pgsql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_pgsql_coro_onError(swReactor *reactor, swEvent *event);
int php_pgsql_result2array(PGresult *pg_result, zval *ret_array, long result_type);
static int swoole_postgresql_coro_close(pg_object *pg_object);
static  int query_result_parse(pg_object *pg_object);
static  int meta_data_result_parse(pg_object *pg_object);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_connect, 0, 0, -1)
    ZEND_ARG_INFO(0, conninfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_query, 0, 0, 0)
    ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_all, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_affected_rows, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_num_rows, 0, 0, 0)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_meta_data, 0, 0, 1)
    ZEND_ARG_INFO(0, table_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_row, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_assoc, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_array, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_fetch_object, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, row)
    ZEND_ARG_INFO(0, class_name)
    ZEND_ARG_INFO(0, l)
    ZEND_ARG_INFO(0, ctor_params)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_postgresql_coro_methods[] =
{
    PHP_ME(swoole_postgresql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_postgresql_coro, connect, arginfo_pg_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, query, arginfo_pg_query, ZEND_ACC_PUBLIC )
    PHP_ME(swoole_postgresql_coro, fetchAll, arginfo_pg_fetch_all, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, affectedRows, arginfo_pg_affected_rows, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, numRows, arginfo_pg_num_rows, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, metaData, arginfo_pg_meta_data, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchObject, arginfo_pg_fetch_object, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchAssoc, arginfo_pg_fetch_assoc, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchArray, arginfo_pg_fetch_array, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, fetchRow, arginfo_pg_fetch_row, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

static zend_class_entry swoole_postgresql_coro_ce;
static zend_class_entry *swoole_postgresql_coro_class_entry_ptr;
static int le_link , le_result;

void swoole_postgresql_coro_init(int module_number TSRMLS_DC)
{

    INIT_CLASS_ENTRY(swoole_postgresql_coro_ce, "Swoole\\Coroutine\\PostgreSQL", swoole_postgresql_coro_methods);
    le_link = zend_register_list_destructors_ex(_destroy_pgsql_link, NULL, "pgsql link", module_number);
    le_result = zend_register_list_destructors_ex(_free_result, NULL, "pgsql result", module_number);
    swoole_postgresql_coro_class_entry_ptr = zend_register_internal_class(&swoole_postgresql_coro_ce TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\PostgreSQL", swoole_postgresql_coro_class_entry_ptr);
    }

    REGISTER_LONG_CONSTANT("SW_PGSQL_ASSOC", PGSQL_ASSOC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SW_PGSQL_NUM", PGSQL_NUM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SW_PGSQL_BOTH", PGSQL_BOTH, CONST_CS | CONST_PERSISTENT);

}

static PHP_METHOD(swoole_postgresql_coro, __construct)
{
    coro_check(TSRMLS_C);
    pg_object *pg;
    pg = emalloc(sizeof(pg_object));
    bzero(pg,sizeof(pg_object));
    pg -> object = getThis();
    swoole_set_object(getThis(), pg);
}

static PHP_METHOD(swoole_postgresql_coro, connect)
{
    zval *conninfo;
    PGconn * pgsql;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(conninfo)
    ZEND_PARSE_PARAMETERS_END();

    pgsql = PQconnectStart(Z_STRVAL_P(conninfo));
    int fd =  PQsocket(pgsql);

    php_swoole_check_reactor();

    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_READ, swoole_pgsql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_WRITE, swoole_pgsql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_ERROR, swoole_pgsql_coro_onError);
    }

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, fd, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_WRITE) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }

    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->fd = fd;
    pg_object->conn = pgsql;
    pg_object->status = CONNECTION_STARTED;

    PQsetnonblocking(pgsql , 1);

    if (pgsql==NULL || PQstatus(pgsql)==CONNECTION_BAD)
    {
        swWarn("Unable to connect to PostgreSQL server: [%s]",pgsql);
        if (pgsql)
        {
            PQfinish(pgsql);
        }
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, fd);
    _socket->object = pg_object;
    _socket->active = 0;

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    if (!sw_current_context)
    {
        sw_current_context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 0, sw_current_context);
    }
    sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
    sw_current_context->onTimeout = NULL;
    #if PHP_MAJOR_VERSION < 7
    sw_current_context->coro_params = getThis();
    #else
    sw_current_context->coro_params = *getThis();
    #endif

    //TODO:  add the timeout
    /*
    if (pg_object->timeout > 0)
    {
        php_swoole_check_timer((int) (ph_object->timeout * 1000));
        pg_object->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_pgsql_coro_onTimeout);
    }*/
    coro_save(sw_current_context);
    coro_yield();

}

static int swoole_pgsql_coro_onWrite(swReactor *reactor, swEvent *event)
{
    char *errMsg;
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (event->socket->active)
    {
        return swReactor_onWrite(SwooleG.main_reactor, event);
    }

    socklen_t len = sizeof(SwooleG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
    {
        swWarn("getsockopt(%d) failed. Error: %s[%d]", event->fd, strerror(errno), errno);
        return SW_ERR;
    }

    pg_object *pg_object = event->socket->object;


    // wait the connection ok
    ConnStatusType status =  PQstatus(pg_object->conn);
    if(status != CONNECTION_OK){
        PostgresPollingStatusType flag = PGRES_POLLING_WRITING;
        for (;;)
        {
            switch (flag)
            {
                case PGRES_POLLING_OK:
                    break;
                case PGRES_POLLING_READING:
                    break;
                case PGRES_POLLING_WRITING:
                    break;
                case PGRES_POLLING_FAILED:
                    errMsg = PQerrorMessage(pg_object->conn);
                    swWarn("error:[%s]",errMsg);
                    break;
                default:
                    break;
            }

            flag = PQconnectPoll(pg_object->conn);
            if(flag == PGRES_POLLING_OK )
            {
                break;
            }
            if(flag == PGRES_POLLING_FAILED )
            {
                errMsg = PQerrorMessage(pg_object->conn);
                swWarn("error:[%s] please cofirm that the connection configuration is correct \n",errMsg);
                break;
            }
        }

    }
    //listen read event
    SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_READ);
    //connected
    event->socket->active = 1;

    php_context *sw_current_context = swoole_get_property(pg_object->object, 0);

    zval *retval = NULL;
    zval return_value;
    ZVAL_RES(&return_value, zend_register_resource(pg_object->conn, le_link));

    int ret = coro_resume(sw_current_context, &return_value, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    return SW_OK;
}

static int swoole_pgsql_coro_onRead(swReactor *reactor, swEvent *event)
{
    pg_object *pg_object = (event->socket->object);

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    switch (pg_object->request_type)
    {
        case NORMAL_QUERY:
            query_result_parse(pg_object);
            break;
        case META_DATA:
            meta_data_result_parse(pg_object);
            break;
    }

    return SW_OK;
}

static  int meta_data_result_parse(pg_object *pg_object)
{

    int i, num_rows;
    zval elem;
    PGresult *pg_result;
    zend_bool extended=0;
    pg_result =PQgetResult(pg_object->conn);

    if (PQresultStatus(pg_result) != PGRES_TUPLES_OK || (num_rows = PQntuples(pg_result)) == 0)
    {
        php_error_docref(NULL, E_WARNING, "Table doesn't exists");
        return  0;
    }

    zval  return_value;
    array_init(&return_value);
    zval * retval = NULL;
    array_init(&elem);
    for (i = 0; i < num_rows; i++)
    {
        pg_object->result = pg_result;
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
        add_assoc_bool_ex(&elem, "has default", sizeof("has default") - 1,
                          !strcmp(PQgetvalue(pg_result, i, 5), "t"));
        /* pg_attribute.attndims */
        add_assoc_long_ex(&elem, "array dims", sizeof("array dims") - 1, atoi(PQgetvalue(pg_result, i, 6)));
        /* pg_type.typtype */
        add_assoc_bool_ex(&elem, "is enum", sizeof("is enum") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "e"));
        if (extended) {
            /* pg_type.typtype */
            add_assoc_bool_ex(&elem, "is base", sizeof("is base") - 1, !strcmp(PQgetvalue(pg_result, i, 7), "b"));
            add_assoc_bool_ex(&elem, "is composite", sizeof("is composite") - 1,
                              !strcmp(PQgetvalue(pg_result, i, 7), "c"));
            add_assoc_bool_ex(&elem, "is pesudo", sizeof("is pesudo") - 1,
                              !strcmp(PQgetvalue(pg_result, i, 7), "p"));
            /* pg_description.description */
            add_assoc_string_ex(&elem, "description", sizeof("description") - 1, PQgetvalue(pg_result, i, 8));
        }
        /* pg_attribute.attname */
        name = PQgetvalue(pg_result, i, 0);
        add_assoc_zval(&return_value, name, &elem);

    }
    php_context *sw_current_context = swoole_get_property(pg_object->object, 0);
    int ret  = coro_resume(sw_current_context, &return_value, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&return_value);
    zval_ptr_dtor(&elem);
    return SW_OK;
}


static  int query_result_parse(pg_object *pg_object)
{

    PGresult *pgsql_result;

    ExecStatusType status;


    int error = 0;
    char *errMsg;
    int ret, res;
    zval *retval = NULL;
    zval return_value;
    php_context *sw_current_context = swoole_get_property(pg_object->object, 0);

    pgsql_result =PQgetResult(pg_object->conn);

    status = PQresultStatus(pgsql_result);

    switch (status) {
        case PGRES_EMPTY_QUERY:
        case PGRES_BAD_RESPONSE:
        case PGRES_NONFATAL_ERROR:
        case PGRES_FATAL_ERROR:
            errMsg = PQerrorMessage(pg_object->conn);
            swWarn("Query failed: [%s]",errMsg);

            PQclear(pgsql_result);
            ZVAL_FALSE(&return_value);
            ret = coro_resume(sw_current_context, &return_value,  &retval);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            swoole_postgresql_coro_close(pg_object);
            break;
        case PGRES_COMMAND_OK: /* successful command that did not return rows */
        default:
            pg_object->result = pgsql_result;
            pg_object->row = 0;
            /* Wait to finish sending buffer */
            res = PQflush(pg_object->conn);

            ZVAL_RES(&return_value, zend_register_resource(pg_object, le_result));
            ret = coro_resume(sw_current_context, &return_value,  &retval);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            PQclear(pgsql_result);

            if (error != 0)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
            }

            break;
    }

    return SW_OK;
}

static PHP_METHOD(swoole_postgresql_coro, query)
{
    zval *query;
    PGconn *pgsql;
    PGresult *pgsql_result;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ZVAL(query)
    ZEND_PARSE_PARAMETERS_END();

    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->request_type = NORMAL_QUERY;
    pgsql = pg_object -> conn;

    while ((pgsql_result = PQgetResult(pgsql)))
    {
        PQclear(pgsql_result);
    }

    int ret  = PQsendQuery(pgsql, Z_STRVAL_P(query));
    if(ret == 0)
    {
        char * errMsg = PQerrorMessage(pgsql);
        swWarn("error:[%s]",errMsg);

    }

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
    sw_current_context->onTimeout = NULL;
    #if PHP_MAJOR_VERSION < 7
    sw_current_context->coro_params = getThis();
    #else
    sw_current_context->coro_params = *getThis();
    #endif

    //TODO:  add the timeout
    /*
        if (pg_object->timeout > 0)
        {
            php_swoole_check_timer((int) (ph_object->timeout * 1000));
            pg_object->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_pgsql_coro_onTimeout);
        }*/
    coro_save(sw_current_context);
    coro_yield();
}

/* {{{ php_pgsql_result2array
 */
int swoole_pgsql_result2array(PGresult *pg_result, zval *ret_array, long result_type)
{
    zval row;
    char *field_name;
    size_t num_fields;
    int pg_numrows, pg_row;
    uint32_t i;
    assert(Z_TYPE_P(ret_array) == IS_ARRAY);

    if ((pg_numrows = PQntuples(pg_result)) <= 0)
    {
        return FAILURE;
    }
    for (pg_row = 0; pg_row < pg_numrows; pg_row++)
    {
        array_init(&row);
        for (i = 0, num_fields = PQnfields(pg_result); i < num_fields; i++)
        {
            field_name = PQfname(pg_result, i);
            if (PQgetisnull(pg_result, pg_row, i))
            {
                if (result_type & PGSQL_ASSOC)
                {
                    add_assoc_null(&row, field_name);
                }
                if (result_type & PGSQL_NUM)
                {
                    add_next_index_null(&row);
                }
            }
            else
            {
                char *element = PQgetvalue(pg_result, pg_row, i);
                if (element)
                {
                    const size_t element_len = strlen(element);
                    if (result_type & PGSQL_ASSOC)
                    {
                        add_assoc_stringl(&row, field_name, element, element_len);
                    }
                    if (result_type & PGSQL_NUM)
                    {
                        add_next_index_stringl(&row, element, element_len);
                    }
                }
            }
        }
        add_index_zval(ret_array, pg_row, &row);
    }
    return SUCCESS;
}

static PHP_METHOD(swoole_postgresql_coro, fetchAll)
{
    zval *result;
    PGresult *pgsql_result;
    pg_object *object;
    zend_long result_type = PGSQL_ASSOC;

    ZEND_PARSE_PARAMETERS_START(1,2)
        Z_PARAM_RESOURCE(result)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(result_type)
    ZEND_PARSE_PARAMETERS_END();

    if ((object = (pg_object *)zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL)
    {
        RETURN_FALSE;
    }

    pgsql_result = object->result;
    array_init(return_value);
    if (swoole_pgsql_result2array(pgsql_result, return_value, result_type) == FAILURE)
    {
        zval_dtor(return_value);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_postgresql_coro,affectedRows)
{
    zval *result;
    PGresult *pgsql_result;
    pg_object *object;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_RESOURCE(result)
    ZEND_PARSE_PARAMETERS_END();

    if ((object = (pg_object *)zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL)
    {
        RETURN_FALSE;
    }

    pgsql_result = object->result;
    RETVAL_LONG(atoi(PQcmdTuples(pgsql_result)));
}


//query's num
static PHP_METHOD(swoole_postgresql_coro,numRows)
{
    zval *result;
    PGresult *pgsql_result;
    pg_object *object;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_RESOURCE(result)
    ZEND_PARSE_PARAMETERS_END();

    if ((object = (pg_object *)zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL)
    {
        RETURN_FALSE;
    }

    pgsql_result = object->result;
    RETVAL_LONG(PQntuples(pgsql_result));
}

static PHP_METHOD(swoole_postgresql_coro,metaData)
{

    char *table_name;
    size_t table_name_len;
    zend_bool extended=0;
    PGconn *pgsql;

    PGresult *pg_result;
    char *src, *tmp_name, *tmp_name2 = NULL;
    char *escaped;
    smart_str querystr = {0};
    size_t new_len;


    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STRING(table_name, table_name_len)
    ZEND_PARSE_PARAMETERS_END();

    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->request_type = META_DATA;
    pgsql = pg_object -> conn;


    while ((pg_result = PQgetResult(pgsql)))
    {
        PQclear(pg_result);
    }

    if (!*table_name)
    {
        php_error_docref(NULL, E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }

    src = estrdup(table_name);
    tmp_name = php_strtok_r(src, ".", &tmp_name2);
    if (!tmp_name)
    {
        efree(src);
        php_error_docref(NULL, E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }
    if (!tmp_name2 || !*tmp_name2)
    {
        /* Default schema */
        tmp_name2 = tmp_name;
        tmp_name = "public";
    }

    if (extended)
    {
        smart_str_appends(&querystr,
                          "SELECT a.attname, a.attnum, t.typname, a.attlen, a.attnotNULL, a.atthasdef, a.attndims, t.typtype, "
                                  "d.description "
                                  "FROM pg_class as c "
                                  " JOIN pg_attribute a ON (a.attrelid = c.oid) "
                                  " JOIN pg_type t ON (a.atttypid = t.oid) "
                                  " JOIN pg_namespace n ON (c.relnamespace = n.oid) "
                                  " LEFT JOIN pg_description d ON (d.objoid=a.attrelid AND d.objsubid=a.attnum AND c.oid=d.objoid) "
                                  "WHERE a.attnum > 0  AND c.relname = '");
    }
    else
    {
        smart_str_appends(&querystr,
                          "SELECT a.attname, a.attnum, t.typname, a.attlen, a.attnotnull, a.atthasdef, a.attndims, t.typtype "
                                  "FROM pg_class as c "
                                  " JOIN pg_attribute a ON (a.attrelid = c.oid) "
                                  " JOIN pg_type t ON (a.atttypid = t.oid) "
                                  " JOIN pg_namespace n ON (c.relnamespace = n.oid) "
                                  "WHERE a.attnum > 0 AND c.relname = '");
    }
    escaped = (char *)safe_emalloc(strlen(tmp_name2), 2, 1);
    new_len = PQescapeStringConn(pgsql, escaped, tmp_name2, strlen(tmp_name2), NULL);
    if (new_len)
    {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' AND n.nspname = '");
    escaped = (char *)safe_emalloc(strlen(tmp_name), 2, 1);
    new_len = PQescapeStringConn(pgsql, escaped, tmp_name, strlen(tmp_name), NULL);
    if (new_len)
    {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' ORDER BY a.attnum;");
    smart_str_0(&querystr);
    efree(src);

    //pg_result = PQexec(pgsql, ZSTR_VAL(querystr.s));


    int ret  = PQsendQuery(pgsql, ZSTR_VAL(querystr.s));
    if(ret == 0)
    {
        char * errMsg = PQerrorMessage(pgsql);
        swWarn("error:[%s]",errMsg);

    }
    smart_str_free(&querystr);

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
    sw_current_context->onTimeout = NULL;
#if PHP_MAJOR_VERSION < 7
        sw_current_context->coro_params = getThis();
#else
        sw_current_context->coro_params = *getThis();
#endif
        /*
            if (redis->timeout > 0)
            {
                php_swoole_check_timer((int) (redis->timeout * 1000));
                redis->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
            }*/
        coro_save(sw_current_context);
        coro_yield();

}

/* {{{ void php_pgsql_fetch_hash */
static void php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAMETERS, zend_long result_type, int into_object)
{
    zval               *result, *zrow = NULL;
    PGresult           *pgsql_result;
    pg_object          *pg_result;
    int                i, num_fields, pgsql_row, use_row;
    zend_long          row = -1;
    char               *field_name;
    zval               *ctor_params = NULL;
    zend_class_entry   *ce = NULL;

    if (into_object)
    {
        zend_string *class_name = NULL;

        if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|z!Sz", &result, &zrow, &class_name, &ctor_params) == FAILURE)
        {
            return;
        }
        if (!class_name)
        {
            ce = zend_standard_class_def;
        } else {
            ce = zend_fetch_class(class_name, ZEND_FETCH_CLASS_AUTO);
        }
        if (!ce)
        {
            php_error_docref(NULL, E_WARNING, "Could not find class '%s'", ZSTR_VAL(class_name));
            return;
        }
        result_type = PGSQL_ASSOC;
    }
    else
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|z!l", &result, &zrow, &result_type) == FAILURE)
        {
            return;
        }
    }
    if (zrow == NULL)
    {
        row = -1;
    } else {
        convert_to_long(zrow);
        row = Z_LVAL_P(zrow);
        if (row < 0) {
            php_error_docref(NULL, E_WARNING, "The row parameter must be greater or equal to zero");
            RETURN_FALSE;
        }
    }
    use_row = ZEND_NUM_ARGS() > 1 && row != -1;

    if (!(result_type & PGSQL_BOTH))
    {
        php_error_docref(NULL, E_WARNING, "Invalid result type");
        RETURN_FALSE;
    }

    if ((pg_result = (pg_object *)zend_fetch_resource(Z_RES_P(result), "PostgreSQL result", le_result)) == NULL)
    {
        RETURN_FALSE;
    }

    pgsql_result = pg_result->result;

    if (use_row)
    {
        if (row < 0 || row >= PQntuples(pgsql_result))
        {
            php_error_docref(NULL, E_WARNING, "Unable to jump to row " ZEND_LONG_FMT " on PostgreSQL result index " ZEND_LONG_FMT,
                    row, Z_LVAL_P(result));
            RETURN_FALSE;
        }
        pgsql_row = (int)row;
        pg_result->row = pgsql_row;
    }
    else
    {
        /* If 2nd param is NULL, use internal row counter to access next row */
        pgsql_row = pg_result->row;
        if (pgsql_row < 0 || pgsql_row >= PQntuples(pgsql_result)) {
            RETURN_FALSE;
        }
        pg_result->row++;
    }

    array_init(return_value);
    for (i = 0, num_fields = PQnfields(pgsql_result); i < num_fields; i++)
    {
        if (PQgetisnull(pgsql_result, pgsql_row, i)) {
            if (result_type & PGSQL_NUM)
            {
                add_index_null(return_value, i);
            }
            if (result_type & PGSQL_ASSOC)
            {
                field_name = PQfname(pgsql_result, i);
                add_assoc_null(return_value, field_name);
            }
        }
        else
        {
            char *element = PQgetvalue(pgsql_result, pgsql_row, i);
            if (element)
            {
                const size_t element_len = strlen(element);

                if (result_type & PGSQL_NUM)
                {
                    add_index_stringl(return_value, i, element, element_len);
                }

                if (result_type & PGSQL_ASSOC)
                {
                    field_name = PQfname(pgsql_result, i);
                    add_assoc_stringl(return_value, field_name, element, element_len);
                }
            }
        }
    }

    if (into_object)
    {
        zval dataset;
        zend_fcall_info fci;
        zend_fcall_info_cache fcc;
        zval retval;

        ZVAL_COPY_VALUE(&dataset, return_value);
        object_and_properties_init(return_value, ce, NULL);
        if (!ce->default_properties_count && !ce->__set)
        {
            Z_OBJ_P(return_value)->properties = Z_ARR(dataset);
        }
        else
        {
            zend_merge_properties(return_value, Z_ARRVAL(dataset));
            zval_ptr_dtor(&dataset);
        }

        if (ce->constructor)
        {
            fci.size = sizeof(fci);
            ZVAL_UNDEF(&fci.function_name);
            fci.object = Z_OBJ_P(return_value);
            fci.retval = &retval;
            fci.params = NULL;
            fci.param_count = 0;
            fci.no_separation = 1;

            if (ctor_params && Z_TYPE_P(ctor_params) != IS_NULL)
            {
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

            fcc.initialized = 1;
            fcc.function_handler = ce->constructor;
#if PHP_MINOR_VERSION > 0
            fcc.calling_scope = zend_get_executed_scope();
#else
            fcc.calling_scope = EG(scope);
#endif
            fcc.called_scope = Z_OBJCE_P(return_value);
            fcc.object = Z_OBJ_P(return_value);

            if (zend_call_function(&fci, &fcc) == FAILURE)
            {
                zend_throw_exception_ex(zend_ce_exception, 0, "Could not execute %s::%s()", ZSTR_VAL(ce->name), ZSTR_VAL(ce->constructor->common.function_name));
            } else
            {
                zval_ptr_dtor(&retval);
            }
            if (fci.params)
            {
                efree(fci.params);
            }
        }
        else if (ctor_params)
        {
            zend_throw_exception_ex(zend_ce_exception, 0, "Class %s does not have a constructor hence you cannot use ctor_params", ZSTR_VAL(ce->name));
        }
    }
}
/* }}} */

/* {{{ proto array fetchRow(resource result [, int row [, int result_type]])
   Get a row as an enumerated array */
static PHP_METHOD(swoole_postgresql_coro,fetchRow)
{
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_NUM, 0);
}
/* }}} */

/* {{{ proto array fetchAssoc(resource result [, int row])
   Fetch a row as an assoc array */
static PHP_METHOD(swoole_postgresql_coro,fetchAssoc)
{
    /* pg_fetch_assoc() is added from PHP 4.3.0. It should raise error, when
       there is 3rd parameter */
    if (ZEND_NUM_ARGS() > 2)
        WRONG_PARAM_COUNT;
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_ASSOC, 0);
}
/* }}} */

/* {{{ proto array fetchArray(resource result [, int row [, int result_type]])
   Fetch a row as an array */
static PHP_METHOD(swoole_postgresql_coro,fetchArray)
{
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_BOTH, 0);
}
/* }}} */

/* {{{ proto object fetchObject(resource result [, int row [, string class_name [, NULL|array ctor_params]]])
   Fetch a row as an object */
static PHP_METHOD(swoole_postgresql_coro,fetchObject)
{
    /* fetchObject() allowed result_type used to be. 3rd parameter
       must be allowed for compatibility */
    php_pgsql_fetch_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, PGSQL_ASSOC, 1);
}

/* {{{ _destroy_pgsql_link
 */
static void _destroy_pgsql_link(zend_resource *rsrc)
{
    PGconn *link = (PGconn *)rsrc->ptr;
    PGresult *res;

    while ((res = PQgetResult(link)))
    {
        PQclear(res);
    }
    PQfinish(link);
}

static void _free_result(zend_resource *rsrc)
{
    pg_object *pg_result = (pg_object *)rsrc->ptr;

    efree(pg_result);
}

static int swoole_pgsql_coro_onError(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    pg_object *pg_object = (event->socket->object);
    zval *retval = NULL, *result;
    zval *zobject  = pg_object->object;

    swoole_postgresql_coro_close(pg_object);

    SW_ALLOC_INIT_ZVAL(result);
    ZVAL_BOOL(result, 0);

    php_context *sw_current_context = swoole_get_property(zobject, 0);
    int ret = coro_resume(sw_current_context, result, &retval);
    sw_zval_free(result);

    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return SW_OK;
}

static PHP_METHOD(swoole_postgresql_coro, __destruct)
{
    pg_object *pg_object = swoole_get_object(getThis());
    swoole_postgresql_coro_close(pg_object);

}

static int swoole_postgresql_coro_close(pg_object *pg_object)
{
    if (!pg_object)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_postgresql_coro.");
        return FAILURE;
    }
    SwooleG.main_reactor->del(SwooleG.main_reactor, pg_object->fd);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, pg_object->fd);
    _socket->object = NULL;
    _socket->active = 0;
    efree(pg_object);
    if(pg_object->object)
    {
        php_context *sw_current_context = swoole_get_property(pg_object->object, 0);
        efree(sw_current_context);
    }

    return SUCCESS;
}
#endif
#endif
