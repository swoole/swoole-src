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
#include "swoole_postgresql_core.h"
#include "swoole_coroutine.h"

static PHP_METHOD(swoole_postgresql_coro, __construct);
static PHP_METHOD(swoole_postgresql_coro, __destruct);
static PHP_METHOD(swoole_postgresql_coro, connect);
static PHP_METHOD(swoole_postgresql_coro, query);
static PHP_METHOD(swoole_postgresql_coro, fetchAll);
static PHP_METHOD(swoole_postgresql_coro, affectedRows);
static PHP_METHOD(swoole_postgresql_coro, numRows);
static PHP_METHOD(swoole_postgresql_coro,metaData);

static void _close_pgsql_link(zend_resource *rsrc);
static void _free_result(zend_resource *rsrc);
static int swoole_pgsql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_pgsql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_pgsql_coro_onError(swReactor *reactor, swEvent *event);
int php_pgsql_result2array(PGresult *pg_result, zval *ret_array, long result_type);
static int swoole_pgsql_coro_close(zval *this, int fd);
static int swoole_postgresql_coro_close(zval *this);
static  int query_result_parse(pg_object *pg_object);
static  int meta_data_result_parse(pg_object *pg_object);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_connect, 0, 0, -1)
    ZEND_ARG_INFO(0, conninfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_query, 0, 0, 0)
    ZEND_ARG_INFO(0, connection)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_pg_meta_data, 0, 0, 2)
    ZEND_ARG_INFO(0, connection)
    ZEND_ARG_INFO(0, table_name)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_postgresql_coro_methods[] =
{
    PHP_ME(swoole_postgresql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_postgresql_coro, connect, arginfo_pg_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, query, arginfo_pg_query, ZEND_ACC_PUBLIC )
    PHP_ME(swoole_postgresql_coro, fetchAll, arginfo_pg_fetch_all, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, affectedRows, arginfo_pg_fetch_all, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, numRows, arginfo_pg_num_rows, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, metaData, arginfo_pg_meta_data, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_postgresql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

static zend_class_entry swoole_postgresql_coro_ce;
static zend_class_entry *swoole_postgresql_coro_class_entry_ptr;
static int le_link , le_result;

void swoole_postgresql_coro_init(int module_number TSRMLS_DC)
{

    INIT_CLASS_ENTRY(swoole_postgresql_coro_ce, "Swoole\\Coroutine\\PostgreSql", swoole_postgresql_coro_methods);
    le_link = zend_register_list_destructors_ex(_close_pgsql_link, NULL, "pgsql link", module_number);
    le_result = zend_register_list_destructors_ex(_free_result, NULL, "pgsql result", module_number);
    swoole_postgresql_coro_class_entry_ptr = zend_register_internal_class(&swoole_postgresql_coro_ce TSRMLS_CC);
    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\PostgreSql", swoole_postgresql_coro_class_entry_ptr);
    }
}
static PHP_METHOD(swoole_postgresql_coro, __construct)
{
    pg_object *pg_object;
    pg_object = emalloc(sizeof(pg_object));
    bzero(pg_object, sizeof(pg_object));

    swoole_set_object(getThis(), pg_object);

}
static PHP_METHOD(swoole_postgresql_coro, connect)
{
    zval *conninfo;
    PGconn * pgsql;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(conninfo)
    ZEND_PARSE_PARAMETERS_END();

    pgsql = PQconnectStart(Z_STRVAL_P(conninfo));
    //pgsql = PQconnectdb(Z_STRVAL_P(conninfo));
    int fd =  PQsocket(pgsql);

    php_printf("sock :%d \n",fd);
    //PQconnectPoll(pgsql);
    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL))
    {
        php_printf("来reactor了");
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_READ, swoole_pgsql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_WRITE, swoole_pgsql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_ERROR, swoole_pgsql_coro_onError);
    }

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, fd, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_WRITE) < 0)
    {
        //swoole_php_fatal_error(E_WARNING, "swoole_event_add failed. Erorr: %s[%d].", redis->context->errstr, redis->context->err);
        RETURN_FALSE;
    }

    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->fd = fd;
    pg_object->conn = pgsql;
    pg_object->status = CONNECTION_STARTED;
    pg_object->object = getThis();


    int no_block = PQsetnonblocking(pgsql , 1);
    php_printf("isblock:%d",no_block);
    //PQconnectPoll(pgsql);
    //get fd

    if (pgsql==NULL || PQstatus(pgsql)==CONNECTION_BAD) {
        swWarn("Unable to connect to PostgreSQL server: [%s]",pgsql);
        if (pgsql) {
            PQfinish(pgsql);
        }
        //goto err;
        RETURN_FALSE;
    }

    php_printf("来了2");
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
    /*
    if (redis->timeout > 0)
    {
        php_swoole_check_timer((int) (redis->timeout * 1000));
        redis->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
    }
     */
    coro_save(sw_current_context);
    coro_yield();
    //RETVAL_RES(zend_register_resource(pgsql, le_link));
    //return;

/*
err:
    zval_dtor(conninfo);
    RETURN_FALSE;
    */
}

static int swoole_pgsql_coro_onWrite(swReactor *reactor, swEvent *event)
{
    char *errMsg;
    php_printf("来了3");
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
        php_printf("进来了吗");
        for (;;)
        {
            switch (flag)
            {
                case PGRES_POLLING_OK:
                    php_printf("ok1");
                    break;
                case PGRES_POLLING_READING:
                    php_printf("读");
                    break;
                case PGRES_POLLING_WRITING:
                    php_printf("写");
                    break;
                case PGRES_POLLING_FAILED:
                    errMsg = PQerrorMessage(pg_object->conn);
                    php_printf("error:%s",errMsg);
                    break;
                default:
                    break;
            }
            php_printf("what's wrong");

            flag = PQconnectPoll(pg_object->conn);
            if(flag == PGRES_POLLING_OK ){
                php_printf("ok");

                break;

            }
            if(flag == PGRES_POLLING_FAILED ){
                php_printf("error:%s",errMsg);
            }
        }

    }
    /*

 */

    //mysql_client *client = event->socket->object;
    //success
    if (SwooleG.error == 0)
    {
        php_printf("来了33\n");

        //listen read event
        php_printf("eventfd:%d",event->fd);
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_POSTGRESQL | SW_EVENT_READ);
        php_printf("来了34\n");
        //connected
        event->socket->active = 1;
        php_printf("来了35\n");

        php_context *sw_current_context = swoole_get_property(pg_object->object, 0);

        zval *retval = NULL;
        zval return_value;
        ZVAL_RES(&return_value, zend_register_resource(pg_object->conn, le_link));

        int ret = coro_resume(sw_current_context, &return_value, &retval);
        //client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
    }
    else
    {
        //client->connector.error_code = SwooleG.error;
        //client->connector.error_msg = strerror(SwooleG.error);
        //client->connector.error_length = strlen(client->connector.error_msg);
        //swoole_mysql_coro_onConnect(client TSRMLS_CC);
    }
    php_printf("来了36\n");
    return SW_OK;
}

static int swoole_pgsql_coro_onRead(swReactor *reactor, swEvent *event)
{
    PGresult *pgsql_result;
    pg_object *pg_object = (event->socket->object);

    php_printf("来了4");
    swWarn("到这了哦 加油！");
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif



    switch (pg_object->request_type) {
        case NORMAL_QUERY:
            query_result_parse(pg_object);
            break;
        case META_DATA:
            php_printf("ee");
            meta_data_result_parse(pg_object);
            break;
    }
    php_printf("hh");
    //PQflush(pg_object->conn);
    //PQclear(pgsql_result);

    return SW_OK;
}

static  int meta_data_result_parse(pg_object *pg_object){
    int i, num_rows;
    zval elem;
    PGresult *pg_result;
    zend_bool extended=0;


    while ((pg_result =PQgetResult(pg_object->conn))) {

        if (PQresultStatus(pg_result) != PGRES_TUPLES_OK || (num_rows = PQntuples(pg_result)) == 0) {
            php_error_docref(NULL, E_WARNING, "Table doesn't exists");
            return  0;
        }

        zval  return_value;
        array_init(&return_value);
        zval * retval = NULL;
        for (i = 0; i < num_rows; i++) {
            pg_object->result = pg_result;
            char *name;
            array_init(&elem);
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
        int res = coro_resume(sw_current_context, &return_value, &retval);
        zval_ptr_dtor(&return_value);
    }
    zval_ptr_dtor(&elem);
    PQclear(pg_result);



}


static  int query_result_parse(pg_object *pg_object){

    PGresult *pgsql_result;

    ExecStatusType status;

    int error = 0;

    while ((pgsql_result =PQgetResult(pg_object->conn)))
    {

        if (PQresultStatus(pgsql_result) != PGRES_COMMAND_OK) {
            php_printf("unexpected result while sending file list: %s",
                       PQresultErrorMessage(pgsql_result));

            //PQclear(pgsql_result);
        }
        //reactor->del(SwooleG.main_reactor, event->fd);
        /*
        if ((PGG(auto_reset_persistent) & 2) && PQstatus(pgsql) != CONNECTION_OK) {
            PQclear(pgsql_result);
            PQreset(pgsql);
            pgsql_result = PQexec(pgsql, query);
        }
        */

        if (pgsql_result) {
            status = PQresultStatus(pgsql_result);
        } else {
            status = (ExecStatusType) PQstatus(pg_object->conn);
        }

        switch (status) {
            case PGRES_EMPTY_QUERY:
            case PGRES_BAD_RESPONSE:
            case PGRES_NONFATAL_ERROR:
            case PGRES_FATAL_ERROR:
                swWarn("Query failed: [%s]",pg_object->conn);
                PQclear(pgsql_result);
                //RETURN_FALSE;
                break;
            case PGRES_COMMAND_OK: /* successful command that did not return rows */
                php_printf("OKOKKKKKKKKKKKKKKKK");
            default:
                if (pgsql_result) {
                    pg_object->result = pgsql_result;
                    pg_object->row = 0;


                    //zval *zv = &((zend_reference*)te)->val;


                    int is_non_blocking = PQisnonblocking(pg_object->conn);
                    php_printf("is_non_blocking%d",is_non_blocking);
                    int ret ;
                    /* Wait to finish sending buffer */
                    ret = PQflush(pg_object->conn);

                    zval *retval = NULL;
                    zval return_value;
                    ZVAL_RES(&return_value, zend_register_resource(pg_object, le_result));
                    php_context *sw_current_context = swoole_get_property(pg_object->object, 0);
                    int res = coro_resume(sw_current_context, &return_value,  &retval);
                    php_printf("dayuleingma : %d",ret);

                    if (error != 0)
                    {
                        //swoole_php_fatal_error(E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
                    }

                    //efree(event->socket->object);

                    //event->socket->active = 0;

                    //client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
                    //RETURN_RES(zend_register_resource(pg_result, le_result));
                } else {
                    PQclear(pgsql_result);
                    //RETURN_FALSE;
                }
                break;
        }

    }

}

static PHP_METHOD(swoole_postgresql_coro, query)
{
    zval *pgsql_link = NULL;
    zval *query;
    PGconn *pgsql;
    PGresult *pgsql_result;
    ExecStatusType status;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_RESOURCE(pgsql_link)
        Z_PARAM_ZVAL(query)
    ZEND_PARSE_PARAMETERS_END();

    pgsql = (PGconn *)zend_fetch_resource(Z_RES_P(pgsql_link), "postgresql connection", le_link);

    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->request_type = NORMAL_QUERY;

    while ((pgsql_result = PQgetResult(pgsql))) {
        PQclear(pgsql_result);
    }

    int ret  = PQsendQuery(pgsql, Z_STRVAL_P(query));
    if(ret == 0){
        char * errMsg = PQerrorMessage(pgsql);
        php_printf("error:%s",errMsg);

    }
    php_printf("ret:%d",ret);

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
    /*
        if (redis->timeout > 0)
        {
            php_swoole_check_timer((int) (redis->timeout * 1000));
            redis->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
        }*/
    coro_save(sw_current_context);
    coro_yield();
    /*pgsql_result = PQgetResult(pgsql);*/

/*
    if ((PGG(auto_reset_persistent) & 2) && PQstatus(pgsql) != CONNECTION_OK) {
        PQclear(pgsql_result);
        PQreset(pgsql);
        pgsql_result = PQexec(pgsql, query);
    }
    */

/*
    if (pgsql_result) {
        status = PQresultStatus(pgsql_result);
    } else {
        status = (ExecStatusType) PQstatus(pgsql);
    }

    switch (status) {
        case PGRES_EMPTY_QUERY:
        case PGRES_BAD_RESPONSE:
        case PGRES_NONFATAL_ERROR:
        case PGRES_FATAL_ERROR:
            swWarn("Query failed: [%s]",pgsql);
            PQclear(pgsql_result);
            RETURN_FALSE;
            break;
        case PGRES_COMMAND_OK: *//* successful command that did not return rows */
/*
        default:
            if (pgsql_result) {
                pg_result = (pgsql_result_handle *) emalloc(sizeof(pgsql_result_handle));
                pg_result->conn = pgsql;
                pg_result->result = pgsql_result;
                pg_result->row = 0;
                RETURN_RES(zend_register_resource(pg_result, le_result));
            } else {
                PQclear(pgsql_result);
                RETURN_FALSE;
            }
            break;
    }
*/
}

/* {{{ php_pgsql_result2array
 */
int php_pgsql_result2array(PGresult *pg_result, zval *ret_array, long result_type)
{
    zval row;
    char *field_name;
    size_t num_fields;
    int pg_numrows, pg_row;
    uint32_t i;
    assert(Z_TYPE_P(ret_array) == IS_ARRAY);
    php_printf("1111111\n");

    if ((pg_numrows = PQntuples(pg_result)) <= 0) {
        php_printf("222222\n");
        return FAILURE;
    }
    for (pg_row = 0; pg_row < pg_numrows; pg_row++) {
        php_printf("3\n");
        array_init(&row);
        for (i = 0, num_fields = PQnfields(pg_result); i < num_fields; i++) {
            php_printf("4\n");
            field_name = PQfname(pg_result, i);
            if (PQgetisnull(pg_result, pg_row, i)) {
                if (result_type & PGSQL_ASSOC) {
                    add_assoc_null(&row, field_name);
                }
                if (result_type & PGSQL_NUM) {
                    add_next_index_null(&row);
                }
            } else {
                char *element = PQgetvalue(pg_result, pg_row, i);
                if (element) {
                    const size_t element_len = strlen(element);
                    if (result_type & PGSQL_ASSOC) {
                        add_assoc_stringl(&row, field_name, element, element_len);
                    }
                    if (result_type & PGSQL_NUM) {
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
    if (php_pgsql_result2array(pgsql_result, return_value, result_type) == FAILURE)
    {
        zval_dtor(return_value);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_postgresql_coro,affectedRows){
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
static PHP_METHOD(swoole_postgresql_coro,numRows){
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

    zval *pgsql_link;
    char *table_name;
    size_t table_name_len;
    zend_bool extended=0;
    PGconn *pgsql;

    PGresult *pg_result;
    char *src, *tmp_name, *tmp_name2 = NULL;
    char *escaped;
    smart_str querystr = {0};
    size_t new_len;


    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_RESOURCE(pgsql_link)
        Z_PARAM_STRING(table_name, table_name_len)
    ZEND_PARSE_PARAMETERS_END();

    pgsql = (PGconn *)zend_fetch_resource(Z_RES_P(pgsql_link), "postgresql connection", le_link);


    while ((pg_result = PQgetResult(pgsql))) {
        PQclear(pg_result);
    }

    if (!*table_name) {
        php_error_docref(NULL, E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }

    src = estrdup(table_name);
    tmp_name = php_strtok_r(src, ".", &tmp_name2);
    if (!tmp_name) {
        efree(src);
        php_error_docref(NULL, E_WARNING, "The table name must be specified");
        RETURN_FALSE;
    }
    if (!tmp_name2 || !*tmp_name2) {
        /* Default schema */
        tmp_name2 = tmp_name;
        tmp_name = "public";
    }

    if (extended) {
        smart_str_appends(&querystr,
                          "SELECT a.attname, a.attnum, t.typname, a.attlen, a.attnotNULL, a.atthasdef, a.attndims, t.typtype, "
                                  "d.description "
                                  "FROM pg_class as c "
                                  " JOIN pg_attribute a ON (a.attrelid = c.oid) "
                                  " JOIN pg_type t ON (a.atttypid = t.oid) "
                                  " JOIN pg_namespace n ON (c.relnamespace = n.oid) "
                                  " LEFT JOIN pg_description d ON (d.objoid=a.attrelid AND d.objsubid=a.attnum AND c.oid=d.objoid) "
                                  "WHERE a.attnum > 0  AND c.relname = '");
    } else {
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
    if (new_len) {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' AND n.nspname = '");
    escaped = (char *)safe_emalloc(strlen(tmp_name), 2, 1);
    new_len = PQescapeStringConn(pgsql, escaped, tmp_name, strlen(tmp_name), NULL);
    if (new_len) {
        smart_str_appendl(&querystr, escaped, new_len);
    }
    efree(escaped);

    smart_str_appends(&querystr, "' ORDER BY a.attnum;");
    smart_str_0(&querystr);
    efree(src);

    //pg_result = PQexec(pgsql, ZSTR_VAL(querystr.s));


    pg_object *pg_object = swoole_get_object(getThis());
    pg_object->request_type = META_DATA;
    int ret  = PQsendQuery(pgsql, ZSTR_VAL(querystr.s));
    if(ret == 0){
        char * errMsg = PQerrorMessage(pgsql);
        php_printf("error:%s",errMsg);

    }
    php_printf("ret:%d",ret);
    smart_str_free(&querystr);

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
        /*
            if (redis->timeout > 0)
            {
                php_swoole_check_timer((int) (redis->timeout * 1000));
                redis->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
            }*/
        coro_save(sw_current_context);
        coro_yield();



}

/* {{{ _close_pgsql_link
 */
static void _close_pgsql_link(zend_resource *rsrc)
{
    PGconn *link = (PGconn *)rsrc->ptr;
    PGresult *res;

    while ((res = PQgetResult(link))) {
        PQclear(res);
    }
    PQfinish(link);
}

static void _free_result(zend_resource *rsrc)
{
    pg_object *pg_result = (pg_object *)rsrc->ptr;

    PQclear(pg_result->result);
    efree(pg_result);
}

static int swoole_pgsql_coro_onError(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    pg_object *pg_object = (event->socket->object);
    zval *retval = NULL, *result;
    zval *zobject = pg_object->object;

    swoole_mysql_coro_close(zobject);

    SW_ALLOC_INIT_ZVAL(result);
    /*
    zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "EPOLLERR/EPOLLHUP/EPOLLRDHUP happen!" TSRMLS_CC);
    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 104 TSRMLS_CC);
     */
    ZVAL_BOOL(result, 0);
    /*
    if (client->defer && !client->defer_yield)
    {
        client->result = result;
        return SW_OK;
    }
    client->defer_yield = 0;
    client->cid = 0;
     */
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
    swoole_postgresql_coro_close(getThis());

}

static int swoole_postgresql_coro_close(zval *this)
{
    SWOOLE_GET_TSRMLS;
    pg_object *pg_object = swoole_get_object(this);
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
    php_context *sw_current_context = swoole_get_property(this, 0);
    efree(sw_current_context);

    /*
    if (client->timer)
    {
        swTimer_del(&SwooleG.timer, client->timer);
        client->timer = NULL;
    }

    if (client->statement_list)
    {
        swLinkedList_node *node = client->statement_list->head;
        while (node)
        {
            mysql_statement *stmt = node->data;
            if (stmt->object)
            {
                swoole_set_object(stmt->object, NULL);
                efree(stmt->object);
            }
            efree(stmt);
            node = node->next;
        }
        swLinkedList_free(client->statement_list);
    }

    client->cli->close(client->cli);
    swClient_free(client->cli);
    efree(client->cli);
    client->cli = NULL;
    client->state = SW_MYSQL_STATE_CLOSED;
    client->iowait = SW_MYSQL_CORO_STATUS_CLOSED;
     */

    return SUCCESS;
}
