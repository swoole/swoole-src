/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "swoole_mysql.h"

#ifdef SW_USE_MYSQLND
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_charset.h"
#endif

static PHP_METHOD(swoole_mysql_coro, __construct);
static PHP_METHOD(swoole_mysql_coro, __destruct);
static PHP_METHOD(swoole_mysql_coro, connect);
static PHP_METHOD(swoole_mysql_coro, query);
static PHP_METHOD(swoole_mysql_coro, recv);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape);
#endif
static PHP_METHOD(swoole_mysql_coro, begin);
static PHP_METHOD(swoole_mysql_coro, commit);
static PHP_METHOD(swoole_mysql_coro, rollback);
static PHP_METHOD(swoole_mysql_coro, prepare);
static PHP_METHOD(swoole_mysql_coro, setDefer);
static PHP_METHOD(swoole_mysql_coro, getDefer);
static PHP_METHOD(swoole_mysql_coro, close);

static PHP_METHOD(swoole_mysql_coro_statement, __destruct);
static PHP_METHOD(swoole_mysql_coro_statement, execute);
static PHP_METHOD(swoole_mysql_coro_statement, fetch);
static PHP_METHOD(swoole_mysql_coro_statement, fetchAll);
static PHP_METHOD(swoole_mysql_coro_statement, nextResult);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_connect, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_query, 0, 0, 1)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_begin, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_commit, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_rollback, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_prepare, 0, 0, 1)
    ZEND_ARG_INFO(0, query)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

#ifdef SW_USE_MYSQLND
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_execute, 0, 0, 0)
    ZEND_ARG_INFO(0, params)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetch, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetchAll, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_nextResult, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_mysql_coro_ce;
static zend_class_entry *swoole_mysql_coro_class_entry_ptr;
static zend_object_handlers swoole_mysql_coro_handlers;

static zend_class_entry swoole_mysql_coro_exception_ce;
static zend_class_entry *swoole_mysql_coro_exception_class_entry_ptr;

static zend_class_entry swoole_mysql_coro_statement_ce;
static zend_class_entry *swoole_mysql_coro_statement_class_entry_ptr;

static const zend_function_entry swoole_mysql_coro_methods[] =
{
    PHP_ME(swoole_mysql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_mysql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_mysql_coro, connect, arginfo_swoole_mysql_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, query, arginfo_swoole_mysql_coro_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, recv, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql_coro, escape, arginfo_swoole_mysql_coro_escape, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_mysql_coro, begin, arginfo_swoole_mysql_coro_begin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, commit, arginfo_swoole_mysql_coro_commit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, rollback, arginfo_swoole_mysql_coro_rollback, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, prepare, arginfo_swoole_mysql_coro_prepare, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, setDefer, arginfo_swoole_mysql_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_mysql_coro_statement_methods[] =
{
    PHP_ME(swoole_mysql_coro_statement, execute, arginfo_swoole_mysql_coro_statement_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetch, arginfo_swoole_mysql_coro_statement_fetch, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetchAll, arginfo_swoole_mysql_coro_statement_fetchAll, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, nextResult, arginfo_swoole_mysql_coro_statement_nextResult, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_coro_onConnect(mysql_client *client TSRMLS_DC);
static void swoole_mysql_coro_onTimeout(swTimer *timer, swTimer_node *tnode);

static void swoole_mysql_coro_free_storage(zend_object *object);
static zend_object *swoole_mysql_coro_create(zend_class_entry *ce TSRMLS_DC)
{
    zend_object *object;
    object = zend_objects_new(ce);
    object->handlers = &swoole_mysql_coro_handlers;
    object_properties_init(object, ce);

    coro_check(TSRMLS_C);

    mysql_client *client = emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));

    zval _zobject;
    zval* zobject = &_zobject;
    ZVAL_OBJ(zobject, object);
    swoole_set_object(zobject, client);

    return object;
}

void swoole_mysql_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_mysql_coro_ce, "Swoole\\Coroutine\\MySQL", swoole_mysql_coro_methods);
    swoole_mysql_coro_class_entry_ptr = zend_register_internal_class(&swoole_mysql_coro_ce TSRMLS_CC);
    swoole_mysql_coro_class_entry_ptr->create_object = swoole_mysql_coro_create;
    swoole_mysql_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_mysql_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;
    memcpy(&swoole_mysql_coro_handlers, zend_get_std_object_handlers(), sizeof(swoole_mysql_coro_handlers));
    swoole_mysql_coro_handlers.free_obj = swoole_mysql_coro_free_storage;

    INIT_CLASS_ENTRY(swoole_mysql_coro_statement_ce, "Swoole\\Coroutine\\MySQL\\Statement", swoole_mysql_coro_statement_methods);
    swoole_mysql_coro_statement_class_entry_ptr = zend_register_internal_class(&swoole_mysql_coro_statement_ce TSRMLS_CC);
    swoole_mysql_coro_statement_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_mysql_coro_statement_class_entry_ptr->unserialize = zend_class_unserialize_deny;

    INIT_CLASS_ENTRY(swoole_mysql_coro_exception_ce, "Swoole\\Coroutine\\MySQL\\Exception", NULL);
    swoole_mysql_coro_exception_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_mysql_coro_exception_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

    /** ============================================= ALIAS ================================================**/
    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\MySQL", swoole_mysql_coro_class_entry_ptr);
        sw_zend_register_class_alias("Co\\MySQL\\Statement", swoole_mysql_coro_statement_class_entry_ptr);
        sw_zend_register_class_alias("Co\\MySQL\\Exception", swoole_mysql_coro_exception_class_entry_ptr);
    }
    /** ============================================= DECLARES =============================================**/
    zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("serverInfo") - 1, "", ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("sock") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_mysql_coro_class_entry_ptr, SW_STRL("connected") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("connect_error") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("connect_errno") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("affected_rows") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("insert_id") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("error") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("errno") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_long(swoole_mysql_coro_statement_class_entry_ptr, SW_STRL("affected_rows") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_statement_class_entry_ptr, SW_STRL("insert_id") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_mysql_coro_statement_class_entry_ptr, SW_STRL("error") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_coro_statement_class_entry_ptr, SW_STRL("errno") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
}

int mysql_query(zval *zobject, mysql_client *client, swString *sql, zval *callback TSRMLS_DC);

static int swoole_mysql_coro_execute(zval *zobject, mysql_client *client, zval *params TSRMLS_DC)
{
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        return SW_ERR;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        return SW_ERR;
    }

    mysql_statement *statement = swoole_get_object(zobject);
    if (!statement)
    {
        swoole_php_fatal_error(E_WARNING, "mysql preparation is not ready.");
        return SW_ERR;
    }

    int params_length = 0;
    if (params)
    {
        params_length = php_swoole_array_length(params);
    }

    if (params_length != statement->param_count)
    {
        swoole_php_fatal_error(E_WARNING, "mysql statement#%d expects %d parameter, %d given.", statement->id,
                statement->param_count, params_length);
        return SW_ERR;
    }

    swString_clear(mysql_request_buffer);

    client->cmd = SW_MYSQL_COM_STMT_EXECUTE;
    client->statement = statement;

    bzero(mysql_request_buffer->str, 5);
    //command
    mysql_request_buffer->str[4] = SW_MYSQL_COM_STMT_EXECUTE;
    mysql_request_buffer->length = 5;
    char *p = mysql_request_buffer->str;
    p += 5;

    // stmt.id
    mysql_int4store(p, statement->id);
    p += 4;
    // flags = CURSOR_TYPE_NO_CURSOR
    mysql_int1store(p, 0);
    p += 1;
    // iteration_count
    mysql_int4store(p, 1);
    p += 4;

    mysql_request_buffer->length += 9;

    if (params_length == 0)
    {
        goto send;
    }

    //null bitmap
    unsigned int null_count = (params_length + 7) / 8;
    memset(p, 0, null_count);
    p += null_count;
    mysql_request_buffer->length += null_count;

    //rebind
    mysql_int1store(p, 1);
    p += 1;
    mysql_request_buffer->length += 1;

    int i;
    for (i = 0; i < statement->param_count; i++)
    {
        mysql_int2store(p, SW_MYSQL_TYPE_VAR_STRING);
        p += 2;
    }

    mysql_request_buffer->length += params_length * 2;

    long lval;
    char buf[10];
    {
        zval *value;
        zval _value;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            ZVAL_DUP(&_value, value);
            value = &_value;
            convert_to_string(value);
            if (Z_STRLEN_P(value) > 0xffff)
            {
                buf[0] = (char) SW_MYSQL_TYPE_VAR_STRING;
                if (swString_append_ptr(mysql_request_buffer, buf, 1) < 0)
                {
                    zval_dtor(value);
                    return SW_ERR;
                }
            }
            else if (Z_STRLEN_P(value) > 250)
            {
                buf[0] = (char) SW_MYSQL_TYPE_BLOB;
                if (swString_append_ptr(mysql_request_buffer, buf, 1) < 0)
                {
                    zval_dtor(value);
                    return SW_ERR;
                }
            }
            lval = mysql_write_lcb(buf, Z_STRLEN_P(value));
            if (swString_append_ptr(mysql_request_buffer, buf, lval) < 0)
            {
                zval_dtor(value);
                return SW_ERR;
            }
            if (swString_append_ptr(mysql_request_buffer, Z_STRVAL_P(value), Z_STRLEN_P(value)) < 0)
            {
                zval_dtor(value);
                return SW_ERR;
            }
            zval_dtor(value);
        SW_HASHTABLE_FOREACH_END();
    }

    send:

    //length
    mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);

    //send data
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 2013 TSRMLS_CC);
            zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "Lost connection to MySQL server during query" TSRMLS_CC);
        }
        return SW_ERR;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        return SW_OK;
    }

    return SW_OK;
}

static int swoole_mysql_coro_parse_response(mysql_client *client, zval **result, int from_next_result)
{
    zval *zobject = client->object;

    if (mysql_response(client) < 0)
    {
        return SW_ERR;
    }

    //remove from eventloop
    //reactor->del(reactor, event->fd);

    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("affected_rows"),
            client->response.affected_rows TSRMLS_CC);
    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("insert_id"),
            client->response.insert_id TSRMLS_CC);

    if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
    {
        zend_update_property_long(swoole_mysql_coro_statement_class_entry_ptr, client->statement->object,
                ZEND_STRL("affected_rows"), client->response.affected_rows TSRMLS_CC);
        zend_update_property_long(swoole_mysql_coro_statement_class_entry_ptr, client->statement->object,
                ZEND_STRL("insert_id"), client->response.insert_id TSRMLS_CC);
    }

    client->state = SW_MYSQL_STATE_QUERY;

    //OK
    if (client->response.response_type == 0)
    {
        SW_ALLOC_INIT_ZVAL(*result);
        // prepare finished and create statement
        if (client->cmd == SW_MYSQL_COM_STMT_PREPARE)
        {
            if (client->statement_list == NULL)
            {
                client->statement_list = swLinkedList_new(0, NULL);
            }
            swLinkedList_append(client->statement_list, client->statement);
            object_init_ex(*result, swoole_mysql_coro_statement_class_entry_ptr);
            swoole_set_object(*result, client->statement);
            client->statement->object = sw_zval_dup(*result);
        }
        else
        {
            if (from_next_result)
            {
                // pass the ok response ret val
                ZVAL_NULL(*result);
            }
            else
            {
                ZVAL_TRUE(*result);
            }
        }
    }
    //ERROR
    else if (client->response.response_type == 255)
    {
        SW_ALLOC_INIT_ZVAL(*result);
        ZVAL_BOOL(*result, 0);

        zend_update_property_stringl(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"),
                client->response.server_msg, client->response.l_server_msg TSRMLS_CC);
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"),
                client->response.error_code TSRMLS_CC);

        if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            zend_update_property_stringl(swoole_mysql_coro_statement_class_entry_ptr, client->statement->object,
                    ZEND_STRL("error"), client->response.server_msg, client->response.l_server_msg TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_statement_class_entry_ptr, client->statement->object,
                    ZEND_STRL("errno"), client->response.error_code TSRMLS_CC);
        }
    }
    //ResultSet
    else
    {
        if (client->connector.fetch_mode && client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            if (client->statement->result)
            {
                // free the last one
                sw_zval_free(client->statement->result);
                client->statement->result = NULL;
            }
            // save result on statement and wait for fetch
            client->statement->result = client->response.result_array;
            client->response.result_array = NULL;
            // return true (success)]
            SW_ALLOC_INIT_ZVAL(*result);
            ZVAL_TRUE(*result);
        }
        else
        {
            *result = client->response.result_array;
        }
    }

    return SW_OK;
}

static void swoole_mysql_coro_parse_end(mysql_client *client, swString *buffer)
{
    if (client->response.status_code & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "remaining %ju, more results exists", (uintmax_t) (buffer->length - buffer->offset));
    }
    else
    {
        // no more, clean up
        swString_clear(buffer);
    }
    bzero(&client->response, sizeof(client->response));
    client->statement = NULL;
    client->cmd = SW_MYSQL_COM_NULL;
}

static int swoole_mysql_coro_statement_free(mysql_statement *stmt TSRMLS_DC)
{
    if (stmt->object)
    {
        swoole_set_object(stmt->object, NULL);
        efree(stmt->object);
    }

    if (stmt->buffer)
    {
        swString_free(stmt->buffer);
    }

    if (stmt->result)
    {
        sw_zval_free(stmt->result);
    }

    return SW_OK;
}

static int swoole_mysql_coro_statement_close(mysql_statement *stmt TSRMLS_DC)
{
    // call mysql-server to destruct this statement
    swString_clear(mysql_request_buffer);
    stmt->client->cmd = SW_MYSQL_COM_STMT_CLOSE;
    bzero(mysql_request_buffer->str, 5);
    //command
    mysql_request_buffer->str[4] = SW_MYSQL_COM_STMT_CLOSE;
    mysql_request_buffer->length = 5;
    char *p = mysql_request_buffer->str;
    p += 5;

    // stmt.id
    mysql_int4store(p, stmt->id);
    p += 4;
    mysql_request_buffer->length += 4;
    //length
    mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);
    //send data, mysql-server would not reply
    SwooleG.main_reactor->write(SwooleG.main_reactor, stmt->client->fd, mysql_request_buffer->str, mysql_request_buffer->length);

    return SW_OK;
}

static int swoole_mysql_coro_close(zval *this)
{
    mysql_client *client = swoole_get_object(this);
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql_coro.");
        return FAILURE;
    }

    if (!client->cli)
    {
        return FAILURE;
    }

    if (client->connected)
    {
        //send quit command
        swString_clear(mysql_request_buffer);
        client->cmd = SW_MYSQL_COM_QUIT;
        bzero(mysql_request_buffer->str, 5);
        mysql_request_buffer->str[4] = SW_MYSQL_COM_QUIT;//command
        mysql_request_buffer->length = 5;
        mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);
        SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length);
    }

    zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, this, ZEND_STRL("connected"), 0 TSRMLS_CC);
    SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, client->fd);
    _socket->object = NULL;
    _socket->active = 0;

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
            // after connection closed, mysql stmt cache closed too
            // so we needn't send stmt close command here like pdo.
            swoole_mysql_coro_statement_free(stmt);
            efree(stmt);
            node = node->next;
        }
        swLinkedList_free(client->statement_list);
        client->statement_list = NULL;
    }

    client->cli->close(client->cli);
    swClient_free(client->cli);
    efree(client->cli);
    client->cli = NULL;
    client->state = SW_MYSQL_STATE_CLOSED;
    client->iowait = SW_MYSQL_CORO_STATUS_CLOSED;
    //TODO: clear connector

    return SUCCESS;
}

static PHP_METHOD(swoole_mysql_coro, __construct)
{
}

static PHP_METHOD(swoole_mysql_coro, __destruct)
{
}

static PHP_METHOD(swoole_mysql_coro, connect)
{
    zval *server_info;
    char buf[2048];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &server_info) == FAILURE)
    {
        RETURN_FALSE;
    }

    php_swoole_array_separate(server_info);

    HashTable *_ht = Z_ARRVAL_P(server_info);
    zval *value;

    mysql_client *client = swoole_get_object(getThis());
    if (client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "connection to the server has already been established.");
        RETURN_FALSE;
    }

    mysql_connector *connector = &client->connector;

    if (php_swoole_array_get_value(_ht, "host", value))
    {
        convert_to_string(value);
        connector->host = Z_STRVAL_P(value);
        connector->host_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "HOST parameter is required.", 11 TSRMLS_CC);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "port", value))
    {
        convert_to_long(value);
        connector->port = Z_LVAL_P(value);
    }
    else
    {
        connector->port = SW_MYSQL_DEFAULT_PORT;
    }
    if (php_swoole_array_get_value(_ht, "user", value))
    {
        convert_to_string(value);
        connector->user = Z_STRVAL_P(value);
        connector->user_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "USER parameter is required.", 11 TSRMLS_CC);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "password", value))
    {
        convert_to_string(value);
        connector->password = Z_STRVAL_P(value);
        connector->password_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "PASSWORD parameter is required.", 11 TSRMLS_CC);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "database", value))
    {
        convert_to_string(value);
        connector->database = Z_STRVAL_P(value);
        connector->database_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "DATABASE parameter is required.", 11 TSRMLS_CC);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "timeout", value))
    {
        convert_to_double(value);
        connector->timeout = Z_DVAL_P(value);
    }
    else
    {
        connector->timeout = SW_MYSQL_CONNECT_TIMEOUT;
    }
    if (php_swoole_array_get_value(_ht, "charset", value))
    {
        convert_to_string(value);
        connector->character_set = mysql_get_charset(Z_STRVAL_P(value));
        if (connector->character_set < 0)
        {
            snprintf(buf, sizeof(buf), "unknown charset [%s].", Z_STRVAL_P(value));
            zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, buf, 11 TSRMLS_CC);
            sw_zval_ptr_dtor(&server_info);
            RETURN_FALSE;
        }
    }
    else
    {
        connector->character_set = SW_MYSQL_DEFAULT_CHARSET;
    }

    if (php_swoole_array_get_value(_ht, "strict_type", value))
    {
        convert_to_boolean(value);
        connector->strict_type = Z_BVAL_P(value);
    }

    if (php_swoole_array_get_value(_ht, "fetch_mode", value))
    {
        convert_to_boolean(value);
        connector->fetch_mode = Z_BVAL_P(value);
    }

    swClient *cli = emalloc(sizeof(swClient));
    int type = SW_SOCK_TCP;

    if (strncasecmp(connector->host, ZEND_STRL("unix:/")) == 0)
    {
        connector->host = connector->host + 5;
        connector->host_len = connector->host_len - 5;
        type = SW_SOCK_UNIX_STREAM;
    }
    else if (strchr(connector->host, ':'))
    {
        type = SW_SOCK_TCP6;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_READ, swoole_mysql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_WRITE, swoole_mysql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_ERROR, swoole_mysql_coro_onError);
    }

    if (swClient_create(cli, type, 0) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swClient_create() failed. Error: %s [%d]", strerror(errno), errno);
        _failed:
        zend_update_property_string(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("connect_error"), strerror(errno) TSRMLS_CC);
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("connect_errno"), errno TSRMLS_CC);
        efree(cli);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }

    //tcp nodelay
    if (type != SW_SOCK_UNIX_STREAM)
    {
        int tcp_nodelay = 1;
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            swoole_php_sys_error(E_WARNING, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) failed.", cli->socket->fd);
        }
    }

    int ret = cli->connect(cli, connector->host, connector->port, connector->timeout, 1);
    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_WRITE) < 0)
        {
            goto _failed;
        }
    }
    else
    {
        goto _failed;
    }

    zend_update_property(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("serverInfo"), server_info TSRMLS_CC);
    sw_zval_ptr_dtor(&server_info);
    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    if (!client->buffer)
    {
        client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
    }
    else
    {
        swString_clear(client->buffer);
        bzero(&client->response, sizeof(client->response));
    }
    client->fd = cli->socket->fd;
    client->object = getThis();
    client->cli = cli;
    sw_copy_to_stack(client->object, client->_object);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, cli->socket->fd);
    _socket->object = client;
    _socket->active = 0;

    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 0, context);
    }
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->onTimeout = NULL;
    context->coro_params = *getThis();

    if (connector->timeout > 0)
    {
        php_swoole_check_timer((int) (connector->timeout * 1000));
        connector->timer = SwooleG.timer.add(&SwooleG.timer, (int) (connector->timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
    }
    client->cid = sw_get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, query)
{
    swString sql;
    bzero(&sql, sizeof(sql));

    mysql_client *client = swoole_get_object(getThis());
    if (!client || client->state == SW_MYSQL_STATE_CLOSED)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        swoole_php_fatal_error(E_WARNING, "The MySQL connection is not established.");
        RETURN_FALSE;
    }

    if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting for calling recv, cannot send new sql query.");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    double timeout = client->connector.timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|d", &sql.str, &sql.length, &timeout) == FAILURE)
    {
        return;
    }

    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    swString_clear(mysql_request_buffer);

    if (mysql_query(getThis(), client, &sql, NULL TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    client->state = SW_MYSQL_STATE_READ_START;
    php_context *context = swoole_get_property(getThis(), 0);
    if (timeout > 0)
    {
        client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        if (client->timer && client->defer)
        {
            context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
        }
    }
    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }
    client->cid = sw_get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, begin)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }
    if (client->transaction)
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "There is already an active transaction.", 21 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("START TRANSACTION"));
    if (mysql_query(getThis(), client, &sql, NULL TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 1;
        double timeout = client->connector.timeout;
        php_context *context = swoole_get_property(getThis(), 0);
        if (timeout > 0)
        {
            client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
            if (client->timer && client->defer)
            {
                context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
            }
        }
        if (client->defer)
        {
            client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
            //RETURN_TRUE;
        }
        client->cid = sw_get_current_cid();
        coro_save(context);
        coro_yield();
    }
}

static PHP_METHOD(swoole_mysql_coro, commit)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    if (!client->transaction)
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "There is no active transaction.", 22 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("COMMIT"));
    if (mysql_query(getThis(), client, &sql, NULL TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 0;
        php_context *context = swoole_get_property(getThis(), 0);
        double timeout = client->connector.timeout;
        if (timeout > 0)
        {
            client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
            if (client->timer && client->defer)
            {
                context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
            }
        }
        if (client->defer)
        {
            client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
            //RETURN_TRUE;
        }
        client->cid = sw_get_current_cid();
        coro_save(context);
        coro_yield();
    }
}

static PHP_METHOD(swoole_mysql_coro, rollback)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    if (!client->transaction)
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "There is no active transaction.", 22 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("ROLLBACK"));
    if (mysql_query(getThis(), client, &sql, NULL TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 0;
        php_context *context = swoole_get_property(getThis(), 0);
        double timeout = client->connector.timeout;
        if (timeout > 0)
        {
            client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
            if (client->timer && client->defer)
            {
                context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
            }
        }
        if (client->defer)
        {
            client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
            //RETURN_TRUE;
        }
        client->cid = sw_get_current_cid();
        coro_save(context);
        coro_yield();
    }
}

static PHP_METHOD(swoole_mysql_coro, getDefer)
{
    mysql_client *client = swoole_get_object(getThis());
    RETURN_BOOL(client->defer);
}

static PHP_METHOD(swoole_mysql_coro, setDefer)
{
    zend_bool defer = 1;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &defer) == FAILURE)
    {
        return;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (client->iowait > SW_MYSQL_CORO_STATUS_READY)
    {
        RETURN_BOOL(defer);
    }
    client->defer = defer;
    RETURN_TRUE
}

static PHP_METHOD(swoole_mysql_coro, recv)
{
    mysql_client *client = swoole_get_object(getThis());

    if (!client->defer)
    {
        swoole_php_fatal_error(E_WARNING, "you should not use recv without defer ");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_READY;
        zval _result = *client->result;
        efree(client->result);
        zval *result = &_result;
        client->result = NULL;
        RETURN_ZVAL(result, 0, 1);
    }

    if (client->iowait != SW_MYSQL_CORO_STATUS_WAIT)
    {
        swoole_php_fatal_error(E_WARNING, "no request.");
        RETURN_FALSE;
    }

    client->suspending = 1;
    client->cid = sw_get_current_cid();
    php_context *context = swoole_get_property(getThis(), 0);
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, prepare)
{
    swString sql;
    bzero(&sql, sizeof(sql));

    mysql_client *client = swoole_get_object(getThis());
    if (!client || client->state == SW_MYSQL_STATE_CLOSED)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        swoole_php_fatal_error(E_WARNING, "The MySQL connection is not established.");
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    double timeout = client->connector.timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s|d", &sql.str, &sql.length, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    client->cmd = SW_MYSQL_COM_STMT_PREPARE;
    client->state = SW_MYSQL_STATE_READ_START;

    swString_clear(mysql_request_buffer);

    if (mysql_prepare(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //send query
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zval *zobject = getThis();
            zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 2013 TSRMLS_CC);
            zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "Lost connection to MySQL server during query" TSRMLS_CC);
        }
        RETURN_FALSE;
    }

    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }

    php_context *context = swoole_get_property(getThis(), 0);
    if (timeout > 0)
    {
        client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
    }
    client->suspending = 1;
    client->cid = sw_get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro_statement, execute)
{
    zval *params = NULL;

    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    mysql_client *client = stmt->client;
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        RETURN_FALSE;
    }
    if (unlikely(client->cid && client->cid != sw_get_current_cid()))
    {
        swoole_php_fatal_error(E_ERROR, "mysql client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    double timeout = client->connector.timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|ad", &params, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (swoole_mysql_coro_execute(getThis(), client, params TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    php_context *context = swoole_get_property(client->object, 0);
    if (timeout > 0)
    {
        client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        if (client->timer && client->defer)
        {
            context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
        }
    }
    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }
    client->suspending = 1;
    client->cid = sw_get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro_statement, fetch)
{
    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    if (!stmt->client->connector.fetch_mode)
    {
        RETURN_FALSE;
    }

    if (stmt->result)
    {
        zval args[1];
        // the function argument is a reference
        ZVAL_NEW_REF(stmt->result, stmt->result);
        args[0] = *stmt->result;

        zval *fcn;
        SW_MAKE_STD_ZVAL(fcn);
        ZVAL_STRING(fcn, "array_shift");
        int ret;
        zval retval;
        ret = call_user_function_ex(EG(function_table), NULL, fcn, &retval, 1, args, 0, NULL TSRMLS_CC);
        sw_zval_ptr_dtor(&fcn);
        ZVAL_UNREF(stmt->result);

        if (ret == FAILURE)
        {
            if (stmt->result)
            {
                sw_zval_free(stmt->result);
                stmt->result = NULL;
            }
            RETURN_NULL();
        }
        else
        {
            if (php_swoole_array_length(stmt->result) == 0)
            {
                sw_zval_free(stmt->result);
                stmt->result = NULL;
            }
            RETURN_ZVAL(&retval, 0, 1);
        }
    }
    else
    {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, fetchAll)
{
    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    if (!stmt->client->connector.fetch_mode)
    {
        RETURN_FALSE;
    }

    if (stmt->result)
    {
        zval _result = *stmt->result;
        efree(stmt->result);
        zval *result = &_result;
        stmt->result = NULL;
        RETURN_ZVAL(result, 0, 1);
    }
    else
    {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, nextResult)
{
    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    mysql_client *client = stmt->client;

    if (stmt->buffer && stmt->buffer->offset < stmt->buffer->length)
    {
        client->cmd = SW_MYSQL_COM_STMT_EXECUTE;
        client->state = SW_MYSQL_STATE_READ_START;
        client->statement = stmt;
        zval *result = NULL;
        if (swoole_mysql_coro_parse_response(client, &result, 1) == SW_OK)
        {
            swoole_mysql_coro_parse_end(client, stmt->buffer); // ending tidy up

            zval _result = *result;
            efree(result);
            result = &_result;
            RETURN_ZVAL(result, 0, 1);
        }
        else
        {
            RETURN_FALSE;
        }
    }
    else
    {
        RETURN_NULL()
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        return;
    }
    swoole_mysql_coro_statement_close(stmt TSRMLS_CC);
    swoole_mysql_coro_statement_free(stmt);
    swLinkedList_remove(stmt->client->statement_list, stmt);
    efree(stmt);
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape)
{
    swString str;
    bzero(&str, sizeof(str));
    long flags;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &str.str, &str.length, &flags) == FAILURE)
    {
        return;
    }

    if (str.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "String is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        RETURN_FALSE;
    }

    char *newstr = safe_emalloc(2, str.length + 1, 1);
    if (newstr == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "emalloc(%ld) failed.", str.length + 1);
        RETURN_FALSE;
    }

    const MYSQLND_CHARSET* cset = mysqlnd_find_charset_nr(client->connector.character_set);
    if (cset == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "unknown mysql charset[%d].", client->connector.character_set);
        RETURN_FALSE;
    }
    int newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str.str, str.length TSRMLS_CC);
    if (newstr_len < 0)
    {
        swoole_php_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed.");
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(newstr, newstr_len, 0);
}
#endif

static PHP_METHOD(swoole_mysql_coro, close)
{
    if (swoole_mysql_coro_close(getThis()) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static void swoole_mysql_coro_free_storage(zend_object *object)
{
    // as __destruct
    zval _zobject;
    zval* zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    mysql_client *client = swoole_get_object(zobject);
    if (!client)
    {
        goto _dtor;
    }
    if (client->state != SW_MYSQL_STATE_CLOSED && client->cli)
    {
        swoole_mysql_coro_close(zobject);
    }
    if (client->buffer)
    {
        swString_free(client->buffer);
    }
    efree(client);
    swoole_set_object(zobject, NULL);

    php_context *context = swoole_get_property(zobject, 0);
    if (!context)
    {
        goto _dtor;
    }
    if (likely(context->state == SW_CORO_CONTEXT_RUNNING))
    {
        efree(context);
    }
    else
    {
        context->state = SW_CORO_CONTEXT_TERM;
    }
    swoole_set_property(zobject, 0, NULL);

    _dtor:
    // dtor object
    zend_object_std_dtor(object);
}

static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL, *result;
    mysql_client *client = event->socket->object;
    zval *zobject = client->object;

    swoole_mysql_coro_close(zobject);

    SW_ALLOC_INIT_ZVAL(result);
    zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "EPOLLERR/EPOLLHUP/EPOLLRDHUP happen!" TSRMLS_CC);
    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 104 TSRMLS_CC);
    ZVAL_BOOL(result, 0);
    if (client->defer && !client->suspending)
    {
        client->result = result;
        return SW_OK;
    }
    client->suspending = 0;
    client->cid = 0;
    php_context *sw_current_context = swoole_get_property(zobject, 0);
    int ret = coro_resume(sw_current_context, result, &retval);
    sw_zval_free(result);

    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return SW_OK;
}

static void swoole_mysql_coro_onConnect(mysql_client *client TSRMLS_DC)
{
    zval *zobject = client->object;

    zval *retval = NULL;
    zval *result;

    if (client->connector.timer)
    {
        swTimer_del(&SwooleG.timer, client->connector.timer);
        client->connector.timer = NULL;
    }

    SW_MAKE_STD_ZVAL(result);

    //SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    if (client->connector.error_code > 0)
    {
        zend_update_property_stringl(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), client->connector.error_msg, client->connector.error_length TSRMLS_CC);
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), client->connector.error_code TSRMLS_CC);

        ZVAL_BOOL(result, 0);

        swoole_mysql_coro_close(zobject);
    }
    else
    {
        client->state = SW_MYSQL_STATE_QUERY;
        client->iowait = SW_MYSQL_CORO_STATUS_READY;
        zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 1 TSRMLS_CC);
        client->connected = 1;
        ZVAL_BOOL(result, 1);
    }

    client->cid = 0;

    php_context *sw_current_context = swoole_get_property(zobject, 0);
    int ret = coro_resume(sw_current_context, result, &retval);
    sw_zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void swoole_mysql_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *result;
    zval *retval = NULL;

    php_context *ctx = tnode->data;

    SW_ALLOC_INIT_ZVAL(result);
    ZVAL_BOOL(result, 0);
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;

    mysql_client *client = swoole_get_object(zobject);

    if (client->iowait == SW_MYSQL_CORO_STATUS_CLOSED)
    {
        zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "connect timeout" TSRMLS_CC);
    }
    else
    {
        zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "query timeout" TSRMLS_CC);
    }

    zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), ETIMEDOUT TSRMLS_CC);

    //timeout close conncttion
    client->timer = NULL;
    client->state = SW_MYSQL_STATE_QUERY;
    swoole_mysql_coro_close(zobject);

    if (client->defer && !client->suspending)
    {
        client->result = result;
        return;
    }
    client->suspending = 0;
    client->cid = 0;

    int ret = coro_resume(ctx, result, &retval);

    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_free(result);
}

static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event)
{
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

    mysql_client *client = event->socket->object;
    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_READ);
        //connected
        event->socket->active = 1;
        client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
    }
    else
    {
        client->connector.error_code = SwooleG.error;
        client->connector.error_msg = strerror(SwooleG.error);
        client->connector.error_length = strlen(client->connector.error_msg);
        swoole_mysql_coro_onConnect(client TSRMLS_CC);
    }
    return SW_OK;
}

static int swoole_mysql_coro_onHandShake(mysql_client *client TSRMLS_DC)
{
    swString *buffer = client->buffer;
    swClient *cli = client->cli;
    mysql_connector *connector = &client->connector;

    int n = cli->recv(cli, buffer->str + buffer->length, buffer->size - buffer->length, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", cli->socket->fd);
            return SW_ERR;
        case SW_CLOSE:
            goto system_call_error;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_ERR;
        }
    }
    else if (n == 0)
    {
        errno = ECONNRESET;
        goto system_call_error;
    }

    buffer->length += n;

    int ret = 0;

    _again:
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "handshake on %d", client->handshake);
    if (client->switch_check)
    {
        // after handshake we need check if server request us to switch auth type first
        goto _check_switch;
    }

    switch(client->handshake)
    {
    case SW_MYSQL_HANDSHAKE_WAIT_REQUEST:
    {
        client->switch_check = 1;
        ret = mysql_handshake(connector, buffer->str, buffer->length);

        if (ret < 0)
        {
            goto _error;
        }
        else if (ret > 0)
        {
            _send:
            if (cli->send(cli, connector->buf, connector->packet_length + 4, 0) < 0)
            {
                system_call_error: connector->error_code = errno;
                connector->error_msg = strerror(errno);
                connector->error_length = strlen(connector->error_msg);
                swoole_mysql_coro_onConnect(client TSRMLS_CC);
                return SW_OK;
            }
            else
            {
                // clear for the new package
                swString_clear(buffer);
                // mysql_handshake will return the next state flag
                client->handshake = ret;
            }
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_SWITCH:
    {
        _check_switch:
        client->switch_check = 0;
        int next_state;
        // handle auth switch request
        switch (next_state = mysql_auth_switch(connector, buffer->str, buffer->length))
        {
        case SW_AGAIN:
            return SW_OK;
        case SW_ERR:
            // not the switch package, go to the next
            goto _again;
        default:
            ret = next_state;
            goto _send;
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_SIGNATURE:
    {
        switch (mysql_parse_auth_signature(buffer, connector))
        {
        case SW_MYSQL_AUTH_SIGNATURE_SUCCESS:
        {
            client->handshake = SW_MYSQL_HANDSHAKE_WAIT_RESULT;
            break;
        }
        case SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED:
        {
            // send response and wait RSA public key
            ret = SW_MYSQL_HANDSHAKE_WAIT_RSA; // handshake = ret
            goto _send;
        }
        default:
        {
            goto _error;
        }
        }

        // may be more packages
        if (buffer->offset < buffer->length)
        {
            goto _again;
        }
        else
        {
            swString_clear(buffer);
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_RSA:
    {
        // encode by RSA
#ifdef SW_MYSQL_RSA_SUPPORT
        switch (mysql_parse_rsa(connector, SWSTRING_CURRENT_VL(buffer)))
        {
        case SW_AGAIN:
            return SW_OK;
        case SW_OK:
            ret = SW_MYSQL_HANDSHAKE_WAIT_RESULT; // handshake = ret
            goto _send;
        default:
            goto _error;
        }
#else
        connector->error_code = -1;
        connector->error_msg = "MySQL8 RSA-Auth need enable OpenSSL!";
        connector->error_length = strlen(connector->error_msg);
        swoole_mysql_coro_onConnect(client TSRMLS_CC);
        return SW_OK;
#endif
        break;
    }
    default:
    {
        ret = mysql_get_result(connector, SWSTRING_CURRENT_VL(buffer));
        if (ret < 0)
        {
            _error:
            swoole_mysql_coro_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            swString_clear(buffer);
            client->handshake = SW_MYSQL_HANDSHAKE_COMPLETED;
            swoole_mysql_coro_onConnect(client TSRMLS_CC);
        }
        // else recv again
    }
    }

    return SW_OK;
}

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event)
{
    mysql_client *client = event->socket->object;
    if (client->handshake != SW_MYSQL_HANDSHAKE_COMPLETED)
    {
        return swoole_mysql_coro_onHandShake(client TSRMLS_CC);
    }

    if (client->timer)
    {
        swTimer_del(&SwooleG.timer, client->timer);
        client->timer = NULL;
    }

    int sock = event->fd;
    int ret;

    zval *zobject = client->object;

    swString *buffer;
    if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
    {
        if (client->statement->buffer == NULL)
        {
            // statement save the response data itself
            client->statement->buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }
        buffer = client->statement->buffer;
    }
    else
    {
        buffer = client->buffer;
    }

    zval *retval = NULL;
    zval *result = NULL;

    while(1)
    {
        ret = recv(sock, buffer->str + buffer->length, buffer->size - buffer->length, 0);
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "recv-ret=%d, buffer-length=%zu.", ret, buffer->length);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                switch (swConnection_error(errno))
                {
                case SW_ERROR:
                    swSysError("Read from socket[%d] failed.", event->fd);
                    return SW_ERR;
                case SW_CLOSE:
                    goto close_fd;
                case SW_WAIT:
                    if (client->check_offset == buffer->length)
                    {
                        return SW_OK;
                    }
                    else
                    {
                        // have already check all of the data
                        goto parse_response;
                    }
                default:
                    return SW_ERR;
                }
            }
        }
        else if (ret == 0)
        {
            close_fd:
            if (client->state == SW_MYSQL_STATE_READ_END)
            {
                goto parse_response;
            }


            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 111 TSRMLS_CC);
            zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "connection close by peer" TSRMLS_CC);
            if (client->connected)
            {
                client->connected = 0;
                zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 2006 TSRMLS_CC);
                zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "MySQL server has gone away" TSRMLS_CC);
            }
            swoole_mysql_coro_close(zobject);

            if (!client->cid)
            {
                return SW_OK;
            }

            SW_ALLOC_INIT_ZVAL(result);
            ZVAL_BOOL(result, 0);
            if (client->defer && !client->suspending)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }
            client->suspending = 0;
            client->cid = 0;

            php_context *sw_current_context = swoole_get_property(zobject, 0);
            ret = coro_resume(sw_current_context, result, &retval);
            sw_zval_free(result);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            client->state = SW_MYSQL_STATE_QUERY;
            return SW_OK;
        }
        else
        {
            buffer->length += ret;
            //recv again
            if (buffer->length == buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    swoole_php_fatal_error(E_ERROR, "malloc failed.");
                    reactor->del(SwooleG.main_reactor, event->fd);
                }
                continue;
            }

            parse_response:

            // always check that is package complete
            // and maybe more responses has already received in buffer, we check it now.
            if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE && mysql_is_over(client) != SW_OK)
            {
                // the **last** sever status flag shows that more results exist but we hasn't received.
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "need more");
                continue;
            }

            if (swoole_mysql_coro_parse_response(client, &result, 0) != SW_OK)
            {
                return SW_OK;//parse error
            }
            swoole_mysql_coro_parse_end(client, buffer); // ending tidy up


            if (client->defer && !client->suspending)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }
            client->suspending = 0;
            client->iowait = SW_MYSQL_CORO_STATUS_READY;
            client->cid = 0;

            php_context *sw_current_context = swoole_get_property(zobject, 0);
            ret = coro_resume(sw_current_context, result, &retval);
            if (result)
            {
                sw_zval_free(result);
            }
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            return SW_OK;
        }
    }
    return SW_OK;
}

#endif
