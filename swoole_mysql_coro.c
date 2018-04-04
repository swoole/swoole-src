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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_connect, 0, 0, 2)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_prepare, 0, 0, 2)
    ZEND_ARG_INFO(0, query)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_execute, 0, 0, 1)
    ZEND_ARG_INFO(0, params)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_mysql_coro_ce;
static zend_class_entry *swoole_mysql_coro_class_entry_ptr;

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
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
    PHP_FE_END
};

static const zend_function_entry swoole_mysql_coro_statement_methods[] =
{
    PHP_ME(swoole_mysql_coro_statement, execute, arginfo_swoole_mysql_coro_statement_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
    PHP_FE_END
};

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_coro_onConnect(mysql_client *client TSRMLS_DC);
static void swoole_mysql_coro_onTimeout(swTimer *timer, swTimer_node *tnode);

extern swString *mysql_request_buffer;

void swoole_mysql_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_mysql_coro_ce, "Swoole\\Coroutine\\MySQL", swoole_mysql_coro_methods);
    swoole_mysql_coro_class_entry_ptr = zend_register_internal_class(&swoole_mysql_coro_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_mysql_coro_statement_ce, "Swoole\\Coroutine\\MySQL\\Statement",
            swoole_mysql_coro_statement_methods);
    swoole_mysql_coro_statement_class_entry_ptr = zend_register_internal_class(
            &swoole_mysql_coro_statement_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_mysql_coro_exception_ce, "Swoole\\Coroutine\\MySQL\\Exception", NULL);
    swoole_mysql_coro_exception_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_mysql_coro_exception_ce,
            zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\MySQL", swoole_mysql_coro_class_entry_ptr);
        sw_zend_register_class_alias("Co\\MySQL\\Statement", swoole_mysql_coro_statement_class_entry_ptr);
        sw_zend_register_class_alias("Co\\MySQL\\Exception", swoole_mysql_coro_exception_class_entry_ptr);
    }

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

static int swoole_mysql_coro_close(zval *this)
{
    SWOOLE_GET_TSRMLS;
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

    return SUCCESS;
}

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

    if (php_swoole_array_length(params) != statement->param_count)
    {
        swoole_php_fatal_error(E_WARNING, "mysql statement#%d expects %d parameter, %d given.", statement->id,
                statement->param_count, php_swoole_array_length(params));
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

    //null bitmap
    unsigned int null_count = (php_swoole_array_length(params) + 7) / 8;
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

    mysql_request_buffer->length += php_swoole_array_length(params) * 2;

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

    //length
    mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);

    //send data
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 2006 TSRMLS_CC);
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

static PHP_METHOD(swoole_mysql_coro, __construct)
{
	coro_check(TSRMLS_C);

    if (!mysql_request_buffer)
    {
        mysql_request_buffer = swString_new(SW_MYSQL_QUERY_INIT_SIZE);
        if (!mysql_request_buffer)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            RETURN_FALSE;
        }
    }

    mysql_client *client = emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));
    swoole_set_object(getThis(), client);
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
#if PHP_MAJOR_VERSION < 7
        if(Z_TYPE_P(value) == IS_BOOL && Z_BVAL_P(value) == 1)
#else
        if(Z_TYPE_P(value) == IS_TRUE)
#endif
        {
            connector->strict_type = 1;
        }else{
            connector->strict_type = 0;
        }
    } else{
        connector->strict_type = 0;
    }

    swClient *cli = emalloc(sizeof(swClient));
    int type = SW_SOCK_TCP;

    if (strncasecmp(connector->host, ZEND_STRL("unix://")) == 0)
    {
        connector->host = connector->host + 6;
        connector->host_len = connector->host_len - 6;
        type = SW_SOCK_UNIX_STREAM;
    }
    else if (strchr(connector->host, ':'))
    {
        type = SW_SOCK_TCP6;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE, swoole_mysql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_ERROR, swoole_mysql_coro_onError);
    }

    if (swClient_create(cli, type, 0) < 0)
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, "swClient_create failed.", 1 TSRMLS_CC);
        efree(cli);
        sw_zval_ptr_dtor(&server_info);
        RETURN_FALSE;
    }

    int tcp_nodelay = 1;
    if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
    {
        swoole_php_sys_error(E_WARNING, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) failed.", cli->socket->fd);
    }

    int ret = cli->connect(cli, connector->host, connector->port, connector->timeout, 1);
    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE) < 0)
        {
            efree(cli);
            sw_zval_ptr_dtor(&server_info);
            RETURN_FALSE;
        }
    }
    else
    {
        efree(cli);
        snprintf(buf, sizeof(buf), "connect to mysql server[%s:%d] failed.", connector->host, connector->port);
        sw_zval_ptr_dtor(&server_info);
        zend_throw_exception(swoole_mysql_coro_exception_class_entry_ptr, buf, 2 TSRMLS_CC);
        RETURN_FALSE;
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

#if PHP_MAJOR_VERSION < 7
    sw_zval_add_ref(&client->object);
#endif

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
#if PHP_MAJOR_VERSION < 7
	context->coro_params = getThis();
#else
	context->coro_params = *getThis();
#endif
	if (connector->timeout > 0)
	{
        php_swoole_check_timer((int) (connector->timeout * 1000));
        connector->timer = SwooleG.timer.add(&SwooleG.timer, (int) (connector->timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
	}
    client->cid = get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, query)
{
    swString sql;
    bzero(&sql, sizeof(sql));
    double timeout = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|d", &sql.str, &sql.length, &timeout) == FAILURE)
    {
        return;
    }

    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        swoole_php_error(E_WARNING, "object is not instanceof swoole_mysql_coro.");
        RETURN_FALSE;
    }

    if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting for calling recv, cannot send new sql query.");
        RETURN_FALSE;
    }

    if (unlikely(client->cid && client->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "mysql client has already been bound to another coroutine.");
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
    client->cid = get_current_cid();
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
    if (unlikely(client->cid && client->cid != get_current_cid())) {
        swoole_php_fatal_error(E_WARNING, "mysql client has already been bound to another coroutine.");
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
        client->cid = get_current_cid();
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

    if (unlikely(client->cid && client->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "mysql client has already been bound to another coroutine.");
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
        client->cid = get_current_cid();
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

    if (unlikely(client->cid && client->cid != get_current_cid())) {
        swoole_php_fatal_error(E_WARNING, "mysql client has already been bound to another coroutine.");
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
        client->cid = get_current_cid();
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

	if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
	{
		client->iowait = SW_MYSQL_CORO_STATUS_READY;
#if PHP_MAJOR_VERSION >= 7
        zval _result = *client->result;
        efree(client->result);
        zval *result = &_result;
#else
        zval *result = client->result;
#endif
        client->result = NULL;
		RETURN_ZVAL(result, 0, 1);
	}

	if (client->iowait != SW_MYSQL_CORO_STATUS_WAIT)
	{
	    swoole_php_fatal_error(E_WARNING, "no request.");
		RETURN_FALSE;
	}

    client->defer_yield = 1;
    client->cid = get_current_cid();
	php_context *context = swoole_get_property(getThis(), 0);
    coro_save(context);
	coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, prepare)
{
    swString sql;
    bzero(&sql, sizeof(sql));

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s", &sql.str, &sql.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    client->cmd = SW_MYSQL_COM_STMT_PREPARE;

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
            zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        php_context *context = swoole_get_property(getThis(), 0);
        double timeout = client->connector.timeout;
        if (timeout > 0)
        {
            client->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        }
        client->cid = get_current_cid();
        coro_save(context);
        coro_yield();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, execute)
{
    zval *params;
    double timeout = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "a|d", &params, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

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
    client->defer_yield = 1;
    client->cid = get_current_cid();
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_mysql_coro_statement, __destruct)
{
    mysql_statement *stmt = swoole_get_object(getThis());
    if (!stmt)
    {
        return;
    }
    efree(stmt->object);
    stmt->object = NULL;
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
        swoole_php_fatal_error(E_ERROR, "unknown mysql charset[%s].", client->connector.character_set);
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

static PHP_METHOD(swoole_mysql_coro, __destruct)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        return;
    }
    if (client->state != SW_MYSQL_STATE_CLOSED && client->cli)
    {
        swoole_mysql_coro_close(getThis());
    }
    if (client->buffer)
    {
        swString_free(client->buffer);
    }
    efree(client);
    swoole_set_object(getThis(), NULL);

    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
        return;
    }
    if (likely(context->state == SW_CORO_CONTEXT_RUNNING))
    {
        efree(context);
    }
    else
    {
        context->state = SW_CORO_CONTEXT_TERM;
    }
    swoole_set_property(getThis(), 0, NULL);
}

static PHP_METHOD(swoole_mysql_coro, close)
{
    if (swoole_mysql_coro_close(getThis()) == FAILURE)
    {
        RETURN_FALSE;
    }
#if PHP_MAJOR_VERSION < 7
    sw_zval_ptr_dtor(&getThis());
#endif
	RETURN_TRUE;
}

static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *retval = NULL, *result;
    mysql_client *client = event->socket->object;
    zval *zobject = client->object;

    swoole_mysql_coro_close(zobject);

	SW_ALLOC_INIT_ZVAL(result);
	zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "EPOLLERR/EPOLLHUP/EPOLLRDHUP happen!" TSRMLS_CC);
	zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 104 TSRMLS_CC);
    ZVAL_BOOL(result, 0);
	if (client->defer && !client->defer_yield)
	{
		client->result = result;
		return SW_OK;
	}
    client->defer_yield = 0;
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
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *result;
    zval *retval = NULL;

    php_context *ctx = tnode->data;

    SW_ALLOC_INIT_ZVAL(result);
    ZVAL_BOOL(result, 0);
#if PHP_MAJOR_VERSION < 7
    zval *zobject = (zval *)ctx->coro_params;
#else
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;
#endif
    mysql_client *client = swoole_get_object(zobject);

	if (client->iowait == SW_MYSQL_CORO_STATUS_CLOSED)
	{
		zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "connect timeout" TSRMLS_CC);
	}
	else
	{
		zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "query timeout" TSRMLS_CC);
	}

	zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 110 TSRMLS_CC);

	//timeout close conncttion
	client->timer = NULL;
	client->state = SW_MYSQL_STATE_QUERY;
    swoole_mysql_coro_close(zobject);

    if (client->defer && !client->defer_yield)
    {
        client->result = result;
        return;
    }
    client->defer_yield = 0;
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

    mysql_client *client = event->socket->object;
    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ);
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

    int ret;
    if (client->handshake == SW_MYSQL_HANDSHAKE_WAIT_REQUEST)
    {
        ret = mysql_handshake(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_coro_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
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
                swString_clear(buffer);
                client->handshake = SW_MYSQL_HANDSHAKE_WAIT_RESULT;
            }
        }
    }
    else
    {
        ret = mysql_get_result(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_coro_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            swString_clear(buffer);
            client->handshake = SW_MYSQL_HANDSHAKE_COMPLETED;
            swoole_mysql_coro_onConnect(client TSRMLS_CC);
        }
    }
    return SW_OK;
}

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

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
    swString *buffer = client->buffer;

    zval *retval = NULL;
    zval *result = NULL;

    while(1)
    {
        ret = recv(sock, buffer->str + buffer->length, buffer->size - buffer->length, 0);
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
                    goto parse_response;
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

            zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "connection close by peer" TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 111 TSRMLS_CC);
            swoole_mysql_coro_close(zobject);

            SW_ALLOC_INIT_ZVAL(result);
            ZVAL_BOOL(result, 0);
            if (client->defer && !client->defer_yield)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }
            client->defer_yield = 0;
            if (!client->cid)
            {
                return SW_OK;
            }
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
            if (mysql_response(client) < 0)
            {
                return SW_OK;
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
                SW_ALLOC_INIT_ZVAL(result);
                if (client->cmd == SW_MYSQL_COM_STMT_PREPARE)
                {
                    if (client->statement_list == NULL)
                    {
                        client->statement_list = swLinkedList_new(0, NULL);
                    }
                    swLinkedList_append(client->statement_list, client->statement);
                    object_init_ex(result, swoole_mysql_coro_statement_class_entry_ptr);
                    swoole_set_object(result, client->statement);
                    client->statement->object = sw_zval_dup(result);
                }
                else
                {
                    ZVAL_BOOL(result, 1);
                }
            }
            //ERROR
            else if (client->response.response_type == 255)
            {
                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 0);

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
                result = client->response.result_array;
            }

            swString_clear(client->buffer);
            bzero(&client->response, sizeof(client->response));
            if (client->defer && !client->defer_yield)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }
            client->defer_yield = 0;
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
