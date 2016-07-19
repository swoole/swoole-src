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

static PHP_METHOD(swoole_mysql_coro, __construct);
static PHP_METHOD(swoole_mysql_coro, __destruct);
static PHP_METHOD(swoole_mysql_coro, connect);
static PHP_METHOD(swoole_mysql_coro, query);
static PHP_METHOD(swoole_mysql_coro, close);

static zend_class_entry swoole_mysql_coro_ce;
static zend_class_entry *swoole_mysql_coro_class_entry_ptr;

static zend_class_entry swoole_mysql_coro_exception_ce;
static zend_class_entry *swoole_mysql_coro_exception_class_entry;

static const zend_function_entry swoole_mysql_coro_methods[] =
{
    PHP_ME(swoole_mysql_coro, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_mysql_coro, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_mysql_coro, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, query, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, close, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int mysql_request(swString *sql, swString *buffer);
static int mysql_handshake(mysql_connector *connector, char *buf, int len);
static int mysql_get_result(mysql_connector *connector, char *buf, int len);

#ifdef SW_MYSQL_DEBUG
static void mysql_client_info(mysql_client *client);
static void mysql_column_info(mysql_field *field);
#endif

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_coro_onConnect(mysql_client *client TSRMLS_DC);
static void swoole_mysql_coro_onTimeout(php_context *cxt);

static swString *mysql_request_buffer = NULL;
static int isset_event_callback = 0;

void swoole_mysql_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_coro_ce, "swoole_mysql_coro", "Swoole\\Coroutine\\MySQL", swoole_mysql_coro_methods);
	swoole_mysql_coro_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_mysql_coro_ce, swoole_client_multi_class_entry_ptr, "swoole_client_multi" TSRMLS_CC);

    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_coro_exception_ce, "swoole_mysql_coro_exception", "Swoole\\MySQL\\Exception", NULL);
    swoole_mysql_coro_exception_class_entry = sw_zend_register_internal_class_ex(&swoole_mysql_coro_exception_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

    zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("serverInfo") - 1, "", ZEND_ACC_PRIVATE TSRMLS_CC);
	zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("sock") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_bool(swoole_mysql_coro_class_entry_ptr, SW_STRL("connected") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("connect_error") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("connect_errno") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("affected_rows") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("insert_id") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(swoole_mysql_coro_class_entry_ptr, SW_STRL("error") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_mysql_coro_class_entry_ptr, SW_STRL("errno") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
}

static int mysql_request(swString *sql, swString *buffer)
{
    bzero(buffer->str, 5);
    //length
    mysql_pack_length(sql->length + 1, buffer->str);
    //command
    buffer->str[4] = SW_MYSQL_COM_QUERY;
    buffer->length = 5;
    return swString_append(buffer, sql);
}

static int mysql_get_result(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;
    int packet_length = mysql_uint3korr(tmp);
    if (len < packet_length + 4)
    {
        return 0;
    }
    //int packet_number = tmp[3];
    tmp += 4;

    uint8_t opcode = *tmp;
    tmp += 1;

    //ERROR Packet
    if (opcode == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = packet_length - 3;
        return -1;
    }
    else
    {
        return 1;
    }
}

static int mysql_handshake(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;
    /**
     * handshake request
     */
    mysql_handshake_request request;
    bzero(&request, sizeof(request));

    request.packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < request.packet_length + 4)
    {
        return 0;
    }

    request.packet_number = tmp[3];
    tmp += 4;

    request.protocol_version = *tmp;
    tmp += 1;

    //ERROR Packet
    if (request.protocol_version == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = request.packet_length - 3;
        return -1;
    }

    request.server_version = tmp;
    tmp += (strlen(request.server_version) + 1);

    request.connection_id = *((int *) tmp);
    tmp += 4;

    memcpy(request.auth_plugin_data, tmp, 8);
    tmp += 8;

    request.filler = *tmp;
    tmp += 1;

    memcpy(((char *) (&request.capability_flags)) + 2, tmp, 2);
    tmp += 2;

    if (tmp - tmp < len)
    {
        request.character_set = *tmp;
        tmp += 1;

        memcpy(&request.status_flags, tmp, 2);
        tmp += 2;

        memcpy(&request.capability_flags, tmp, 2);
        tmp += 2;

        request.l_auth_plugin_data = *tmp;
        tmp += 1;

        memcpy(&request.reserved, tmp, sizeof(request.reserved));
        tmp += sizeof(request.reserved);

        if (request.capability_flags & SW_MYSQL_CLIENT_SECURE_CONNECTION)
        {
            int len = MAX(13, request.l_auth_plugin_data - 8);
            memcpy(request.auth_plugin_data + 8, tmp, len);
            tmp += len;
        }

        if (request.capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH)
        {
            request.auth_plugin_name = tmp;
            request.l_auth_plugin_name = strlen(tmp);
        }
    }

    int value;
    tmp = connector->buf + 4;

    //capability flags, CLIENT_PROTOCOL_41 always set
    value = SW_MYSQL_CLIENT_PROTOCOL_41 | SW_MYSQL_CLIENT_SECURE_CONNECTION | SW_MYSQL_CLIENT_CONNECT_WITH_DB | SW_MYSQL_CLIENT_PLUGIN_AUTH;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //max-packet size
    value = 300;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //character set
    *tmp = 10;
    tmp += 1;

    //string[23]     reserved (all [0])
    tmp += 23;

    //string[NUL]    username
    memcpy(tmp, connector->user, connector->user_len);
    tmp[connector->user_len] = '\0';
    tmp += (connector->user_len + 1);

    //auth-response
    char hash_0[20];
    bzero(hash_0, sizeof(hash_0));
    php_swoole_sha1(connector->password, connector->password_len, (uchar *) hash_0);

    char hash_1[20];
    bzero(hash_1, sizeof(hash_1));
    php_swoole_sha1(hash_0, sizeof(hash_0), (uchar *) hash_1);

    char str[40];
    memcpy(str, request.auth_plugin_data, 20);
    memcpy(str + 20, hash_1, 20);

    char hash_2[20];
    php_swoole_sha1(str, sizeof(str), (uchar *) hash_2);

    char hash_3[20];

    int *a = (int *) hash_2;
    int *b = (int *) hash_0;
    int *c = (int *) hash_3;

    int i;
    for (i = 0; i < 5; i++)
    {
        c[i] = a[i] ^ b[i];
    }

    *tmp = 20;
    memcpy(tmp + 1, hash_3, 20);
    tmp += 21;

    //string[NUL]    database
    memcpy(tmp, connector->database, connector->database_len);
    tmp[connector->database_len] = '\0';
    tmp += (connector->database_len + 1);

    //string[NUL]    auth plugin name
    memcpy(tmp, request.auth_plugin_name, request.l_auth_plugin_name);
    tmp[request.l_auth_plugin_name] = '\0';
    tmp += (request.l_auth_plugin_name + 1);

    connector->packet_length = tmp - connector->buf - 4;
    mysql_pack_length(connector->packet_length, connector->buf);
    connector->buf[3] = 1;

    return 1;
}

static int mysql_response(mysql_client *client)
{
    swString *buffer = client->buffer;

    char *p = buffer->str + buffer->offset;
    int ret;
    char nul;
    int n_buf = buffer->length - buffer->offset;

    while (n_buf > 0)
    {
        switch (client->state)
        {
        case SW_MYSQL_STATE_READ_START:
            if (buffer->length - buffer->offset < 5)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }
            client->response.packet_length = mysql_uint3korr(p);
            client->response.packet_number = p[3];
            p += 4;
            n_buf -= 4;

            if (n_buf < client->response.packet_length)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }

            client->response.response_type = p[0];
            p ++;
            n_buf --;

            /* error */
            if (client->response.response_type == 0xFF)
            {
                client->response.error_code = mysql_uint2korr(p);
                /* status flag 1byte (#), skip.. */
                memcpy(client->response.status_msg, p + 3, 5);
                client->response.server_msg = p + 8;
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* eof */
            else if (client->response.response_type == 254)
            {
                client->response.warnings = mysql_uint2korr(p);
                client->response.status_code = mysql_uint2korr(p + 2);
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_ERR;
            }
            /* ok */
            else if (client->response.response_type == 0)
            {
                /* affected rows */
                ret = mysql_length_coded_binary(p, (ulong_t *) &client->response.affected_rows, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* insert id */
                ret = mysql_length_coded_binary(p, (ulong_t *) &client->response.insert_id, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* server status */
                client->response.status_code = mysql_uint2korr(p);
                n_buf -= 2;
                p += 2;

                /* server warnings */
                client->response.warnings = mysql_uint2korr(p);

                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* result set */
            else
            {
                client->buffer->offset += 5;
                client->response.num_column = client->response.response_type;
                client->response.columns = ecalloc(client->response.num_column, sizeof(mysql_field));
                client->state = SW_MYSQL_STATE_READ_FIELD;
                break;
            }

        case SW_MYSQL_STATE_READ_FIELD:
            if (mysql_read_columns(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_ROW;
                break;
            }

        case SW_MYSQL_STATE_READ_ROW:
            if (mysql_read_rows(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }

        default:
            return SW_ERR;
        }
    }

    return SW_OK;
}

#ifdef SW_MYSQL_DEBUG

static void mysql_client_info(mysql_client *client)
{
    printf("\n"SW_START_LINE"\nmysql_client\nbuffer->offset=%ld\nbuffer->length=%ld\nstatus=%d\n"
            "packet_length=%d\npacket_number=%d\n"
            "insert_id=%d\naffected_rows=%d\n"
            "warnings=%d\n"SW_END_LINE, client->buffer->offset, client->buffer->length, client->response.status_code,
            client->response.packet_length, client->response.packet_number,
            client->response.insert_id, client->response.affected_rows,
            client->response.warnings);
    int i;

    if (client->response.num_column)
    {
        for (i = 0; i < client->response.num_column; i++)
        {
            mysql_column_info(&client->response.columns[i]);
        }
    }
}

static void mysql_column_info(mysql_field *field)
{
    printf("\n"SW_START_LINE"\nname=%s, table=%s, db=%s\n"
            "name_length=%d, table_length=%d, db_length=%d\n"
            "catalog=%s, default_value=%s\n"
            "length=%ld, type=%d\n"SW_END_LINE,
            field->name, field->table, field->db,
            field->name_length, field->table_length, field->db_length,
            field->catalog, field->def,
            field->length, field->type
           );
}

#endif


static PHP_METHOD(swoole_mysql_coro, __construct)
{
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

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &server_info) == FAILURE)
    {
        RETURN_FALSE;
    }

    HashTable *_ht = Z_ARRVAL_P(server_info);
    zval *value;

    mysql_client *client = swoole_get_object(getThis());
    mysql_connector *connector = &client->connector;

    if (php_swoole_array_get_value(_ht, "host", value))
    {
        convert_to_string(value);
        connector->host = Z_STRVAL_P(value);
        connector->host_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, "HOST parameter is required.", 11 TSRMLS_CC);
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
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, "USER parameter is required.", 11 TSRMLS_CC);
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
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, "PASSWORD parameter is required.", 11 TSRMLS_CC);
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
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, "DATABASE parameter is required.", 11 TSRMLS_CC);
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

    char buf[2048];
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
    if (!isset_event_callback)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE, swoole_mysql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_ERROR, swoole_mysql_coro_onError);
    }

    if (swClient_create(cli, type, 0) < 0)
    {
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, "swClient_create failed.", 1 TSRMLS_CC);
		efree(cli);
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
            RETURN_FALSE;
        }
    }
    else
    {
		efree(cli);
        snprintf(buf, sizeof(buf), "connect to mysql server[%s:%d] failed.", connector->host, connector->port);
        zend_throw_exception(swoole_mysql_coro_exception_class_entry, buf, 2 TSRMLS_CC);
        RETURN_FALSE;
    }

    zend_update_property(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("serverInfo"), server_info TSRMLS_CC);
	zend_update_property_long(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

	if (!client->buffer)
	{
		client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
	}
    client->fd = cli->socket->fd;
    client->object = getThis();
    client->cli = cli;
    sw_copy_to_stack(client->object, client->_object);

	swConnection *socket = swReactor_get(SwooleG.main_reactor, cli->socket->fd);
    socket->object = client;

    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 0, context);
    }
	context->onTimeout = swoole_mysql_coro_onTimeout;
	context->coro_params = getThis();
	context->coro_params_cnt = 1;
	coro_save(return_value, return_value_ptr, context);
	coro_yield();
}

static PHP_METHOD(swoole_mysql_coro, query)
{
    swString sql;
    bzero(&sql, sizeof(sql));
    double timeout = 0.0;

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
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql_coro.");
        RETURN_FALSE;
    }

    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    swString_clear(mysql_request_buffer);

    if (mysql_request(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //add to eventloop
    if (SwooleG.main_reactor->add(SwooleG.main_reactor, client->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed.");
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
		client->cli->timeout_id = php_swoole_add_timer_coro((int)(timeout*1000), client->fd, (void *)context TSRMLS_CC);
		if (swoole_multi_is_multi_mode(getThis()) == CORO_MULTI)
		{
			RETURN_TRUE;
		}
		coro_save(return_value, return_value_ptr, context);
		coro_yield();
    }
}

static PHP_METHOD(swoole_mysql_coro, __destruct)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql_coro.");
        RETURN_FALSE;
    }
    else if (client->state != SW_MYSQL_STATE_CLOSED && client->cli)
    {
        zval *retval;
        sw_zend_call_method_with_0_params(&getThis(), swoole_mysql_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
	if (client->buffer) {
		swString_free(client->buffer);
	}
    efree(client);
    swoole_set_object(getThis(), NULL);

    php_context *context = swoole_get_property(getThis(), 0);
    if (!context)
    {
		return;
    }
	efree(context);
    swoole_set_property(getThis(), 0, NULL);
}

static PHP_METHOD(swoole_mysql_coro, close)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql_coro.");
        RETURN_FALSE;
    }

    if (!client->cli)
    {
        RETURN_FALSE;
    }

    zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);
    }
	swConnection *socket = swReactor_get(SwooleG.main_reactor, client->fd);
	socket->object = NULL;
	socket->active = 0;

    if (client->cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(client->cli->timeout_id TSRMLS_CC);
		client->cli->timeout_id = 0;
    }

    client->cli->close(client->cli);
    swClient_free(client->cli);
	sw_free(client->cli->socket);
    efree(client->cli);
    client->cli = NULL;

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

    sw_zend_call_method_with_0_params(&zobject, swoole_mysql_coro_class_entry_ptr, NULL, "close", &retval);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

	SW_MAKE_STD_ZVAL(result);
	zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), "EPOLLERR/EPOLLHUP/EPOLLRDHUP happen!" TSRMLS_CC);
	zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), 104 TSRMLS_CC);
    ZVAL_BOOL(result, 0);
	if (swoole_multi_resume(zobject, result) == CORO_MULTI)
	{
		result = NULL;
		return SW_OK;
	}
	php_context *sw_current_context = swoole_get_property(zobject, 0);
	int ret = coro_resume(sw_current_context, result, &retval);
    sw_zval_ptr_dtor(&result);
#if PHP_MAJOR_VERSION > 5
    efree(result);
#endif
	if (ret == CORO_END && retval)
	{
		sw_zval_ptr_dtor(&retval);
	}

    return SW_OK;
}

static void swoole_mysql_coro_onConnect(mysql_client *client TSRMLS_DC)
{
    zval *zobject = client->object;

    zval *retval;
    zval *result;

    SW_MAKE_STD_ZVAL(result);

    SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    if (client->connector.error_code > 0)
    {
        zend_update_property_stringl(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_error"), client->connector.error_msg, client->connector.error_length TSRMLS_CC);
        zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), client->connector.error_code TSRMLS_CC);

        ZVAL_BOOL(result, 0);

		sw_zend_call_method_with_0_params(&zobject, swoole_mysql_coro_class_entry_ptr, NULL, "close", &retval);
		if (retval)
		{
			sw_zval_ptr_dtor(&retval);
		}
    }
    else
    {
        zend_update_property_bool(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 1 TSRMLS_CC);
        ZVAL_BOOL(result, 1);
    }

	php_context *sw_current_context = swoole_get_property(zobject, 0);
	int ret = coro_resume(sw_current_context, result, &retval);
    sw_zval_ptr_dtor(&result);
#if PHP_MAJOR_VERSION > 5
    efree(result);
#endif
	if (ret == CORO_END && retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
}


static void swoole_mysql_coro_onTimeout(php_context *ctx)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *result;
    zval *retval;

    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 0);
    zval *zobject = (zval *)ctx->coro_params;
	zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), "query timeout." TSRMLS_CC);
	zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), 110 TSRMLS_CC);

	//timeout close conncttion
    mysql_client *client = swoole_get_object(zobject);
	client->cli->timeout_id = 0;
	client->state = SW_MYSQL_STATE_QUERY;
    sw_zend_call_method_with_0_params(&zobject, swoole_mysql_coro_class_entry_ptr, NULL, "close", &retval);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

	if (swoole_multi_resume(zobject, result) == CORO_MULTI)
	{
		result = NULL;
		return;
	}

    int ret = coro_resume(ctx, result, &retval);

    if (ret == CORO_END && retval) {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&result);
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
	if (client->cli->timeout_id > 0)
	{
		php_swoole_clear_timer_coro(client->cli->timeout_id TSRMLS_CC);
		client->cli->timeout_id = 0;
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
            sw_zend_call_method_with_0_params(&zobject, swoole_mysql_coro_class_entry_ptr, NULL, "close", &retval);
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }

			SW_ALLOC_INIT_ZVAL(result);
			ZVAL_BOOL(result, 0);
			if (swoole_multi_resume(zobject, result) == CORO_MULTI)
			{
				result = NULL;
				return SW_OK;
			}
			php_context *sw_current_context = swoole_get_property(zobject, 0);
			ret = coro_resume(sw_current_context, result, &retval);
			sw_zval_ptr_dtor(&result);
#if PHP_MAJOR_VERSION > 5
            efree(result);
#endif
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
            reactor->del(reactor, event->fd);

            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("affected_rows"), client->response.affected_rows TSRMLS_CC);
            zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("insert_id"), client->response.insert_id TSRMLS_CC);
            client->state = SW_MYSQL_STATE_QUERY;

            //OK
            if (client->response.response_type == 0)
            {
                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 1);
            }
            //ERROR
            else if (client->response.response_type == 255)
            {
                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 0);

                zend_update_property_string(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("error"), client->response.server_msg TSRMLS_CC);
                zend_update_property_long(swoole_mysql_coro_class_entry_ptr, zobject, ZEND_STRL("errno"), client->response.error_code TSRMLS_CC);
            }
            //ResultSet
            else
            {
                result = client->response.result_array;
            }

			swString_clear(client->buffer);
			if (client->response.columns)
			{
				efree(client->response.columns);
			}
			bzero(&client->response, sizeof(client->response));
			if (swoole_multi_resume(zobject, result) == CORO_MULTI)
			{
				result = NULL;
				return SW_OK;
			}
			php_context *sw_current_context = swoole_get_property(zobject, 0);
			ret = coro_resume(sw_current_context, result, &retval);
			sw_zval_ptr_dtor(&result);

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
