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

#ifdef SW_ASYNC_MYSQL
#include "swoole_mysql.h"

static PHP_METHOD(swoole_mysql, __construct);
static PHP_METHOD(swoole_mysql, __destruct);
static PHP_METHOD(swoole_mysql, query);
static PHP_METHOD(swoole_mysql, close);

static zend_class_entry swoole_mysql_ce;
static zend_class_entry *swoole_mysql_class_entry_ptr;

static zend_class_entry swoole_mysql_exception_ce;
static zend_class_entry *swoole_mysql_exception_class_entry;

static const zend_function_entry swoole_mysql_methods[] =
{
    PHP_ME(swoole_mysql, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_mysql, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_mysql, query, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, close, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int mysql_request(swString *sql, swString *buffer);

#ifdef SW_MYSQL_DEBUG
static void mysql_client_info(mysql_client *client);
static void mysql_column_info(mysql_field *field);
#endif

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event);
static swString *mysql_request_buffer = NULL;
static int isset_event_callback = 0;

void swoole_mysql_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_ce, "swoole_mysql", "Swoole\\MySQL", swoole_mysql_methods);
    swoole_mysql_class_entry_ptr = zend_register_internal_class(&swoole_mysql_ce TSRMLS_CC);

    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_exception_ce, "swoole_mysql_exception", "Swoole\\MySQL\Exception", NULL);
    swoole_mysql_exception_class_entry = zend_register_internal_class(&swoole_mysql_exception_ce TSRMLS_CC);
}

static PHP_METHOD(swoole_mysql, __construct)
{
    if (!mysql_request_buffer)
    {
        mysql_request_buffer = swString_new(65536);
        if (!mysql_request_buffer)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            RETURN_FALSE;
        }
    }

    zval *mysql_link;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &mysql_link) == FAILURE)
    {
        RETURN_FALSE;
    }

    int sock = -1;
    mysql_get_socket(mysql_link, return_value, &sock TSRMLS_CC);
    if (sock <= 0)
    {
        zend_throw_exception(swoole_mysql_exception_class_entry, "get mysqli socket failed.", 0 TSRMLS_CC);
        RETURN_FALSE;
    }

    mysql_client *client = emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));
    client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
    client->fd = sock;
    client->object = getThis();

    zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 1 TSRMLS_CC);
    zend_update_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("mysqli"), mysql_link TSRMLS_CC);

    client->mysqli = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("mysqli"), 0 TSRMLS_CC);
    sw_copy_to_stack(client->mysqli, client->_mysqli);

    swoole_set_object(getThis(), client);

    php_swoole_check_reactor();
    swSetNonBlock(sock);

    if (!isset_event_callback)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_onRead);
    }

    swConnection *socket = swReactor_get(SwooleG.main_reactor, sock);
    socket->active = 1;
    socket->object = client;
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

PHP_FUNCTION(swoole_get_mysqli_sock)
{
    zval *mysql_link;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &mysql_link) == FAILURE)
    {
        return;
    }

    int sock = -1;
    mysql_get_socket(mysql_link, return_value, &sock TSRMLS_CC);

    if (sock <= 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(sock);
    }
}

PHP_METHOD(swoole_mysql, query)
{
    zval *callback;
    swString sql;
    bzero(&sql, sizeof(sql));

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &sql.str, &sql.length, &callback) == FAILURE)
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
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    client->callback = callback;
    sw_copy_to_stack(client->callback, client->_callback);

    sw_zval_add_ref(&client->callback);
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
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("errno"), 2006 TSRMLS_CC);
            swoole_set_object(getThis(), NULL);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, __destruct)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    efree(client);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_mysql, close)
{
    mysql_client *client = swoole_get_object(getThis());
    zval *mysqli = client->mysqli;
    zval *retval = NULL;

    zend_class_entry *class_entry = zend_get_class_entry(mysqli TSRMLS_CC);
    zend_call_method_with_0_params(&mysqli, class_entry, NULL, "close", &retval);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    mysql_client *client = event->socket->object;
    int sock = event->fd;

    zval *zobject = client->object;
    swString *buffer = client->buffer;
    int ret;

    zval **args[2];

    zval *callback = NULL;
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

            reactor->del(reactor, event->fd);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);

            if (client->callback)
            {
                args[0] = &zobject;
                args[1] = &result;

                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 0);

                callback = client->callback;
                if (sw_call_user_function_ex(EG(function_table), NULL, client->callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
                {
                    swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback[2] handler error.");
                }
                if (retval)
                {
                    sw_zval_ptr_dtor(&retval);
                }
                if (result)
                {
                    sw_zval_ptr_dtor(&result);
                }
                sw_zval_ptr_dtor(&callback);
                client->callback = NULL;
                client->state = SW_MYSQL_STATE_QUERY;
            }

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

            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("affected_rows"), client->response.affected_rows TSRMLS_CC);
            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("insert_id"), client->response.insert_id TSRMLS_CC);
            client->state = SW_MYSQL_STATE_QUERY;

            args[0] = &zobject;

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

                zend_update_property_string(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("error"), client->response.server_msg TSRMLS_CC);
                zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), client->response.error_code TSRMLS_CC);
            }
            //ResultSet
            else
            {
                result = client->response.result_array;
            }

            args[1] = &result;
            callback = client->callback;
            if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback[2] handler error.");
                reactor->del(SwooleG.main_reactor, event->fd);
            }

            /* free memory */
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            if (result)
            {
                sw_zval_ptr_dtor(&result);
            }
            //free callback object
            sw_zval_ptr_dtor(&callback);
            //clear buffer
            swString_clear(client->buffer);
            if (client->response.columns)
            {
                efree(client->response.columns);
            }
            bzero(&client->response, sizeof(client->response));
            return SW_OK;
        }
    }
    return SW_OK;
}

#endif
