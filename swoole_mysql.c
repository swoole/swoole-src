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

#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqli/mysqli_mysqlnd.h"
#include "ext/mysqli/php_mysqli_structs.h"

//#define SW_MYSQL_STRICT_TYPE
//#define SW_MYSQL_DEBUG

enum mysql_command
{
    SW_MYSQL_COM_SLEEP = 0,
    SW_MYSQL_COM_QUIT,
    SW_MYSQL_SW_MYSQL_COM_INIT_DB,
    SW_MYSQL_COM_QUERY = 3,
    SW_MYSQL_COM_FIELD_LIST,
    SW_MYSQL_COM_CREATE_DB,
    SW_MYSQL_COM_DROP_DB,
    SW_MYSQL_COM_REFRESH,
    SW_MYSQL_COM_SHUTDOWN,
    SW_MYSQL_COM_STATISTICS,
    SW_MYSQL_COM_PROCESS_INFO,
    SW_MYSQL_COM_CONNECT,
    SW_MYSQL_COM_PROCESS_KILL,
    SW_MYSQL_COM_DEBUG,
    SW_MYSQL_COM_PING,
    SW_MYSQL_COM_TIME,
    SW_MYSQL_COM_DELAYED_INSERT,
    SW_MYSQL_COM_CHANGE_USER,
    SW_MYSQL_COM_BINLOG_DUMP,
    SW_MYSQL_COM_TABLE_DUMP,
    SW_MYSQL_COM_CONNECT_OUT,
    SW_MYSQL_COM_REGISTER_SLAVE,
    SW_MYSQL_COM_STMT_PREPARE,
    SW_MYSQL_COM_STMT_EXECUTE,
    SW_MYSQL_COM_STMT_SEND_LONG_DATA,
    SW_MYSQL_COM_STMT_CLOSE,
    SW_MYSQL_COM_STMT_RESET,
    SW_MYSQL_COM_SET_OPTION,
    SW_MYSQL_COM_STMT_FETCH,
    SW_MYSQL_COM_DAEMON,
    SW_MYSQL_COM_END
};

enum mysql_read_state
{
    SW_MYSQL_STATE_QUERY,
    SW_MYSQL_STATE_READ_START,
    SW_MYSQL_STATE_READ_FIELD,
    SW_MYSQL_STATE_READ_ROW,
    SW_MYSQL_STATE_READ_END,
};

enum mysql_error_code
{
    SW_MYSQL_ERR_PROTOCOL_ERROR = 1,
    SW_MYSQL_ERR_BUFFER_OVERSIZE,
    SW_MYSQL_ERR_PACKET_CORRUPT,
    SW_MYSQL_ERR_WANT_READ,
    SW_MYSQL_ERR_WANT_WRITE,
    SW_MYSQL_ERR_UNKNOWN_ERROR,
    SW_MYSQL_ERR_MYSQL_ERROR,
    SW_MYSQL_ERR_SERVER_LOST,
    SW_MYSQL_ERR_BAD_PORT,
    SW_MYSQL_ERR_RESOLV_HOST,
    SW_MYSQL_ERR_SYSTEM,
    SW_MYSQL_ERR_CANT_CONNECT,
    SW_MYSQL_ERR_BUFFER_TOO_SMALL,
    SW_MYSQL_ERR_UNEXPECT_R_STATE,
    SW_MYSQL_ERR_STRFIELD_CORRUPT,
    SW_MYSQL_ERR_BINFIELD_CORRUPT,
    SW_MYSQL_ERR_BAD_LCB,
    SW_MYSQL_ERR_LEN_OVER_BUFFER,
    SW_MYSQL_ERR_CONVLONG,
    SW_MYSQL_ERR_CONVLONGLONG,
    SW_MYSQL_ERR_CONVFLOAT,
    SW_MYSQL_ERR_CONVDOUBLE,
    SW_MYSQL_ERR_CONVTIME,
    SW_MYSQL_ERR_CONVTIMESTAMP,
    SW_MYSQL_ERR_CONVDATE
};

enum mysql_field_types
{
    SW_MYSQL_TYPE_DECIMAL,
    SW_MYSQL_TYPE_TINY,
    SW_MYSQL_TYPE_SHORT,
    SW_MYSQL_TYPE_LONG,
    SW_MYSQL_TYPE_FLOAT,
    SW_MYSQL_TYPE_DOUBLE,
    SW_MYSQL_TYPE_NULL,
    SW_MYSQL_TYPE_TIMESTAMP,
    SW_MYSQL_TYPE_LONGLONG,
    SW_MYSQL_TYPE_INT24,
    SW_MYSQL_TYPE_DATE,
    SW_MYSQL_TYPE_TIME,
    SW_MYSQL_TYPE_DATETIME,
    SW_MYSQL_TYPE_YEAR,
    SW_MYSQL_TYPE_NEWDATE,
    SW_MYSQL_TYPE_VARCHAR,
    SW_MYSQL_TYPE_BIT,
    SW_MYSQL_TYPE_NEWDECIMAL = 246,
    SW_MYSQL_TYPE_ENUM = 247,
    SW_MYSQL_TYPE_SET = 248,
    SW_MYSQL_TYPE_TINY_BLOB = 249,
    SW_MYSQL_TYPE_MEDIUM_BLOB = 250,
    SW_MYSQL_TYPE_LONG_BLOB = 251,
    SW_MYSQL_TYPE_BLOB = 252,
    SW_MYSQL_TYPE_VAR_STRING = 253,
    SW_MYSQL_TYPE_STRING = 254,
    SW_MYSQL_TYPE_GEOMETRY = 255
};

typedef struct
{
    char *name; /* Name of column */
    char *org_name; /* Original column name, if an alias */
    char *table; /* Table of column if column was a field */
    char *org_table; /* Org table name, if table was an alias */
    char *db; /* Database for table */
    char *catalog; /* Catalog for table */
    char *def; /* Default value (set by mysql_list_fields) */
    unsigned long length; /* Width of column (create length) */
    unsigned long max_length; /* Max width for selected set */
    unsigned int name_length;
    unsigned int org_name_length;
    unsigned int table_length;
    unsigned int org_table_length;
    unsigned int db_length;
    unsigned int catalog_length;
    unsigned int def_length;
    unsigned int flags; /* Div flags */
    unsigned int decimals; /* Number of decimals in field */
    unsigned int charsetnr; /* Character set */
    enum mysql_field_types type; /* Type of field. See mysql_com.h for types */
    void *extension;
} mysql_field;

typedef union
{
    signed char stiny;
    unsigned char utiny;
    unsigned char mbool;
    short ssmall;
    unsigned short small;
    int sint;
    unsigned int uint;
    long long sbigint;
    unsigned long long ubigint;
    float mfloat;
    double mdouble;
} mysql_row;

typedef struct
{
    uint8_t state;
    swString *buffer;
    zval *callback;
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
#endif
    struct
    {
        mysql_field *columns;
        uint16_t num_column;
        uint32_t num_row;
        uint8_t wait_recv;
        uint8_t response_type;
        uint32_t packet_length :24;
        uint32_t packet_number :8;
        uint32_t error_code;
        uint32_t warnings;
        uint16_t status_code;
        char status_msg[6];
        char *server_msg;
        ulong_t affected_rows;
        ulong_t insert_id;
        zval *result_array;
    } response;

} mysql_client;

#define mysql_uint2korr(A)  (uint16_t) (((uint16_t) ((zend_uchar) (A)[0])) +\
                               ((uint16_t) ((zend_uchar) (A)[1]) << 8))
#define mysql_uint3korr(A)  (uint32_t) (((uint32_t) ((zend_uchar) (A)[0])) +\
                               (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((zend_uchar) (A)[2])) << 16))
#define mysql_uint4korr(A)  (uint32_t) (((uint32_t) ((zend_uchar) (A)[0])) +\
                               (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((zend_uchar) (A)[2])) << 16) +\
                               (((uint32_t) ((zend_uchar) (A)[3])) << 24))

#define mysql_uint8korr(A)    ((uint64_t)(((uint32_t) ((zend_uchar) (A)[0])) +\
                                    (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                                    (((uint32_t) ((zend_uchar) (A)[2])) << 16) +\
                                    (((uint32_t) ((zend_uchar) (A)[3])) << 24)) +\
                                    (((uint64_t) (((uint32_t) ((zend_uchar) (A)[4])) +\
                                    (((uint32_t) ((zend_uchar) (A)[5])) << 8) +\
                                    (((uint32_t) ((zend_uchar) (A)[6])) << 16) +\
                                    (((uint32_t) ((zend_uchar) (A)[7])) << 24))) << 32))


static int mysql_request(swString *sql, swString *buffer);
#ifdef SW_MYSQL_DEBUG
static void mysql_client_info(mysql_client *client);
static void mysql_column_info(mysql_field *field);
#endif
static int mysql_decode_field(char *buf, int len, mysql_field *col);
static int mysql_decode_row(mysql_client *client, char *buf, int packet_len);
static int swoole_mysql_onRead(swReactor *reactor, swEvent *event);

static sw_inline void mysql_pack_length(int length, char *buf)
{
    buf[2] = length >> 16;
    buf[1] = length >> 8;
    buf[0] = length;
}

static sw_inline int mysql_lcb_ll(char *m, ulong_t *r, char *nul, int len)
{
    if (len < 1)
        return -1;
    switch ((unsigned char) m[0])
    {

    case 251: /* fb : 1 octet */
        *r = 0;
        *nul = 1;
        return 1;

    case 252: /* fc : 2 octets */
        if (len < 3)
        {
            return -1;
        }
        *r = mysql_uint2korr(m + 1);
        *nul = 0;
        return 3;

    case 253: /* fd : 3 octets */
        if (len < 5)
        {
            return -1;
        }
        *r = mysql_uint3korr(m + 1);
        *nul = 0;
        return 4;

    case 254: /* fe */
        if (len < 9)
        {
            return -1;
        }
        *r = mysql_uint8korr(m + 1);
        *nul = 0;
        return 9;

    default:
        *r = (unsigned char) m[0];
        *nul = 0;
        return 1;
    }
}

static sw_inline int mysql_length_coded_binary(char *m, ulong_t *r, char *nul, int len)
{
    ulong_t val = 0;
    int retcode = mysql_lcb_ll(m, &val, nul, len);
    *r = val;
    return retcode;
}

static sw_inline void mysql_get_socket(zval *mysql_link, zval *return_value, int *sock TSRMLS_DC)
{
    MY_MYSQL *mysql;
    php_stream *stream;
    *sock = -1;

    if (Z_TYPE_P(mysql_link) != IS_OBJECT || strcasecmp(Z_OBJCE_P(mysql_link)->name, "mysqli") != 0)
    {
        return;
    }

#if PHP_MAJOR_VERSION > 5
    MYSQLI_FETCH_RESOURCE_CONN(mysql, mysql_link, MYSQLI_STATUS_VALID);
    stream = mysql->mysql->data->net->data->m.get_stream(mysql->mysql->data->net TSRMLS_CC);
#elif PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 4
    MYSQLI_FETCH_RESOURCE_CONN(mysql, &mysql_link, MYSQLI_STATUS_VALID);
    stream = mysql->mysql->data->net->data->m.get_stream(mysql->mysql->data->net TSRMLS_CC);
#else
    MYSQLI_FETCH_RESOURCE_CONN(mysql, &mysql_link, MYSQLI_STATUS_VALID);
    stream = mysql->mysql->data->net->stream;
#endif
    if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )sock, 1) != SUCCESS || *sock <= 2)
    {
        return;
    }
}

static sw_inline int mysql_decode_field(char *buf, int len, mysql_field *col)
{
    int i;
    unsigned long size;
    char nul;
    char *wh;
    int tmp_len;

    wh = buf;

    i = 0;

    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->catalog_length = size;
    memmove(wh, &buf[i], size);
    col->catalog = wh;
    col->catalog[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    db */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->db_length = size;
    memmove(wh, &buf[i], size);
    col->db = wh;
    col->db[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->table_length = size;
    memmove(wh, &buf[i], size);
    col->table = wh;
    col->table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_table_length = size;
    memmove(wh, &buf[i], size);
    col->org_table = wh;
    col->org_table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->name_length = size;
    memmove(wh, &buf[i], size);
    col->name = wh;
    col->name[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_name_length = size;
    memmove(wh, &buf[i], size);
    col->org_name = wh;
    col->org_name[size] = '\0';
    wh += size + 1;
    i += size;

    /* check len */
    if (i + 13 > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }

    /* (filler) */
    i += 1;

    /* charset */
    col->charsetnr = uint2korr(&buf[i]);
    i += 2;

    /* length */
    col->length = uint4korr(&buf[i]);
    i += 4;

    /* type */
    col->type = (unsigned char) buf[i];
    i += 1;

    /* flags */
    col->flags = uint3korr(&buf[i]);
    i += 2;

    /* decimals */
    col->decimals = buf[i];
    i += 1;

    /* filler */
    i += 2;

    /* default - a priori facultatif */
    if (len - i > 0)
    {
        tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
        if (tmp_len == -1)
        {
            return -SW_MYSQL_ERR_BAD_LCB;
        }
        i += tmp_len;
        if (i + size > len)
        {
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }
        col->def_length = size;
        memmove(wh, &buf[i], size);
        col->def = wh;
        col->def[size] = '\0';
        wh += size + 1;
        i += size;
    }
    else
    {
        col->def = NULL;
        col->def_length = 0;
    }

    /* set write pointer */
    return wh - buf;
}

static sw_inline int mysql_decode_row(mysql_client *client, char *buf, int packet_len)
{
    int read_n = 0, i;
    int tmp_len;
    unsigned long len;
    char nul;

#ifdef SW_MYSQL_STRICT_TYPE
    mysql_row row;
    char value_buffer[32];
    bzero(&row, sizeof(row));
    char *error;
    char mem;
#endif

    zval *result_array = client->response.result_array;
    zval *row_array;
    SW_ALLOC_INIT_ZVAL(row_array);
    array_init(row_array);

    for (i = 0; i < client->response.num_column; i++)
    {
        tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_len - read_n);
        if (tmp_len == -1)
        {
            return -SW_MYSQL_ERR_BAD_LCB;
        }

        read_n += tmp_len;
        if (read_n + len > packet_len)
        {
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }

        if (nul == 1)
        {
            continue;
        }

        int type = client->response.columns[i].type;
        switch (type)
        {
        case MYSQL_TYPE_NULL:
            add_assoc_null(row_array, client->response.columns[i].name);
            break;
        /* String */
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_NEWDECIMAL:
        case MYSQL_TYPE_BIT:
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_NEWDATE:
        /* Date Time */
        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_YEAR:
        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_DATE:
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            break;
        /* Integer */
        case MYSQL_TYPE_TINY:
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_INT24:
        case MYSQL_TYPE_LONG:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.sint = strtol(value_buffer, &error, 10);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVLONG;
            }
            add_assoc_long(row_array, client->response.columns[i].name, row.sint);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;
        case MYSQL_TYPE_LONGLONG:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.sbigint = strtoll(value_buffer, &error, 10);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVLONG;
            }
            add_assoc_long(row_array, client->response.columns[i].name, row.sbigint);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;

        case MYSQL_TYPE_FLOAT:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.mfloat = strtof(value_buffer, &error);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVFLOAT;
            }
            add_assoc_double(row_array, client->response.columns[i].name, row.mfloat);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;

        case MYSQL_TYPE_DOUBLE:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.mdouble = strtod(value_buffer, &error);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVDOUBLE;
            }
            add_assoc_double(row_array, client->response.columns[i].name, row.mdouble);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);
    return read_n;
}

static sw_inline int mysql_read_eof(mysql_client *client, char *buffer, int n_buf)
{
    //EOF, length (3byte) + id(1byte) + 0xFE + warning(2byte) + status(2byte)
    if (n_buf < 9)
    {
        client->response.wait_recv = 1;
        return SW_ERR;
    }

    client->response.packet_length = mysql_uint3korr(buffer);
    client->response.packet_number = buffer[3];

    //not EOF packet
    uint8_t eof = buffer[4];
    if (eof != 0xfe)
    {
        return SW_ERR;
    }

    client->response.warnings = mysql_uint2korr(buffer + 5);
    client->response.status_code = mysql_uint2korr(buffer + 7);

    return SW_OK;
}

static sw_inline int mysql_read_columns(mysql_client *client)
{
    int i;
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    for (i = client->response.packet_number - 1; i < client->response.num_column; i++)
    {
        client->response.packet_length = mysql_uint3korr(buffer);
        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        //no enough data
        if (n_buf < client->response.packet_length)
        {
            wait_recv: client->buffer->offset += buffer - (client->buffer->str + client->buffer->offset);
            client->response.wait_recv = 1;
            return SW_ERR;
        }

        ret = mysql_decode_field(buffer, client->response.packet_length, &client->response.columns[i]);
        if (ret > 0)
        {
            buffer += client->response.packet_length;
            n_buf -= client->response.packet_length;
        }
        else
        {
            break;
        }
    }

    if (mysql_read_eof(client, buffer, n_buf) < 0)
    {
        goto wait_recv;
    }

    buffer += 9;
    n_buf -= 9;

    zval *result_array = client->response.result_array;
    if (!result_array)
    {
        SW_ALLOC_INIT_ZVAL(result_array);
        array_init(result_array);
        client->response.result_array = result_array;
    }
    client->buffer->offset += buffer - (client->buffer->str + client->buffer->offset);

    return SW_OK;
}

static sw_inline int mysql_read_rows(mysql_client *client)
{
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    //RecordSet parse
    while (n_buf > 0)
    {
        if (n_buf < 4)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }
        else if (n_buf == 9 && mysql_read_eof(client, buffer, n_buf) == 0)
        {
            return SW_OK;
        }

        client->response.packet_length = mysql_uint3korr(buffer);
        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        //no enough data
        if (n_buf < client->response.packet_length)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }

        //decode
        ret = mysql_decode_row(client, buffer, client->response.packet_length);
        if (ret < 0)
        {
            break;
        }

        //next row
        client->response.num_row++;
        buffer += client->response.packet_length;
        n_buf -= client->response.packet_length;
        client->buffer->offset += client->response.packet_length + 4;
    }

    return SW_ERR;
}

static swString *mysql_request_buffer = NULL;
static int isset_event_callback = 0;

void swoole_mysql_init(int module_number TSRMLS_DC)
{
    mysql_request_buffer = swString_new(65536);
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

PHP_FUNCTION(swoole_mysql_query)
{
    zval *mysql_link;
    zval *callback;
    swString sql;
    bzero(&sql, sizeof(sql));

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zsz", &mysql_link, &sql.str, &sql.length, &callback) == FAILURE)
    {
        return;
    }

    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    int sock = -1;
    mysql_get_socket(mysql_link, return_value, &sock TSRMLS_CC);
    if (sock <= 0)
    {
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(mysql_link);
    if (!client)
    {
        client = emalloc(sizeof(mysql_client));
        bzero(client, sizeof(mysql_client));
        client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
        swoole_set_object(mysql_link, client);

        php_swoole_check_reactor();
        swSetNonBlock(sock);

        zend_class_entry *class_entry = zend_get_class_entry(mysql_link TSRMLS_CC);
        zend_update_property_bool(class_entry, mysql_link, ZEND_STRL("_connected"), 1 TSRMLS_CC);

        if (!isset_event_callback)
        {
            SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_onRead);
        }
        swConnection *socket = swReactor_get(SwooleG.main_reactor, sock);
        socket->active = 1;
#if PHP_MAJOR_VERSION >= 7
        zval *new_zval = emalloc(sizeof(zval));
        ZVAL_COPY(new_zval, mysql_link);
        socket->object = new_zval;
#else
        socket->object = mysql_link;
#endif
    }
    else if (client->state != SW_MYSQL_STATE_QUERY)
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
    if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed.");
        RETURN_FALSE;
    }
    //send query
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, sock, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_class_entry *class_entry = zend_get_class_entry(mysql_link TSRMLS_CC);
            zend_update_property_bool(class_entry, mysql_link, ZEND_STRL("_connected"), 0 TSRMLS_CC);
            zend_update_property_bool(class_entry, mysql_link, ZEND_STRL("_errno"), 2006 TSRMLS_CC);
            swoole_set_object(mysql_link, NULL);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        RETURN_TRUE;
    }
}

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *mysql_link = event->socket->object;
    int sock = event->fd;

    mysql_client *client = swoole_get_object(mysql_link);
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

            swoole_set_object(mysql_link, NULL);
            reactor->del(reactor, event->fd);
            zend_class_entry *class_entry = zend_get_class_entry(mysql_link TSRMLS_CC);
            zend_update_property_bool(class_entry, mysql_link, ZEND_STRL("_connected"), 0 TSRMLS_CC);

            if (client->callback)
            {
                args[0] = &mysql_link;
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

            zend_class_entry *class_entry = zend_get_class_entry(mysql_link TSRMLS_CC);
            zend_update_property_long(class_entry, mysql_link, ZEND_STRL("_affected_rows"), client->response.affected_rows TSRMLS_CC);
            zend_update_property_long(class_entry, mysql_link, ZEND_STRL("_insert_id"), client->response.insert_id TSRMLS_CC);
            client->state = SW_MYSQL_STATE_QUERY;

            args[0] = &mysql_link;

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

                zend_update_property_string(class_entry, mysql_link, ZEND_STRL("_error"), client->response.server_msg TSRMLS_CC);
                zend_update_property_long(class_entry, mysql_link, ZEND_STRL("_errno"), client->response.error_code TSRMLS_CC);
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
