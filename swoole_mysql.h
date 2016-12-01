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

#ifndef SWOOLE_MYSQL_H_
#define SWOOLE_MYSQL_H_

//#define SW_MYSQL_STRICT_TYPE
//#define SW_MYSQL_DEBUG

enum mysql_command
{
    SW_MYSQL_COM_SLEEP = 0,
    SW_MYSQL_COM_QUIT,
    SW_MYSQL_COM_INIT_DB,
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

enum mysql_handshake_state
{
    SW_MYSQL_HANDSHAKE_WAIT_REQUEST,
    SW_MYSQL_HANDSHAKE_WAIT_RESULT,
    SW_MYSQL_HANDSHAKE_COMPLETED,
};

enum mysql_read_state
{
    SW_MYSQL_STATE_QUERY,
    SW_MYSQL_STATE_READ_START,
    SW_MYSQL_STATE_READ_FIELD,
    SW_MYSQL_STATE_READ_ROW,
    SW_MYSQL_STATE_READ_END,
    SW_MYSQL_STATE_CLOSED,
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

#define SW_MYSQL_CLIENT_CONNECT_WITH_DB          8
#define SW_MYSQL_CLIENT_PROTOCOL_41              512
#define SW_MYSQL_CLIENT_PLUGIN_AUTH              (1UL << 19)
#define SW_MYSQL_CLIENT_CONNECT_ATTRS            (1UL << 20)
#define SW_MYSQL_CLIENT_SECURE_CONNECTION        32768

typedef struct
{
    int packet_length;
    int packet_number;
    uint8_t protocol_version;
    char *server_version;
    int connection_id;
    char auth_plugin_data[21];
    uint8_t l_auth_plugin_data;
    char filler;
    int capability_flags;
    char character_set;
    int16_t status_flags;
    char reserved[10];
    char *auth_plugin_name;
    uint8_t l_auth_plugin_name;
} mysql_handshake_request;

typedef struct
{
    char *host;
    char *user;
    char *password;
    char *database;

    zend_size_t host_len;
    zend_size_t user_len;
    zend_size_t password_len;
    zend_size_t database_len;

    long port;
    double timeout;

    int capability_flags;
    int max_packet_size;
    char character_set;
    int packet_length;
    char buf[512];

    uint16_t error_code;
    char *error_msg;
    uint16_t error_length;
} mysql_connector;

typedef struct
{
    char *buffer;
    char *name; /* Name of column */
    char *org_name; /* Original column name, if an alias */
    char *table; /* Table of column if column was a field */
    char *org_table; /* Org table name, if table was an alias */
    char *db; /* Database for table */
    char *catalog; /* Catalog for table */
    char *def; /* Default value (set by mysql_list_fields) */
    ulong_t length; /* Width of column (create length) */
    ulong_t max_length; /* Max width for selected set */
    uint32_t name_length;
    uint32_t org_name_length;
    uint32_t table_length;
    uint32_t org_table_length;
    uint32_t db_length;
    uint32_t catalog_length;
    uint32_t def_length;
    uint32_t flags; /* Div flags */
    uint32_t decimals; /* Number of decimals in field */
    uint32_t charsetnr; /* Character set */
    enum mysql_field_types type; /* Type of field. See mysql_com.h for types */
    void *extension;
} mysql_field;

typedef union
{
    signed char stiny;
    uchar utiny;
    uchar mbool;
    short ssmall;
    unsigned short small;
    int sint;
    uint32_t uint;
    long long sbigint;
    unsigned long long ubigint;
    float mfloat;
    double mdouble;
} mysql_row;

typedef struct
{
    mysql_field *columns;
    uint16_t num_column;
    uint16_t index_column;
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
    uint16_t l_server_msg;
    ulong_t affected_rows;
    ulong_t insert_id;
    zval *result_array;
} mysql_response_t;

typedef struct
{
    uint8_t state;
    uint8_t handshake;
    swString *buffer;
    swClient *cli;
    zval *object;
    zval *callback;
    zval *onClose;
    int fd;

    mysql_connector connector;

#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _onClose;
#endif
    mysql_response_t response;
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

static sw_inline void mysql_pack_length(int length, char *buf)
{
    buf[2] = length >> 16;
    buf[1] = length >> 8;
    buf[0] = length;
}

static sw_inline int mysql_lcb_ll(char *m, ulong_t *r, char *nul, int len)
{
    if (len < 1)
    {
        return -1;
    }
    switch ((uchar) m[0])
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
        *r = (uchar) m[0];
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

static sw_inline int mysql_decode_field(char *buf, int len, mysql_field *col)
{
    int i;
    ulong_t size;
    char nul;
    char *wh;
    int tmp_len;

    /**
     * string buffer
     */
    char *_buffer = emalloc(len);
    if (!_buffer)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    col->buffer = _buffer;

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
    col->catalog = _buffer;
    _buffer += (size + 1);
    memcpy(col->catalog, &buf[i], size);
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
    col->db = _buffer;
    _buffer += (size + 1);
    memcpy(col->db, &buf[i], size);
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
    col->table = _buffer;
    _buffer += (size + 1);
    memcpy(col->table, &buf[i], size);
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
    col->org_table = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_table, &buf[i], size);
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
    col->name = _buffer;
    _buffer += (size + 1);
    memcpy(col->name, &buf[i], size);
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
    col->org_name = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_name, &buf[i], size);
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
    col->charsetnr = mysql_uint2korr(&buf[i]);
    i += 2;

    /* length */
    col->length = mysql_uint4korr(&buf[i]);
    i += 4;

    /* type */
    col->type = (uchar) buf[i];
    i += 1;

    /* flags */
    col->flags = mysql_uint3korr(&buf[i]);
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
        col->def = _buffer;
        //_buffer += (size + 1);
        memcpy(col->def, &buf[i], size);
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
    ulong_t len;
    char nul;

#ifdef SW_MYSQL_STRICT_TYPE
    mysql_row row;
    char value_buffer[32];
    bzero(&row, sizeof(row));
    char *error;
    char mem;
#endif

    zval *result_array = client->response.result_array;
    zval *row_array = NULL;
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

        swTrace("n=%d, fname=%s, name_length=%d\n", i, client->response.columns[i].name, client->response.columns[i].name_length);

        if (nul == 1)
        {
            add_assoc_null(row_array, client->response.columns[i].name);
            continue;
        }

        int type = client->response.columns[i].type;
        switch (type)
        {
        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, client->response.columns[i].name);
            break;
        /* String */
        case SW_MYSQL_TYPE_TINY_BLOB:
        case SW_MYSQL_TYPE_MEDIUM_BLOB:
        case SW_MYSQL_TYPE_LONG_BLOB:
        case SW_MYSQL_TYPE_BLOB:
        case SW_MYSQL_TYPE_DECIMAL:
        case SW_MYSQL_TYPE_NEWDECIMAL:
        case SW_MYSQL_TYPE_BIT:
        case SW_MYSQL_TYPE_STRING:
        case SW_MYSQL_TYPE_VAR_STRING:
        case SW_MYSQL_TYPE_VARCHAR:
        case SW_MYSQL_TYPE_NEWDATE:
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
        case SW_MYSQL_TYPE_YEAR:
        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
        case SW_MYSQL_TYPE_DATE:
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            break;
        /* Integer */
        case SW_MYSQL_TYPE_TINY:
        case SW_MYSQL_TYPE_SHORT:
        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
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
        case SW_MYSQL_TYPE_LONGLONG:
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

        case SW_MYSQL_TYPE_FLOAT:
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

        case SW_MYSQL_TYPE_DOUBLE:
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

#if PHP_MAJOR_VERSION > 5
    if (row_array)
    {
        efree(row_array);
    }
#endif

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
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    for (; client->response.index_column < client->response.num_column; client->response.index_column++)
    {
        if (n_buf < 4)
        {
            return SW_ERR;
        }

        client->response.packet_length = mysql_uint3korr(buffer);

        //no enough data
        if (n_buf - 4 < client->response.packet_length)
        {
            return SW_ERR;
        }

        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        ret = mysql_decode_field(buffer, client->response.packet_length, &client->response.columns[client->response.index_column]);
        if (ret > 0)
        {
            buffer += client->response.packet_length;
            n_buf -= client->response.packet_length;
            client->buffer->offset += (client->response.packet_length + 4);
        }
        else
        {
            swWarn("mysql_decode_field failed, code=%d.", ret);
            break;
        }
    }

    if (mysql_read_eof(client, buffer, n_buf) < 0)
    {
        return SW_ERR;
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
        //RecordSet end
        else if (n_buf == 9 && mysql_read_eof(client, buffer, n_buf) == 0)
        {
            if (client->response.columns)
            {
                int i;
                for (i = 0; i < client->response.num_column; i++)
                {
                    if (client->response.columns[i].buffer)
                    {
                        efree(client->response.columns[i].buffer);
                        client->response.columns[i].buffer = NULL;
                    }
                }
                efree(client->response.columns);
            }
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

#endif /* SWOOLE_MYSQL_H_ */
