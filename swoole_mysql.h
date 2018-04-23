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
    SW_MYSQL_STATE_READ_PARAM,
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
    SW_MYSQL_TYPE_JSON = 245,
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

#ifdef SW_COROUTINE
typedef enum
{
	SW_MYSQL_CORO_STATUS_CLOSED,
	SW_MYSQL_CORO_STATUS_READY,
	SW_MYSQL_CORO_STATUS_WAIT,
	SW_MYSQL_CORO_STATUS_DONE
} mysql_io_status;
#endif

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
    zend_bool strict_type;

    zend_size_t host_len;
    zend_size_t user_len;
    zend_size_t password_len;
    zend_size_t database_len;

    long port;
    double timeout;
    swTimer_node *timer;

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
    uint32_t id;
    uint16_t field_count;
    uint16_t param_count;
    uint16_t warning_count;
    uint16_t unreaded_param_count;
    struct _mysql_client *client;
    zval *object;
} mysql_statement;

typedef struct
{
    mysql_field *columns;
    ulong_t num_column;
    ulong_t index_column;
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

typedef struct _mysql_client
{
#ifdef SW_COROUTINE
    zend_bool defer;
    zend_bool defer_yield;
    mysql_io_status iowait;
    zval *result;
    int cid;
#endif
    uint8_t state;
    uint8_t handshake;
    uint8_t cmd;
    swString *buffer;
    swClient *cli;
    zval *object;
    zval *callback;
    zval *onClose;
    int fd;
    uint32_t transaction :1;
    uint32_t connected :1;
    uint32_t strict;

    mysql_connector connector;
    mysql_statement *statement;
    swLinkedList *statement_list;

    swTimer_node *timer;

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

#define mysql_int1store(T,A)  do { *((int8_t*) (T)) = (int8_t)(A); } while(0)
#define mysql_int2store(T,A)  do { uint32_t def_temp= (uint32_t) (A) ;\
                  *((zend_uchar*) (T))  =  (zend_uchar)(def_temp); \
                  *((zend_uchar*) (T+1)) = (zend_uchar)((def_temp >> 8)); } while (0)
#define mysql_int3store(T,A)  do { /*lint -save -e734 */\
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16)); \
                  /*lint -restore */} while (0)
#define mysql_int4store(T,A)  do { \
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16));\
                  *(((char *)(T))+3) = (char) (((A) >> 24)); } while (0)
#define mysql_int5store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); } while (0)
/* Based on int5store() from Andrey Hristov */
#define mysql_int6store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); \
                  *(((char *)(T))+5) = (char)(((A) >> 40)); } while (0)

#define mysql_int8store(T,A)  do { uint32_t def_temp= (uint32_t) (A), def_temp2= (uint32_t) ((A) >> 32); \
                mysql_int4store((T),def_temp); \
                mysql_int4store((T+4),def_temp2); } while (0)

int mysql_get_result(mysql_connector *connector, char *buf, int len);
int mysql_get_charset(char *name);
int mysql_handshake(mysql_connector *connector, char *buf, int len);
int mysql_request(swString *sql, swString *buffer);
int mysql_prepare(swString *sql, swString *buffer);
int mysql_response(mysql_client *client);

#ifdef SW_MYSQL_DEBUG
void mysql_client_info(mysql_client *client);
void mysql_column_info(mysql_field *field);
#endif

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

static sw_inline int mysql_write_lcb(char *p, long val)
{
    if (val <= 250)
    {
        mysql_int1store(p, val);
        return 1;
    }
    else if (val <= 0xffff)
    {
        mysql_int2store(p, val);
        return 2;
    }
    else if (val <= 0xffffff)
    {
        mysql_int3store(p, val);
        return 3;
    }
    else
    {
        mysql_int1store(p, 254);
        mysql_int8store(p, val);
        return 9;
    }
}

static sw_inline int mysql_length_coded_binary(char *m, ulong_t *r, char *nul, int len)
{
    ulong_t val = 0;
    int retcode = mysql_lcb_ll(m, &val, nul, len);
    *r = val;
    return retcode;
}

int mysql_query(zval *zobject, mysql_client *client, swString *sql, zval *callback TSRMLS_DC);

#endif /* SWOOLE_MYSQL_H_ */
