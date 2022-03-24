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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Twosee  <twose@qq.com>                                       |
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "php_swoole_cxx.h"
#include "swoole_util.h"

#ifdef SW_USE_OPENSSL
#ifndef OPENSSL_NO_RSA
#define SW_MYSQL_RSA_SUPPORT
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#endif

enum sw_mysql_command
{
    SW_MYSQL_COM_NULL = -1,
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

enum sw_mysql_handshake_state
{
    SW_MYSQL_HANDSHAKE_WAIT_REQUEST,
    SW_MYSQL_HANDSHAKE_WAIT_SWITCH,
    SW_MYSQL_HANDSHAKE_WAIT_SIGNATURE,
    SW_MYSQL_HANDSHAKE_WAIT_RSA,
    SW_MYSQL_HANDSHAKE_WAIT_RESULT,
    SW_MYSQL_HANDSHAKE_COMPLETED,
};

#define SW_MYSQL_AUTH_SIGNATRUE_PACKET_LENGTH 2

enum sw_mysql_auth_signature
{
    SW_MYSQL_AUTH_SIGNATURE_ERROR              = 0x00, // get signature failed
    SW_MYSQL_AUTH_SIGNATURE                    = 0x01,
    SW_MYSQL_AUTH_SIGNATURE_RSA_PREPARED       = 0x02,
    SW_MYSQL_AUTH_SIGNATURE_SUCCESS            = 0x03,
    SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED = 0x04, // rsa required
};

enum sw_mysql_command_flag
{
    SW_MYSQL_COMMAND_FLAG_QUERY   = 1 << 4,
    SW_MYSQL_COMMAND_FLAG_EXECUTE = 1 << 5,
};

enum sw_mysql_state
{
    SW_MYSQL_STATE_CLOSED               = 0,
    SW_MYSQL_STATE_IDLE                 = 1,
    SW_MYSQL_STATE_QUERY                = 2 | SW_MYSQL_COMMAND_FLAG_QUERY,
    SW_MYSQL_STATE_QUERY_FETCH          = 3 | SW_MYSQL_COMMAND_FLAG_QUERY,
    SW_MYSQL_STATE_QUERY_MORE_RESULTS   = 4 | SW_MYSQL_COMMAND_FLAG_QUERY,
    SW_MYSQL_STATE_PREPARE              = 5 | SW_MYSQL_COMMAND_FLAG_QUERY,
    SW_MYSQL_STATE_EXECUTE              = 6 | SW_MYSQL_COMMAND_FLAG_EXECUTE,
    SW_MYSQL_STATE_EXECUTE_FETCH        = 7 | SW_MYSQL_COMMAND_FLAG_EXECUTE,
    SW_MYSQL_STATE_EXECUTE_MORE_RESULTS = 8 | SW_MYSQL_COMMAND_FLAG_EXECUTE,
};

enum sw_mysql_packet_types
{
    SW_MYSQL_PACKET_OK   = 0x0,
    SW_MYSQL_PACKET_AUTH_SIGNATURE_REQUEST = 0x01,

    /* not defined in protocol */
    SW_MYSQL_PACKET_RAW_DATA,
    SW_MYSQL_PACKET_GREETING,
    SW_MYSQL_PACKET_LOGIN,
    SW_MYSQL_PACKET_AUTH_SWITCH_RESPONSE,
    SW_MYSQL_PACKET_AUTH_SIGNATURE_RESPONSE,
    SW_MYSQL_PACKET_LCB, // length coded binary
    SW_MYSQL_PACKET_FIELD,
    SW_MYSQL_PACKET_ROW_DATA,
    SW_MYSQL_PACKET_PREPARE_STATEMENT,
    /* ======================= */

    SW_MYSQL_PACKET_NULL = 0xfb,
    SW_MYSQL_PACKET_EOF  = 0xfe,
    SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST = 0xfe,
    SW_MYSQL_PACKET_ERR  = 0xff
};

enum sw_mysql_field_types
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
    SW_MYSQL_TYPE_NEWDECIMAL,
    SW_MYSQL_TYPE_ENUM,
    SW_MYSQL_TYPE_SET,
    SW_MYSQL_TYPE_TINY_BLOB,
    SW_MYSQL_TYPE_MEDIUM_BLOB,
    SW_MYSQL_TYPE_LONG_BLOB,
    SW_MYSQL_TYPE_BLOB,
    SW_MYSQL_TYPE_VAR_STRING,
    SW_MYSQL_TYPE_STRING,
    SW_MYSQL_TYPE_GEOMETRY
};

// ref: https://dev.mysql.com/doc/dev/mysql-server/8.0.0/group__group__cs__capabilities__flags.html
// use regex: "\#define[ ]+(CLIENT_[A-Z_\d]+)[ ]+(\(?[\dA-Z <]+\)?)\n[ ]+?[ ]+([\s\S ]+?\.) More\.\.\.\n?"
// to "SW_MYSQL_$1 = $2, /* $3 */"
enum sw_mysql_client_capability_flags
{
    SW_MYSQL_CLIENT_LONG_PASSWORD = 1, /* Use the improved version of Old Password Authentication. */
    SW_MYSQL_CLIENT_FOUND_ROWS = 2, /* Send found rows instead of affected rows in EOF_Packet. */
    SW_MYSQL_CLIENT_LONG_FLAG = 4, /* Get all column flags. */
    SW_MYSQL_CLIENT_CONNECT_WITH_DB = 8, /* Database (schema) name can be specified on connect in Handshake Response Packet. */
    SW_MYSQL_CLIENT_NO_SCHEMA = 16, /* Don't allow database.table.column. */
    SW_MYSQL_CLIENT_COMPRESS = 32, /* Compression protocol supported. */
    SW_MYSQL_CLIENT_ODBC = 64, /* Special handling of ODBC behavior. */
    SW_MYSQL_CLIENT_LOCAL_FILES = 128, /* Can use LOAD DATA LOCAL. */
    SW_MYSQL_CLIENT_IGNORE_SPACE = 256, /* Ignore spaces before '('. */
    SW_MYSQL_CLIENT_PROTOCOL_41 = 512, /* New 4.1 protocol. */
    SW_MYSQL_CLIENT_INTERACTIVE = 1024, /* This is an interactive client. */
    SW_MYSQL_CLIENT_SSL = 2048, /* Use SSL encryption for the session. */
    SW_MYSQL_CLIENT_IGNORE_SIGPIPE = 4096, /* Client only flag. */
    SW_MYSQL_CLIENT_TRANSACTIONS = 8192, /* Client knows about transactions. */
    SW_MYSQL_CLIENT_RESERVED = 16384, /* flag for 4.1 protocol. */
    SW_MYSQL_CLIENT_SECURE_CONNECTION = 32768, /* swoole custom name for RESERVED2.  */
    SW_MYSQL_CLIENT_RESERVED2 = 32768, /* flag for 4.1 authentication. */
    SW_MYSQL_CLIENT_MULTI_STATEMENTS = (1UL << 16), /* Enable/disable multi-stmt support. */
    SW_MYSQL_CLIENT_MULTI_RESULTS = (1UL << 17), /* Enable/disable multi-results. */
    SW_MYSQL_CLIENT_PS_MULTI_RESULTS = (1UL << 18), /* Multi-results and OUT parameters in PS-protocol. */
    SW_MYSQL_CLIENT_PLUGIN_AUTH = (1UL << 19), /* Client supports plugin authentication. */
    SW_MYSQL_CLIENT_CONNECT_ATTRS = (1UL << 20), /* Client supports connection attributes. */
    SW_MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = (1UL << 21), /* Enable authentication response packet to be larger than 255 bytes. */
    SW_MYSQL_CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = (1UL << 22), /* Don't close the connection for a user account with expired password. */
    SW_MYSQL_CLIENT_SESSION_TRACK = (1UL << 23), /* Capable of handling server state change information. */
    SW_MYSQL_CLIENT_DEPRECATE_EOF = (1UL << 24), /* Client no longer needs EOF_Packet and will use OK_Packet instead. */
    SW_MYSQL_CLIENT_SSL_VERIFY_SERVER_CERT = (1UL << 30), /* Verify server certificate. */
    SW_MYSQL_CLIENT_REMEMBER_OPTIONS = (1UL << 31) /* Don't reset the options after an unsuccessful connect. */
};

// ref: https://dev.mysql.com/doc/internals/en/status-flags.html
enum sw_mysql_server_status_flags
{
    SW_MYSQL_SERVER_STATUS_IN_TRANS = 0x0001, // a transaction is active
    SW_MYSQL_SERVER_STATUS_AUTOCOMMIT = 0x0002, //auto-commit is enabled
    SW_MYSQL_SERVER_MORE_RESULTS_EXISTS = 0x0008,
    SW_MYSQL_SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010,
    SW_MYSQL_SERVER_STATUS_NO_INDEX_USED = 0x0020,
    SW_MYSQL_SERVER_STATUS_CURSOR_EXISTS = 0x0040, // Used by Binary Protocol Resultset to signal that COM_STMT_FETCH must be used to fetch the row-data.
    SW_MYSQL_SERVER_STATUS_LAST_ROW_SENT = 0x0080,
    SW_MYSQL_SERVER_STATUS_DB_DROPPED = 0x0100,
    SW_MYSQL_SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200,
    SW_MYSQL_SERVER_STATUS_METADATA_CHANGED = 0x0400,
    SW_MYSQL_SERVER_QUERY_WAS_SLOW = 0x0800,
    SW_MYSQL_SERVER_PS_OUT_PARAMS = 0x1000,
    SW_MYSQL_SERVER_STATUS_IN_TRANS_READONLY = 0x2000, // in a read-only transaction
    SW_MYSQL_SERVER_SESSION_STATE_CHANGED = 0x4000 // connection state information has changed
};

#define SW_MYSQL_NO_RSA_ERROR "MySQL8 caching_sha2_password authentication plugin need enable OpenSSL support"

#define SW_MYSQL_NOT_NULL_FLAG               1
#define SW_MYSQL_PRI_KEY_FLAG                2
#define SW_MYSQL_UNIQUE_KEY_FLAG             4
#define SW_MYSQL_MULTIPLE_KEY_FLAG           8
#define SW_MYSQL_BLOB_FLAG                  16
#define SW_MYSQL_UNSIGNED_FLAG              32
#define SW_MYSQL_ZEROFILL_FLAG              64
#define SW_MYSQL_BINARY_FLAG               128
#define SW_MYSQL_ENUM_FLAG                 256
#define SW_MYSQL_AUTO_INCREMENT_FLAG       512
#define SW_MYSQL_TIMESTAMP_FLAG           1024
#define SW_MYSQL_SET_FLAG                 2048
#define SW_MYSQL_NO_DEFAULT_VALUE_FLAG    4096
#define SW_MYSQL_ON_UPDATE_NOW_FLAG       8192
#define SW_MYSQL_PART_KEY_FLAG           16384
#define SW_MYSQL_GROUP_FLAG              32768
#define SW_MYSQL_NUM_FLAG                32768

/* int<3>   payload_length + int<1> sequence_id */
#define SW_MYSQL_PACKET_HEADER_SIZE      4
#define SW_MYSQL_PACKET_TYPE_OFFSET      5
#define SW_MYSQL_PACKET_EOF_MAX_SIZE     9
#define SW_MYSQL_PACKET_PREPARED_OK_SIZE 12
#define SW_MYSQL_MAX_PACKET_BODY_SIZE    0x00ffffff
#define SW_MYSQL_MAX_PACKET_SIZE         (SW_MYSQL_PACKET_HEADER_SIZE + SW_MYSQL_MAX_PACKET_BODY_SIZE)

// nonce: a number or bit string used only once, in security engineering
// other names on doc: challenge/scramble/salt
#define SW_MYSQL_NONCE_LENGTH 20

// clang-format off
#define sw_mysql_uint2korr2korr(A)  (uint16_t) (((uint16_t) ((uchar) (A)[0])) +\
                               ((uint16_t) ((uchar) (A)[1]) << 8))
#define sw_mysql_uint2korr3korr(A)  (uint32_t) (((uint32_t) ((uchar) (A)[0])) +\
                               (((uint32_t) ((uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((uchar) (A)[2])) << 16))
#define sw_mysql_uint2korr4korr(A)  (uint32_t) (((uint32_t) ((uchar) (A)[0])) +\
                               (((uint32_t) ((uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((uchar) (A)[2])) << 16) +\
                               (((uint32_t) ((uchar) (A)[3])) << 24))
#define sw_mysql_uint2korr8korr(A)    ((uint64_t)(((uint32_t) ((uchar) (A)[0])) +\
                                    (((uint32_t) ((uchar) (A)[1])) << 8) +\
                                    (((uint32_t) ((uchar) (A)[2])) << 16) +\
                                    (((uint32_t) ((uchar) (A)[3])) << 24)) +\
                                    (((uint64_t) (((uint32_t) ((uchar) (A)[4])) +\
                                    (((uint32_t) ((uchar) (A)[5])) << 8) +\
                                    (((uint32_t) ((uchar) (A)[6])) << 16) +\
                                    (((uint32_t) ((uchar) (A)[7])) << 24))) << 32))

#define sw_mysql_int1store(T,A)  do { *((int8_t*) (T)) = (int8_t)(A); } while(0)
#define sw_mysql_int2store(T,A)  do { uint32_t def_temp= (uint32_t) (A) ;\
                  *((uchar*) (T))  =  (uchar)(def_temp); \
                  *((uchar*) (T+1)) = (uchar)((def_temp >> 8)); } while (0)
#define sw_mysql_int3store(T,A)  do { /*lint -save -e734 */\
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16)); \
                  /*lint -restore */} while (0)
#define sw_mysql_int4store(T,A)  do { \
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16));\
                  *(((char *)(T))+3) = (char) (((A) >> 24)); } while (0)
#define sw_mysql_int5store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); } while (0)
/* Based on int5store() from Andrey Hristov */
#define sw_mysql_int6store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); \
                  *(((char *)(T))+5) = (char)(((A) >> 40)); } while (0)

// clang-format on

#define sw_mysql_int8store(T,A)  do { \
                uint32_t def_temp= (uint32_t) (A), def_temp2= (uint32_t) ((A) >> 32); \
                sw_mysql_int4store((T),def_temp); \
                sw_mysql_int4store((T+4),def_temp2); } while (0)

#define sw_mysql_doublestore(T,A) do { \
                double def_temp = (double) A; \
                memcpy(T, &def_temp, sizeof(double)); \
                } while (0)

#if defined(SW_DEBUG) && defined(SW_LOG_TRACE_OPEN)
#define swMysqlPacketDump(length, number, data, title) \
    if (SW_LOG_TRACE >= sw_logger()->get_level() && (SW_TRACE_MYSQL_CLIENT & SwooleG.trace_flags)) \
    { \
        swoole_debug("+----------+------------+-------------------------------------------------------+"); \
        swoole_debug("| P#%-6u | L%-9u | %-10u %42s |", number, SW_MYSQL_PACKET_HEADER_SIZE + length, length, title); \
        swoole_hex_dump(data, length); \
    }
#else
#define swMysqlPacketDump(length, number, data, title)
#endif

namespace swoole { namespace mysql {
//-----------------------------------namespace begin--------------------------------------------
char get_charset(const char *name);
uint8_t get_static_type_size(uint8_t type);

inline uint8_t read_lcb_size(const char *p)
{
    switch ((uchar) p[0])
    {
    case 251:
        return 1;
    case 252:
        return 3;
    case 253:
        return 4;
    case 254:
        return 9;
    default:
        return 1;
    }
}

inline uint8_t read_lcb(const char *p, uint64_t *length, bool *nul)
{
    switch ((uchar) p[0])
    {
    case 251: /* fb : 1 octet */
        *length = 0;
        *nul = true;
        return 1;
    case 252: /* fc : 2 octets */
        *length = sw_mysql_uint2korr2korr(p + 1);
        *nul = false;
        return 3;
    case 253: /* fd : 3 octets */
        *length = sw_mysql_uint2korr3korr(p + 1);
        *nul = false;
        return 4;
    case 254: /* fe : 8 octets */
        *length = sw_mysql_uint2korr8korr(p + 1);
        *nul = false;
        return 9;
    default:
        *length = (uchar) p[0];
        *nul = false;
        return 1;
    }
}

inline uint8_t read_lcb(const char *p, uint32_t *length, bool *nul)
{
    uint64_t _r;
    uint8_t ret = read_lcb(p, &_r, nul);
    *length = _r;
    return ret;
}

inline uint8_t write_lcb(char *p, uint64_t length, bool nul = false)
{
    if (nul)
    {
        sw_mysql_int1store(p++, 251);
        return 1;
    }
    if (length <= 250)
    {
        sw_mysql_int1store(p, length);
        return 1;
    }
    else if (length <= 0xffff)
    {
        sw_mysql_int1store(p++, 252);
        sw_mysql_int2store(p, length);
        return 3;
    }
    else if (length <= 0xffffff)
    {
        sw_mysql_int1store(p++, 253);
        sw_mysql_int3store(p, length);
        return 4;
    }
    else
    {
        sw_mysql_int1store(p++, 254);
        sw_mysql_int8store(p, length);
        return 9;
    }
}

class packet
{
public:
    static inline uint32_t get_length(const char *data)
    {
        return sw_mysql_uint2korr3korr(data);
    }
    static inline uint32_t get_number(const char *data)
    {
        return (uint8_t) data[3];
    }
    static inline void set_length(char *buffer, uint32_t length)
    {
        buffer[0] = length;
        buffer[1] = length >> 8;
        buffer[2] = length >> 16;
    }
    static inline void set_number(char *buffer, uint8_t number)
    {
        buffer[3] = number;
    }
    static inline void set_header(char *buffer, uint32_t length, uint8_t number)
    {
        set_length(buffer, length);
        set_number(buffer, number);
    }
};

class server_packet : public packet
{
public:
    struct header {
        uint32_t length :24;
        uint32_t number :8;
        header() : length(0), number(0) { }
    } header;
    server_packet() { }
    server_packet(const char *data)
    {
        parse(data);
    }
    inline void parse(const char *data)
    {
        header.length = packet::get_length(data);
        header.number = packet::get_number(data);
    }
    static inline uint8_t parse_type(const char *data)
    {
        if (sw_unlikely(!data))
        {
            return SW_MYSQL_PACKET_NULL;
        }
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE];
    }
    static inline bool is_eof(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_EOF;
    }
    static inline bool is_ok(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_OK;
    }
    static inline bool is_err(const char *data)
    {
        return (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE] == SW_MYSQL_PACKET_ERR;
    }
};

class server_status
{
public:
    int16_t status = 0;
    void operator =(uint16_t status)
    {
        this->status = status;
    }
    inline bool more_results_exists()
    {
        bool b = !!(status & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS);
        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "More results exist = %u", b);
        return b;
    }
};

class client_packet : public packet
{
public:
    client_packet(size_t body_size = 1024 - SW_MYSQL_PACKET_HEADER_SIZE)
    {
        SW_ASSERT(body_size > 0);
        if (body_size <= 4)
        {
            data.header = stack_buffer;
        }
        else
        {
            data.header = new char[SW_MEM_ALIGNED_SIZE(SW_MYSQL_PACKET_HEADER_SIZE + body_size)]();
        }
        data.body = data.header + SW_MYSQL_PACKET_HEADER_SIZE;
    }
    inline const char* get_data()
    {
        return data.header;
    }
    inline uint32_t get_data_length()
    {
        return SW_MYSQL_PACKET_HEADER_SIZE + get_length();
    }
    inline uint32_t get_length()
    {
        return sw_mysql_uint2korr3korr(data.header);
    }
    inline uint8_t get_number()
    {
        return (uint8_t) data.header[3];
    }
    inline const char* get_body()
    {
        return data.body;
    }
    inline void set_header(uint32_t length, uint8_t number)
    {
        packet::set_header(data.header, length, number);
    }
    ~client_packet()
    {
        if (data.header != stack_buffer)
        {
            delete[] data.header;
        }
    }
protected:
    struct {
        char *header = nullptr;
        char *body = nullptr;
    } data;
    char stack_buffer[SW_MYSQL_PACKET_HEADER_SIZE + 4] = {};
};

class command_packet : public client_packet
{
public:
    command_packet(enum sw_mysql_command command, const char *sql = nullptr, size_t length = 0) : client_packet(1 + length)
    {
        set_command(command);
        set_header(1 + length, 0);
        if (length > 0)
        {
            memcpy(data.body + 1, sql, length);
        }
    };
    inline void set_command(enum sw_mysql_command command)
    {
        data.body[0] = (char) command;
    }
};

class err_packet : public server_packet
{
public:
    uint16_t code;
    std::string msg;
    char sql_state[5 + 1];
    err_packet(const char *data);
};

class ok_packet : public server_packet
{
public:
    uint64_t affected_rows = 0;
    uint64_t last_insert_id = 0;
    mysql::server_status server_status;
    unsigned int warning_count = 0;
    ok_packet() { }
    ok_packet(const char *data);
};

class eof_packet : public server_packet
{
public:
    uint16_t warning_count;
    mysql::server_status server_status;
    eof_packet(const char *data);
};

class raw_data_packet : public server_packet
{
public:
    const char *body;
    raw_data_packet(const char *data) : server_packet(data), body(data + SW_MYSQL_PACKET_HEADER_SIZE)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::RawData");
    }
};

class greeting_packet : public server_packet
{
public:
    uint8_t protocol_version = 0;
    std::string server_version = "";
    int connection_id = 0;
    char auth_plugin_data[SW_MYSQL_NONCE_LENGTH + 1] = {}; // nonce + '\0'
    uint8_t auth_plugin_data_length = 0;
    char filler = 0;
    int capability_flags = 0;
    char charset = SW_MYSQL_DEFAULT_CHARSET;
    mysql::server_status status_flags;
    char reserved[10] = {};
    std::string auth_plugin_name = "";
    greeting_packet(const char *data);
};

class login_packet : public client_packet
{
public:
    login_packet(
        greeting_packet *greeting_packet,
        const std::string &user,
        const std::string &password,
        std::string database,
        char charset
    );
};

class auth_switch_request_packet : public server_packet
{
public:
    std::string auth_method_name = "mysql_native_password";
    char auth_method_data[SW_MYSQL_NONCE_LENGTH + 1] = {};
    auth_switch_request_packet(const char *data);
};

class auth_switch_response_packet : public client_packet
{
public:
    auth_switch_response_packet(auth_switch_request_packet *req, const std::string &password);
};

class auth_signature_request_packet : public server_packet
{
public:
    char data[2] = {};
    auth_signature_request_packet(const char *data) :server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::AuthSignatureRequest");
        memcpy(&this->data, data + SW_MYSQL_PACKET_HEADER_SIZE, 2);
    }
    inline bool is_full_auth_required()
    {
        return data[1] == SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED;
    }
    inline bool is_vaild()
    {
        return data[0] == SW_MYSQL_AUTH_SIGNATURE && (data[1] == SW_MYSQL_AUTH_SIGNATURE_SUCCESS || data[1] == SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED);
    }
};

class auth_signature_prepared_packet : public client_packet
{
public:
    auth_signature_prepared_packet(uint8_t number) : client_packet(1)
    {
        set_header(1, number);
        data.body[0] = SW_MYSQL_AUTH_SIGNATURE_RSA_PREPARED;
    }
};

class auth_signature_response_packet : public client_packet
{
public:
    auth_signature_response_packet(raw_data_packet *raw_data_pakcet, const std::string &password, const char *auth_plugin_data);
};

class lcb_packet : public server_packet
{
public:
    uint32_t length = 0;
    bool nul = 0;
    lcb_packet(const char *data) : server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "Protocol::LengthCodedBinary");
        bytes_length = read_lcb(data + SW_MYSQL_PACKET_HEADER_SIZE, &length, &nul);
        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "binary_length=%u, nul=%u", header.length, nul);
    }
    bool is_vaild()
    {
        return header.length == bytes_length;
    }
private:
    uint8_t bytes_length;
};

class field_packet : public server_packet
{
public:
    char *catalog = nullptr; /* Catalog for table */
    uint32_t catalog_length = 0;
    char *database = nullptr; /* Database for table */
    uint32_t database_length = 0;
    char *table = nullptr; /* Table of column if column was a field */
    uint32_t table_length = 0;
    char *org_table = nullptr; /* Org table name, if table was an alias */
    uint32_t org_table_length = 0;
    char *name = nullptr; /* Name of column */
    uint32_t name_length = 0;
    char *org_name = nullptr; /* Original column name, if an alias */
    uint32_t org_name_length = 0;
    char charset = 0;
    uint64_t length = 0; /* Width of column (create length) */
    uint8_t type = 0; /* Type of field. See mysql_com.h for types */
    uint32_t flags = 0; /* Div flags */
    uint32_t decimals = 0; /* Number of decimals in field */
    char *def = nullptr; /* Default value (set by mysql_list_fields) */
    uint32_t def_length = 0;
    void *extension = nullptr;
    field_packet() { }
    field_packet(const char *data) {
        parse(data);
    }
    void parse(const char *data);
    ~field_packet()
    {
        if (body)
        {
            delete[] body;
        }
    }
protected:
    char *body = nullptr;
};

typedef field_packet param_packet;

class row_data
{
public:
    char stack_buffer[32];
    struct {
        uint64_t length; // binary code length
        bool nul; // is nul?
    } text;
    row_data(const char *data)
    {
        next_packet(data);
    }
    inline void next_packet(const char *data)
    {
        read_ptr = packet_body = data + SW_MYSQL_PACKET_HEADER_SIZE;
        packet_eof = packet_body + packet::get_length(data);
    }
    inline bool eof()
    {
        return read_ptr == packet_eof;
    }
    inline const char* read(size_t length)
    {
        if (sw_likely(read_ptr + length <= packet_eof))
        {
            const char *p = read_ptr;
            read_ptr += length;
            return p;
        }
        return nullptr;
    }
    inline uint32_t recv(char *buf, size_t size)
    {
        uint32_t readable_length = packet_eof - read_ptr;
        uint32_t read_bytes = SW_MIN(readable_length, size);
        if (sw_likely(read_bytes > 0))
        {
            memcpy(buf, read_ptr, read_bytes);
            read_ptr += read_bytes;
        }
        return read_bytes;
    }
protected:
    const char *packet_body;
    const char *packet_eof;
    const char *read_ptr;
};

class row_data_text
{
public:
    uint64_t length = 0;
    bool nul = false;
    const char *body = nullptr;
    row_data_text(const char **pp)
    {
        body = *pp + read_lcb(*pp, &length, &nul);
        *pp = body + length;
        swoole_trace_log(
            SW_TRACE_MYSQL_CLIENT,
            "text[%" PRIu64 "]: %.*s%s",
            length, (int) SW_MIN(64, length), body,
            nul ? "null" : ((length > 64 /*|| length > readable_length*/) ? "..." : "")
        );
    }
};

inline std::string datetime(const char *p, uint8_t length, uint32_t decimals)
{
    uint16_t y = 0;
    uint8_t m = 0, d = 0, h = 0, i = 0, s = 0;
    uint32_t sp = 0;
    if (length != 0)
    {
        y = sw_mysql_uint2korr2korr(p);
        m = *(uint8_t *) (p + 2);
        d = *(uint8_t *) (p + 3);
        if (length > 4)
        {
            h = *(uint8_t *) (p + 4);
            i = *(uint8_t *) (p + 5);
            s = *(uint8_t *) (p + 6);
        }
        if (length > 7)
        {
            sp = sw_mysql_uint2korr4korr(p + 7);
        }
    }
    if (decimals > 0 && decimals < 7) {
        return swoole::std_string::format(
            "%04u-%02u-%02u %02u:%02u:%02u.%0*u",
            y, m, d, h, i, s, decimals, (uint32_t) (sp / ::pow(10, (double) (6 - decimals)))
        );
    } else {
        return swoole::std_string::format(
            "%04u-%02u-%02u %02u:%02u:%02u",
            y, m, d, h, i, s
        );
    }
}

inline std::string time(const char *p, uint8_t length, uint32_t decimals)
{
    bool neg = false;
    uint32_t d = 0, sp = 0;
    uint8_t h = 0, m = 0, s = 0;
    if (length != 0)
    {
        neg = (bool) *((uint8_t *) p);
        d = sw_mysql_uint2korr4korr(p + 1);
        h = *(uint8_t *) (p + 5);
        m = *(uint8_t *) (p + 6);
        s = *(uint8_t *) (p + 7);
        if (length > 8)
        {
            sp = sw_mysql_uint2korr4korr(p + 8);
        }
        if (d != 0) {
            /* Convert days to hours at once */
            h += d * 24;
        }
    }
    if (decimals > 0 && decimals < 7) {
        return swoole::std_string::format(
            "%s%02u:%02u:%02u.%0*u",
            (neg ? "-" : ""), h, m, s, decimals, (uint32_t) (sp / ::pow(10, (double) (6 - decimals)))
        );
    } else {
        return swoole::std_string::format(
            "%s%02u:%02u:%02u",
            (neg ? "-" : ""), h, m, s
        );
    }
}

inline std::string date(const char *p, uint8_t length)
{
    uint16_t y = 0;
    uint8_t m = 0, d = 0;
    if (length != 0)
    {
        y = sw_mysql_uint2korr2korr(p);
        m = *(uint8_t *) (p + 2);
        d = *(uint8_t *) (p + 3);
    }
    return swoole::std_string::format("%04u-%02u-%02u", y, m, d);
}

class result_info
{
public:
    ok_packet ok;

    inline void alloc_fields(uint32_t length)
    {
        clear_fields();
        if (sw_likely(length != 0))
        {
            fields.info = new field_packet[length];
            fields.length = length;
        }
        else
        {
            fields.length = 0;
            fields.info = nullptr;
        }
    }
    inline uint32_t get_fields_length()
    {
        return fields.length;
    }
    inline field_packet* get_fields(uint32_t index)
    {
        return fields.info;
    }
    inline field_packet* get_field(uint32_t index)
    {
        return &fields.info[index];
    }
    inline void set_field(uint32_t index, const char *data)
    {
        fields.info[index].parse(data);
    }
    inline void clear_fields()
    {
        if (fields.length > 0)
        {
            delete[] fields.info;
        }
    }
    ~result_info()
    {
        clear_fields();
    }
protected:
    struct {
        uint32_t length = 0;
        field_packet *info = nullptr;
    } fields;
};

class statement : public server_packet
{
public:
    uint32_t id = 0;
    uint16_t field_count = 0;
    uint16_t param_count = 0;
    uint16_t warning_count = 0;
    statement() { }
    statement(const char* data) : server_packet(data)
    {
        swMysqlPacketDump(header.length, header.number, data, "COM_STMT_PREPARE_OK_Packet");
        // skip the packet header
        data += SW_MYSQL_PACKET_HEADER_SIZE;
        // status (1) -- [00] OK
        SW_ASSERT(data[0] == SW_MYSQL_PACKET_OK);
        data += 1;
        // statement_id (4) -- statement-id
        id = sw_mysql_uint2korr4korr(data);
        data += 4;
        // num_columns (2) -- number of columns
        field_count = sw_mysql_uint2korr2korr(data);
        data += 2;
        // num_params (2) -- number of params
        param_count = sw_mysql_uint2korr2korr(data);
        data += 2;
        // reserved_1 (1) -- [00] filler
        data += 1;
        // warning_count (2) -- number of warnings
        warning_count = sw_mysql_uint2korr2korr(data);
        swoole_trace_log(
            SW_TRACE_MYSQL_CLIENT, "statement_id=%u, field_count=%u, param_count=%u, warning_count=%u",
            id, field_count, param_count, warning_count
        );
    }
};

class null_bitmap
{
public:
    static uint32_t get_size(uint32_t field_length)
    {
        return ((field_length + 9) / 8) + 1;
    }
    null_bitmap(const char *p, uint32_t size) :
            size(size)
    {
        map = new char[size];
        memcpy(map, p, size);
        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "null_count=%u", size);
    }
    inline bool is_null(size_t i)
    {
        return ((map + 1)[((i + 2) / 8)] & (0x01 << ((i + 2) % 8))) != 0;
    }
    ~null_bitmap()
    {
        delete[] map;
    }
protected:
    uint32_t size;
    char *map;
};
//-----------------------------------namespace end--------------------------------------------
}}
