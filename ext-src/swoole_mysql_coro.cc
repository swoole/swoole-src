/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Twosee  <twose@qq.com>                                       |
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "php_swoole_mysql_proto.h"

#include "swoole_string.h"

// see mysqlnd 'L64' macro redefined
#undef L64

SW_EXTERN_C_BEGIN
#include "ext/hash/php_hash.h"
#include "ext/hash/php_hash_sha.h"
#include "ext/standard/php_math.h"
#ifdef SW_USE_MYSQLND
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_charset.h"
#endif
SW_EXTERN_C_END

#include <unordered_map>

/* keep same with pdo and mysqli */
#define MYSQLND_UNKNOWN_SQLSTATE "HY000"
#define MYSQLND_SERVER_GONE "MySQL server has gone away"
#define MYSQLND_CR_UNKNOWN_ERROR 2000
#define MYSQLND_CR_CONNECTION_ERROR 2002
#define MYSQLND_CR_SERVER_GONE_ERROR 2006
#define MYSQLND_CR_OUT_OF_MEMORY 2008
#define MYSQLND_CR_SERVER_LOST 2013
#define MYSQLND_CR_COMMANDS_OUT_OF_SYNC 2014
#define MYSQLND_CR_CANT_FIND_CHARSET 2019
#define MYSQLND_CR_MALFORMED_PACKET 2027
#define MYSQLND_CR_NOT_IMPLEMENTED 2054
#define MYSQLND_CR_NO_PREPARE_STMT 2030
#define MYSQLND_CR_PARAMS_NOT_BOUND 2031
#define MYSQLND_CR_INVALID_PARAMETER_NO 2034
#define MYSQLND_CR_INVALID_BUFFER_USE 2035

using swoole::coroutine::Socket;
using namespace swoole;

namespace swoole {
class mysql_statement;
class mysql_client {
  public:
    /* session related {{{ */
    Socket *socket = nullptr;
    Socket::timeout_controller *tc = nullptr;

    enum sw_mysql_state state = SW_MYSQL_STATE_CLOSED;
    bool quit = false;
    mysql::result_info result;

    std::unordered_map<uint32_t, mysql_statement *> statements;
    mysql_statement *statement = nullptr;
    /* }}} */

    std::string host = SW_MYSQL_DEFAULT_HOST;
    uint16_t port = SW_MYSQL_DEFAULT_PORT;
    bool ssl = false;

    std::string user = "root";
    std::string password = "root";
    std::string database = "test";
    char charset = SW_MYSQL_DEFAULT_CHARSET;

    double connect_timeout = network::Socket::default_connect_timeout;
    bool strict_type = false;

    inline int get_error_code() {
        return error_code;
    }

    inline const char *get_error_msg() {
        return error_msg.c_str();
    }

    inline void non_sql_error(int code, const char *msg) {
        error_code = code;
        error_msg = std_string::format("SQLSTATE[" MYSQLND_UNKNOWN_SQLSTATE "] [%d] %s", code, msg);
    }

    template <typename... Args>
    inline void non_sql_error(int code, const char *format, Args... args) {
        error_code = code;
        error_msg = std_string::format(
            "SQLSTATE[" MYSQLND_UNKNOWN_SQLSTATE "] [%d] %s", code, std_string::format(format, args...).c_str());
    }

    void io_error() {
        if (state == SW_MYSQL_STATE_CLOSED) {
            non_sql_error(MYSQLND_CR_CONNECTION_ERROR, socket->errMsg);
        } else {
            non_sql_error(MYSQLND_CR_SERVER_GONE_ERROR,
                          MYSQLND_SERVER_GONE "%s%s",
                          socket->errCode ? " due to " : "",
                          socket->errCode ? socket->errMsg : "");
        }
        /* don't send QUIT after IO error */
        quit = true;
        close();
    }

    void proto_error(const char *data, const enum sw_mysql_packet_types expected_type) {
        mysql::server_packet packet(data);
        non_sql_error(MYSQLND_CR_MALFORMED_PACKET,
                      "Unexpected mysql packet length=%u, number=%u, type=%u, expected_type=%u",
                      packet.header.length,
                      packet.header.number,
                      (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE],
                      expected_type);
        close();
    }

    void server_error(const char *data) {
        mysql::err_packet err_packet(data);
        error_code = err_packet.code;
        error_msg =
            std_string::format("SQLSTATE[%s] [%d] %s", err_packet.sql_state, err_packet.code, err_packet.msg.c_str());
        state = SW_MYSQL_STATE_IDLE;
    }

    inline bool get_fetch_mode() {
        return fetch_mode;
    }

    inline bool set_fetch_mode(bool v) {
        if (sw_unlikely(socket && v)) {
            non_sql_error(ENOTSUP, "Can not use fetch mode after the connection is established");
            return false;
        }
        fetch_mode = v;
        return true;
    }

    inline bool get_defer() {
        return defer;
    }

    inline bool set_defer(bool v) {
        // if (sw_unlikely(fetch_mode && v))
        // {
        //      non_sql_error(ENOTSUP, "Can not use defer mode when fetch mode is on");
        //    return false;
        // }
        defer = v;
        return true;
    }

    void add_timeout_controller(double timeout, const enum Socket::TimeoutType type) {
        if (sw_unlikely(!socket)) {
            return;
        }
        // Notice: `timeout > 0` is wrong, maybe -1
        if (timeout != 0) {
            SW_ASSERT(!tc);
            tc = new Socket::timeout_controller(socket, timeout, type);
        }
    }

    inline bool has_timedout(enum Socket::TimeoutType type) {
        return tc && tc->has_timedout(type);
    }

    void del_timeout_controller() {
        if (tc) {
            delete tc;
            tc = nullptr;
        }
    }

    bool connect(std::string host, uint16_t port, bool ssl);

    inline bool connect() {
        return connect(host, port, ssl);
    }

    inline bool is_connected() {
        return socket && socket->is_connected();
    }

    inline int get_fd() {
        return socket ? socket->get_fd() : -1;
    }

    inline bool check_connection() {
        if (sw_unlikely(!is_connected())) {
            non_sql_error(MYSQLND_CR_CONNECTION_ERROR, "%s or %s", strerror(ECONNRESET), strerror(ENOTCONN));
            return false;
        }
        return true;
    }

    inline bool check_liveness() {
        if (sw_unlikely(!check_connection())) {
            return false;
        }
        if (sw_unlikely(!socket->check_liveness())) {
            non_sql_error(MYSQLND_CR_SERVER_GONE_ERROR, MYSQLND_SERVER_GONE);
            close();
            return false;
        }
        return true;
    }

    inline bool is_writable() {
        return is_connected() && !socket->has_bound(SW_EVENT_WRITE);
    }

    bool is_available_for_new_request() {
        if (sw_unlikely(state != SW_MYSQL_STATE_IDLE && state != SW_MYSQL_STATE_CLOSED)) {
            if (socket) {
                socket->check_bound_co(SW_EVENT_RDWR);
            }
            non_sql_error(EINPROGRESS,
                          "MySQL client is busy now on state#%d, "
                          "please use recv/fetchAll/nextResult to get all unread data "
                          "and wait for response then try again",
                          state);
            return false;
        }
        if (sw_unlikely(!check_liveness())) {
            return false;
        } else {
            /* without unread data */
            String *buffer = socket->get_read_buffer();
            SW_ASSERT(buffer->length == (size_t) buffer->offset);
            buffer->clear();
            return true;
        }
    }

    const char *recv_packet();

    inline const char *recv_none_error_packet() {
        const char *data = recv_packet();
        if (sw_unlikely(data && mysql::server_packet::is_err(data))) {
            server_error(data);
            return nullptr;
        }
        return data;
    }

    inline const char *recv_eof_packet() {
        const char *data = recv_packet();
        if (sw_unlikely(data && !mysql::server_packet::is_eof(data))) {
            proto_error(data, SW_MYSQL_PACKET_EOF);
            return nullptr;
        }
#ifdef SW_LOG_TRACE_OPEN
        mysql::eof_packet eof_packet(data);
#endif
        return data;
    }

    inline bool send_raw(const char *data, size_t length) {
        if (sw_unlikely(!check_connection())) {
            return false;
        } else {
            if (sw_unlikely(has_timedout(Socket::TIMEOUT_WRITE))) {
                io_error();
                return false;
            }
            if (sw_unlikely(socket->send_all(data, length) != (ssize_t) length)) {
                io_error();
                return false;
            }
            return true;
        }
    }

    bool send_packet(mysql::client_packet *packet);
    bool send_command(enum sw_mysql_command command, const char *sql = nullptr, size_t length = 0);
    // just for internal
    void send_command_without_check(enum sw_mysql_command command, const char *sql = nullptr, size_t length = 0);

    void query(zval *return_value, const char *statement, size_t statement_length);
    void send_query_request(zval *return_value, const char *statement, size_t statement_length);
    void recv_query_response(zval *return_value);
    const char *handle_row_data_size(mysql::row_data *row_data, uint8_t size);
    bool handle_row_data_lcb(mysql::row_data *row_data);
    void handle_row_data_text(zval *return_value, mysql::row_data *row_data, mysql::field_packet *field);
    void handle_strict_type(zval *ztext, mysql::field_packet *field);
    void fetch(zval *return_value);
    void fetch_all(zval *return_value);
    void next_result(zval *return_value);
    bool recv();

    bool send_prepare_request(const char *statement, size_t statement_length);
    mysql_statement *recv_prepare_response();

    void close();

    ~mysql_client() {
        SW_ASSERT(statements.empty());
        close();
    }

  private:
    int error_code = 0;
    std::string error_msg = "";

    /* unable to support both features at the same time, so we have to set them by method {{{ */
    bool fetch_mode = false;
    bool defer = false;
    /* }}} */

    // recv data of specified length
    const char *recv_length(size_t need_length, const bool try_to_recycle = false);
    // usually mysql->connect = connect(TCP) + handshake
    bool handshake();
};

class mysql_statement {
  public:
    std::string statement;
    mysql::statement info;
    mysql::result_info result;

    mysql_statement(mysql_client *client, const char *statement, size_t statement_length) : client(client) {
        this->statement = std::string(statement, statement_length);
    }

    inline mysql_client *get_client() {
        return client;
    }

    inline int get_error_code() {
        return sw_likely(client) ? client->get_error_code() : error_code;
    }

    inline const char *get_error_msg() {
        return sw_likely(client) ? client->get_error_msg() : error_msg.c_str();
    }

    inline bool is_available() {
        if (sw_unlikely(!client)) {
            error_code = ECONNRESET;
            error_msg = "statement must to be recompiled after the connection is broken";
            return false;
        }
        return true;
    }

    inline bool is_available_for_new_request() {
        if (sw_unlikely(!is_available())) {
            return false;
        }
        if (sw_unlikely(!client->is_available_for_new_request())) {
            return false;
        }
        return true;
    }

    inline void add_timeout_controller(double timeout, const enum Socket::TimeoutType type) {
        if (sw_likely(client)) {
            client->add_timeout_controller(timeout, type);
        }
    }

    inline void del_timeout_controller() {
        if (sw_likely(client)) {
            client->del_timeout_controller();
        }
    }

    // [notify = false]: mysql_client actively close
    inline void close(const bool notify = true) {
        if (client) {
            // if client point exists, socket is always available
            if (notify) {
                if (sw_likely(client->is_writable())) {
                    char id[4];
                    sw_mysql_int4store(id, info.id);
                    client->send_command_without_check(SW_MYSQL_COM_STMT_CLOSE, id, sizeof(id));
                }
                client->statements.erase(info.id);
            } else {
                error_code = client->get_error_code();
                error_msg = client->get_error_msg();
            }
            client = nullptr;
        }
    }

    ~mysql_statement() {
        close();
    }

    bool send_prepare_request();
    bool recv_prepare_response();

    void execute(zval *return_value, zval *params);
    void send_execute_request(zval *return_value, zval *params);
    void recv_execute_response(zval *return_value);

    void fetch(zval *return_value);
    void fetch_all(zval *return_value);
    void next_result(zval *return_value);

  private:
    mysql_client *client = nullptr;
    int error_code = 0;
    std::string error_msg;
};
}  // namespace swoole

using swoole::mysql_client;
using swoole::mysql_statement;

static zend_class_entry *swoole_mysql_coro_ce;
static zend_object_handlers swoole_mysql_coro_handlers;

static zend_class_entry *swoole_mysql_coro_exception_ce;
static zend_object_handlers swoole_mysql_coro_exception_handlers;

static zend_class_entry *swoole_mysql_coro_statement_ce;
static zend_object_handlers swoole_mysql_coro_statement_handlers;

struct mysql_coro_t {
    mysql_client *client;
    zend_object std;
};

struct mysql_coro_statement_t {
    mysql_statement *statement;
    zend_object *zclient;
    zend_object std;
};

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_mysql_coro, __construct);
static PHP_METHOD(swoole_mysql_coro, __destruct);
static PHP_METHOD(swoole_mysql_coro, connect);
static PHP_METHOD(swoole_mysql_coro, getDefer);
static PHP_METHOD(swoole_mysql_coro, setDefer);
static PHP_METHOD(swoole_mysql_coro, query);
static PHP_METHOD(swoole_mysql_coro, fetch);
static PHP_METHOD(swoole_mysql_coro, fetchAll);
static PHP_METHOD(swoole_mysql_coro, nextResult);
static PHP_METHOD(swoole_mysql_coro, prepare);
static PHP_METHOD(swoole_mysql_coro, recv);
static PHP_METHOD(swoole_mysql_coro, begin);
static PHP_METHOD(swoole_mysql_coro, commit);
static PHP_METHOD(swoole_mysql_coro, rollback);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape);
#endif
static PHP_METHOD(swoole_mysql_coro, close);

static PHP_METHOD(swoole_mysql_coro_statement, execute);
static PHP_METHOD(swoole_mysql_coro_statement, fetch);
static PHP_METHOD(swoole_mysql_coro_statement, fetchAll);
static PHP_METHOD(swoole_mysql_coro_statement, nextResult);
static PHP_METHOD(swoole_mysql_coro_statement, recv);
static PHP_METHOD(swoole_mysql_coro_statement, close);
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_optional_timeout, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_connect, 0, 0, 0)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_query, 0, 0, 1)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, timeout)
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

static const zend_function_entry swoole_mysql_coro_methods[] =
{
    PHP_ME(swoole_mysql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, setDefer, arginfo_swoole_mysql_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, connect, arginfo_swoole_mysql_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, query, arginfo_swoole_mysql_coro_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, fetch, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, fetchAll, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, nextResult, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, prepare, arginfo_swoole_mysql_coro_prepare, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, recv, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, begin, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, commit, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, rollback, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql_coro, escape, arginfo_swoole_mysql_coro_escape, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_mysql_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_mysql_coro_statement_methods[] =
{
    PHP_ME(swoole_mysql_coro_statement, execute, arginfo_swoole_mysql_coro_statement_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetch, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetchAll, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, nextResult, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, recv, arginfo_swoole_optional_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_sha256(const char *str, int len, unsigned char *digest) {
    PHP_SHA256_CTX context;
    PHP_SHA256Init(&context);
    PHP_SHA256Update(&context, (unsigned char *) str, len);
    PHP_SHA256Final(digest, &context);
}

bool mysql_client::connect(std::string host, uint16_t port, bool ssl) {
    if (socket && (host != this->host || port != this->port || ssl != this->ssl)) {
        close();
    }
    if (!socket) {
        if (host.compare(0, 6, "unix:/", 0, 6) == 0) {
            host = host.substr(sizeof("unix:") - 1);
            host.erase(0, host.find_first_not_of('/') - 1);
            socket = new Socket(SW_SOCK_UNIX_STREAM);
        } else if (host.find(':') != std::string::npos) {
            socket = new Socket(SW_SOCK_TCP6);
        } else {
            socket = new Socket(SW_SOCK_TCP);
        }
        if (sw_unlikely(socket->get_fd() < 0)) {
            php_swoole_fatal_error(E_WARNING, "new Socket() failed. Error: %s [%d]", strerror(errno), errno);
            non_sql_error(MYSQLND_CR_CONNECTION_ERROR, strerror(errno));
            delete socket;
            socket = nullptr;
            return false;
        }
        socket->set_zero_copy(true);
#ifdef SW_USE_OPENSSL
        if (ssl) {
            socket->enable_ssl_encrypt();
        }
#endif
        socket->set_timeout(connect_timeout, Socket::TIMEOUT_CONNECT);
        add_timeout_controller(connect_timeout, Socket::TIMEOUT_ALL);
        if (!socket->connect(host, port)) {
            io_error();
            return false;
        }
        this->host = host;
        this->port = port;
#ifdef SW_USE_OPENSSL
        this->ssl = ssl;
#endif
        if (!handshake()) {
            close();
            return false;
        }
        state = SW_MYSQL_STATE_IDLE;
        quit = false;
        del_timeout_controller();
    }
    return true;
}

const char *mysql_client::recv_length(size_t need_length, const bool try_to_recycle) {
    if (sw_likely(check_connection())) {
        ssize_t retval;
        String *buffer = socket->get_read_buffer();
        off_t offset = buffer->offset;                    // save offset instead of buffer point (due to realloc)
        size_t read_n = buffer->length - buffer->offset;  // readable bytes
        if (try_to_recycle && read_n == 0) {
            swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
                       "mysql buffer will be recycled, length=%zu, offset=%jd",
                       buffer->length,
                       (intmax_t) offset);
            buffer->clear();
            offset = 0;
        }
        while (read_n < need_length) {
            if (sw_unlikely(has_timedout(Socket::TIMEOUT_READ))) {
                io_error();
                return nullptr;
            }
            if (sw_unlikely(buffer->length == buffer->size)) {
                /* offset + need_length = new size (min) */
                if (!buffer->extend(SW_MEM_ALIGNED_SIZE_EX(offset + need_length, SwooleG.pagesize))) {
                    non_sql_error(MYSQLND_CR_OUT_OF_MEMORY, strerror(ENOMEM));
                    return nullptr;
                } else {
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "mysql buffer extend to %zu", buffer->size);
                }
            }
            retval = socket->recv(buffer->str + buffer->length, buffer->size - buffer->length);
            if (sw_unlikely(retval <= 0)) {
                io_error();
                return nullptr;
            }
            read_n += retval;
            buffer->length += retval;
        }
        buffer->offset += need_length;
        return buffer->str + offset;
    }
    return nullptr;
}

const char *mysql_client::recv_packet() {
    const char *p;
    uint32_t length;
    p = recv_length(SW_MYSQL_PACKET_HEADER_SIZE, true);
    if (sw_unlikely(!p)) {
        return nullptr;
    }
    length = mysql::packet::get_length(p);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "recv packet length=%u, number=%u", length, mysql::packet::get_number(p));
    p = recv_length(length);
    if (sw_unlikely(!p)) {
        return nullptr;
    }
    /* Notice: why we do this? because buffer maybe reallocated when recv data */
    return p - SW_MYSQL_PACKET_HEADER_SIZE;
}

bool mysql_client::send_packet(mysql::client_packet *packet) {
    const char *data = packet->get_data();
    uint32_t length = SW_MYSQL_PACKET_HEADER_SIZE + packet->get_length();
    if (sw_likely(send_raw(data, length))) {
        return true;
    }
    return false;
}

bool mysql_client::send_command(enum sw_mysql_command command, const char *sql, size_t length) {
    if (sw_likely(SW_MYSQL_PACKET_HEADER_SIZE + 1 + length <= SwooleG.pagesize)) {
        mysql::command_packet command_packet(command, sql, length);
        return send_raw(command_packet.get_data(), command_packet.get_data_length());
    } else {
        /* if the data is larger than page_size, copy memory to the kernel buffer multiple times is much faster */
        size_t send_s = SW_MIN(length, SW_MYSQL_MAX_PACKET_BODY_SIZE - 1), send_n = send_s, number = 0;
        mysql::command_packet command_packet(command);
        command_packet.set_header(1 + send_s, number++);

        if (sw_unlikely(!send_raw(command_packet.get_data(), SW_MYSQL_PACKET_HEADER_SIZE + 1)) ||
            !send_raw(sql, send_s)) {
            return false;
        }
        /* MySQL single packet size is 16M, we must subpackage */
        while (send_n < length) {
            send_s = length - send_n;
            send_s = SW_MIN(send_s, SW_MYSQL_MAX_PACKET_BODY_SIZE);
            command_packet.set_header(send_s, number++);
            if (sw_unlikely(!send_raw(command_packet.get_data(), SW_MYSQL_PACKET_HEADER_SIZE)) ||
                !send_raw(sql + send_n, send_s)) {
                return false;
            }
            send_n += send_s;
        }
        return true;
    }
}

void mysql_client::send_command_without_check(enum sw_mysql_command command, const char *sql, size_t length) {
    mysql::command_packet command_packet(command, sql, length);
    (void) (socket && socket->send(command_packet.get_data(), command_packet.get_data_length()));
}

bool mysql_client::handshake() {
    const char *data;
    // recv greeting pakcet
    if (sw_unlikely(!(data = recv_none_error_packet()))) {
        return false;
    }
    mysql::greeting_packet greeting_packet(data);
    // generate login packet
    do {
        mysql::login_packet login_packet(&greeting_packet, user, password, database, charset);
        if (sw_unlikely(!send_packet(&login_packet))) {
            return false;
        }
    } while (0);
    // recv auth switch request packet, 4 possible packet types
    switch (mysql::server_packet::parse_type(data = recv_packet())) {
    case SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST: {
        mysql::auth_switch_request_packet request(data);
        mysql::auth_switch_response_packet response(&request, password);
        if (sw_unlikely(!send_packet(&response))) {
            return false;
        }
        break;
    }
    case SW_MYSQL_PACKET_AUTH_SIGNATURE_REQUEST: {
        mysql::auth_signature_request_packet request(data);
        if (sw_unlikely(!request.is_vaild())) {
            goto _proto_error;
        }
        if (sw_likely(!request.is_full_auth_required())) {
            break;
        }
        // no cache, need full auth with rsa key (openssl required)
#ifdef SW_MYSQL_RSA_SUPPORT
        // tell the server we are prepared
        do {
            mysql::auth_signature_prepared_packet prepared(request.header.number + 1);
            if (sw_unlikely(!send_packet(&prepared))) {
                return false;
            }
        } while (0);
        // recv rsa key and encode the password
        do {
            if (sw_unlikely(!(data = recv_none_error_packet()))) {
                return false;
            }
            mysql::raw_data_packet raw_data_packet(data);
            mysql::auth_signature_response_packet response(
                &raw_data_packet, password, greeting_packet.auth_plugin_data);
            if (sw_unlikely(!send_packet(&response))) {
                return false;
            }
        } while (0);
        break;
#else
        error_code = EPROTONOSUPPORT;
        error_msg = SW_MYSQL_NO_RSA_ERROR;
        return false;
#endif
    }
    case SW_MYSQL_PACKET_OK: {
#ifdef SW_LOG_TRACE_OPEN
        mysql::ok_packet ok_packet(data);
#endif
        return true;
    }
    case SW_MYSQL_PACKET_ERR:
        server_error(data);
        return false;
    case SW_MYSQL_PACKET_NULL:
        // io_error
        return false;
    default:
    _proto_error:
        proto_error(data, SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST);
        return false;
    }
    // maybe ok packet or err packet
    if (sw_unlikely(!(data = recv_none_error_packet()))) {
        return false;
    }
#ifdef SW_LOG_TRACE_OPEN
    mysql::ok_packet ok_packet(data);
#endif
    return true;
}

void mysql_client::query(zval *return_value, const char *statement, size_t statement_length) {
    send_query_request(return_value, statement, statement_length);
    if (EXPECTED(!defer && Z_TYPE_P(return_value) == IS_TRUE)) {
        recv_query_response(return_value);
    }
}

void mysql_client::send_query_request(zval *return_value, const char *statement, size_t statement_length) {
    if (sw_unlikely(!is_available_for_new_request())) {
        RETURN_FALSE;
    }
    if (sw_unlikely(!send_command(SW_MYSQL_COM_QUERY, statement, statement_length))) {
        RETURN_FALSE;
    }
    state = SW_MYSQL_STATE_QUERY;
    RETURN_TRUE;
};

void mysql_client::recv_query_response(zval *return_value) {
    const char *data;
    if (sw_unlikely(!(data = recv_none_error_packet()))) {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_ok(data)) {
        mysql::ok_packet ok_packet(data);
        result.ok = ok_packet;
        state = ok_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_QUERY_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_TRUE;
    }
    do {
        mysql::lcb_packet lcb_packet(data);
        if (sw_unlikely(lcb_packet.length == 0)) {
            // is it possible?
            proto_error(data, SW_MYSQL_PACKET_FIELD);
            RETURN_FALSE;
        }
        result.alloc_fields(lcb_packet.length);
        for (uint32_t i = 0; i < lcb_packet.length; i++) {
            if (sw_unlikely(!(data = recv_packet()))) {
                RETURN_FALSE;
            }
            result.set_field(i, data);
        }
    } while (0);
    // expect eof
    if (sw_unlikely(!(data = recv_eof_packet()))) {
        RETURN_FALSE;
    }
    state = SW_MYSQL_STATE_QUERY_FETCH;
    if (get_fetch_mode()) {
        RETURN_TRUE;
    }
    fetch_all(return_value);
}

const char *mysql_client::handle_row_data_size(mysql::row_data *row_data, uint8_t size) {
    const char *p, *data;
    SW_ASSERT(size < sizeof(row_data->stack_buffer));
    if (sw_unlikely(!(p = row_data->read(size)))) {
        uint8_t received = row_data->recv(row_data->stack_buffer, size);
        if (sw_unlikely(!(data = recv_packet()))) {
            return nullptr;
        }
        row_data->next_packet(data);
        received += row_data->recv(row_data->stack_buffer + received, size - received);
        if (sw_unlikely(received != size)) {
            proto_error(data, SW_MYSQL_PACKET_ROW_DATA);
            return nullptr;
        }
        p = row_data->stack_buffer;
    }
    return p;
}

bool mysql_client::handle_row_data_lcb(mysql::row_data *row_data) {
    const char *p, *data;
    // recv 1 byte to get binary code size
    if (sw_unlikely(row_data->eof())) {
        if (sw_unlikely(!(data = recv_packet()))) {
            return false;
        }
        row_data->next_packet(data);
        if (sw_unlikely(row_data->eof())) {
            proto_error(data, SW_MYSQL_PACKET_ROW_DATA);
            return false;
        }
    }
    // decode lcb (use 0 to prevent read_ptr from moving)
    // recv "size" bytes to get binary code length
    p = handle_row_data_size(row_data, mysql::read_lcb_size(row_data->read(0)));
    if (sw_unlikely(!p)) {
        return false;
    }
    mysql::read_lcb(p, &row_data->text.length, &row_data->text.nul);
    return true;
}

void mysql_client::handle_row_data_text(zval *return_value, mysql::row_data *row_data, mysql::field_packet *field) {
    const char *p, *data;
    if (sw_unlikely(!handle_row_data_lcb(row_data))) {
        RETURN_FALSE;
    }
    if (sw_unlikely(!(p = row_data->read(row_data->text.length)))) {
        size_t received = 0, required = row_data->text.length;
        if (required < sizeof(row_data->stack_buffer)) {
            p = handle_row_data_size(row_data, required);
            if (sw_unlikely(!p)) {
                RETURN_FALSE;
            }
        } else {
            zend_string *zstring = zend_string_alloc(required, 0);
            do {
                received += row_data->recv(ZSTR_VAL(zstring) + received, required - received);
                if (received == required) {
                    break;
                }
                if (row_data->eof()) {
                    if (sw_unlikely(!(data = recv_packet()))) {
                        RETURN_FALSE;
                    }
                    row_data->next_packet(data);
                }
            } while (true);
            ZSTR_VAL(zstring)[ZSTR_LEN(zstring)] = '\0';
            RETVAL_STR(zstring);
            goto _return;
        }
    }
    if (row_data->text.nul || field->type == SW_MYSQL_TYPE_NULL) {
        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s is null", field->name_length, field->name);
        RETURN_NULL();
    } else {
        RETVAL_STRINGL(p, row_data->text.length);
    _return:
        swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
                   "%.*s=[%lu]%.*s%s",
                   field->name_length,
                   field->name,
                   Z_STRLEN_P(return_value),
                   (int) SW_MIN(32, Z_STRLEN_P(return_value)),
                   Z_STRVAL_P(return_value),
                   (Z_STRLEN_P(return_value) > 32 ? "..." : ""));
    }
}

void mysql_client::handle_strict_type(zval *ztext, mysql::field_packet *field) {
    if (sw_likely(Z_TYPE_P(ztext) == IS_STRING)) {
        char *error;
        switch (field->type) {
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
        case SW_MYSQL_TYPE_GEOMETRY:
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
        case SW_MYSQL_TYPE_YEAR:
        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
        case SW_MYSQL_TYPE_DATE:
        case SW_MYSQL_TYPE_JSON:
            return;
        /* Integer */
        case SW_MYSQL_TYPE_TINY:
        case SW_MYSQL_TYPE_SHORT:
        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                ulong_t uint = strtoul(Z_STRVAL_P(ztext), &error, 10);
                if (sw_likely(*error == '\0')) {
                    zend_string_release(Z_STR_P(ztext));
                    ZVAL_LONG(ztext, uint);
                }
            } else {
                long sint = strtol(Z_STRVAL_P(ztext), &error, 10);
                if (sw_likely(*error == '\0')) {
                    zend_string_release(Z_STR_P(ztext));
                    ZVAL_LONG(ztext, sint);
                }
            }
            break;
        case SW_MYSQL_TYPE_LONGLONG:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                unsigned long long ubigint = strtoull(Z_STRVAL_P(ztext), &error, 10);
                if (sw_likely(*error == '\0' && ubigint <= ZEND_LONG_MAX)) {
                    zend_string_release(Z_STR_P(ztext));
                    ZVAL_LONG(ztext, ubigint);
                }
            } else {
                long long sbigint = strtoll(Z_STRVAL_P(ztext), &error, 10);
                if (sw_likely(*error == '\0')) {
                    zend_string_release(Z_STR_P(ztext));
                    ZVAL_LONG(ztext, sbigint);
                }
            }
            break;
        case SW_MYSQL_TYPE_FLOAT:
        case SW_MYSQL_TYPE_DOUBLE: {
            double mdouble = strtod(Z_STRVAL_P(ztext), &error);
            if (sw_likely(*error == '\0')) {
                zend_string_release(Z_STR_P(ztext));
                ZVAL_DOUBLE(ztext, mdouble);
            }
            break;
        }
        default: {
            swoole_warning("unknown type[%d] for field [%.*s].", field->type, field->name_length, field->name);
            break;
        }
        }
    }
}

void mysql_client::fetch(zval *return_value) {
    if (sw_unlikely(!is_connected())) {
        RETURN_FALSE;
    }
    if (sw_unlikely(state != SW_MYSQL_STATE_QUERY_FETCH)) {
        RETURN_NULL();
    }
    const char *data;
    if (sw_unlikely(!(data = recv_packet()))) {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_eof(data)) {
        mysql::eof_packet eof_packet(data);
        state =
            eof_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_QUERY_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_NULL();
    }
    do {
        mysql::row_data row_data(data);
        array_init_size(return_value, result.get_fields_length());
        for (uint32_t i = 0; i < result.get_fields_length(); i++) {
            mysql::field_packet *field = result.get_field(i);
            zval ztext;
            handle_row_data_text(&ztext, &row_data, field);
            if (sw_unlikely(Z_TYPE_P(&ztext) == IS_FALSE)) {
                zval_ptr_dtor(return_value);
                RETURN_FALSE;
            }
            if (strict_type) {
                handle_strict_type(&ztext, field);
            }
            add_assoc_zval_ex(return_value, field->name, field->name_length, &ztext);
        }
    } while (0);
}

void mysql_client::fetch_all(zval *return_value) {
    array_init(return_value);
    while (true) {
        zval zrow;
        fetch(&zrow);
        if (sw_unlikely(ZVAL_IS_NULL(&zrow))) {
            // eof
            return;
        }
        if (sw_unlikely(Z_TYPE_P(&zrow) == IS_FALSE)) {
            // error
            zval_ptr_dtor(return_value);
            RETURN_FALSE;
        }
        (void) add_next_index_zval(return_value, &zrow);
    }
}

void mysql_client::next_result(zval *return_value) {
    if (sw_unlikely(state == SW_MYSQL_STATE_QUERY_FETCH)) {
        // skip unread data
        fetch_all(return_value);
        zval_ptr_dtor(return_value);
        next_result(return_value);
    } else if (sw_likely(state == SW_MYSQL_STATE_QUERY_MORE_RESULTS)) {
        recv_query_response(return_value);
    } else if (state == SW_MYSQL_STATE_IDLE) {
        RETURN_NULL();
    } else {
        RETURN_FALSE;
    }
}

bool mysql_client::send_prepare_request(const char *statement, size_t statement_length) {
    this->statement = new mysql_statement(this, statement, statement_length);
    if (sw_unlikely(!this->statement->send_prepare_request())) {
        delete this->statement;
        this->statement = nullptr;
        return false;
    }
    return true;
}

mysql_statement *mysql_client::recv_prepare_response() {
    if (sw_likely(state == SW_MYSQL_STATE_PREPARE)) {
        mysql_statement *statement = this->statement;
        SW_ASSERT(statement != nullptr);
        this->statement = nullptr;
        if (sw_unlikely(!statement->recv_prepare_response())) {
            delete statement;
            return nullptr;
        }
        statements[statement->info.id] = statement;
        return statement;
    }
    return nullptr;
}

void mysql_client::close() {
    state = SW_MYSQL_STATE_CLOSED;
    Socket *socket = this->socket;
    if (socket) {
        del_timeout_controller();
        if (!quit && is_writable()) {
            send_command_without_check(SW_MYSQL_COM_QUIT);
            quit = true;
        }
        // make statements non-available
        while (!statements.empty()) {
            auto i = statements.begin();
            i->second->close(false);
            statements.erase(i);
        }
        if (sw_likely(!socket->has_bound())) {
            this->socket = nullptr;
        }
        if (sw_likely(socket->close())) {
            delete socket;
        }
    }
}

bool mysql_statement::send_prepare_request() {
    if (sw_unlikely(!is_available_for_new_request())) {
        return false;
    }
    if (sw_unlikely(!client->send_command(SW_MYSQL_COM_STMT_PREPARE, statement.c_str(), statement.length()))) {
        return false;
    }
    client->state = SW_MYSQL_STATE_PREPARE;
    return true;
}

bool mysql_statement::recv_prepare_response() {
    if (sw_unlikely(!is_available())) {
        return false;
    } else {
        client->state = SW_MYSQL_STATE_IDLE;
    }
    const char *data;
    if (sw_unlikely(!(data = client->recv_none_error_packet()))) {
        return false;
    }
    info = mysql::statement(data);
    if (sw_likely(info.param_count != 0)) {
        for (uint16_t i = info.param_count; i--;) {
            if (sw_unlikely(!(data = client->recv_packet()))) {
                return false;
            }
#ifdef SW_LOG_TRACE_OPEN
            mysql::param_packet param_packet(data);
#endif
        }
        if (sw_unlikely(!(data = client->recv_eof_packet()))) {
            return false;
        }
    }
    if (info.field_count != 0) {
        result.alloc_fields(info.field_count);
        for (uint16_t i = 0; i < info.field_count; i++) {
            if (sw_unlikely(!(data = client->recv_packet()))) {
                return false;
            }
            result.set_field(i, data);
        }
        if (sw_unlikely(!(data = client->recv_eof_packet()))) {
            return false;
        }
    }
    return true;
}

void mysql_statement::execute(zval *return_value, zval *params) {
    send_execute_request(return_value, params);
    /* Notice: must check return_value first */
    if (EXPECTED(Z_TYPE_P(return_value) == IS_TRUE && !client->get_defer())) {
        recv_execute_response(return_value);
    }
}

void mysql_statement::send_execute_request(zval *return_value, zval *params) {
    if (sw_unlikely(!is_available_for_new_request())) {
        RETURN_FALSE;
    }

    uint32_t param_count = params ? php_swoole_array_length(params) : 0;

    if (sw_unlikely(param_count != info.param_count)) {
        client->non_sql_error(MYSQLND_CR_INVALID_PARAMETER_NO,
                              "Statement#%u expects %u parameter, %u given.",
                              info.id,
                              info.param_count,
                              param_count);
        RETURN_FALSE;
    }

    String *buffer = client->socket->get_write_buffer();
    char *p = buffer->str;

    memset(p, 0, 5);
    // command
    buffer->str[4] = SW_MYSQL_COM_STMT_EXECUTE;
    buffer->length = 5;
    p += 5;

    // stmt.id
    sw_mysql_int4store(p, info.id);
    p += 4;
    // flags = CURSOR_TYPE_NO_CURSOR
    sw_mysql_int1store(p, 0);
    p += 1;
    // iteration_count
    sw_mysql_int4store(p, 1);
    p += 4;
    buffer->length += 9;

    // TODO: support more types
    if (param_count != 0) {
        // null bitmap
        size_t null_start_offset = p - buffer->str;
        unsigned int map_size = (param_count + 7) / 8;
        memset(p, 0, map_size);
        p += map_size;
        buffer->length += map_size;

        // rebind
        sw_mysql_int1store(p, 1);
        p += 1;
        buffer->length += 1;

        size_t type_start_offset = p - buffer->str;
        p += param_count * 2;
        buffer->length += param_count * 2;

        char stack_buffer[10];
        zend_ulong index = 0;
        zval *value;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), value) {
            switch (client->strict_type ? Z_TYPE_P(value) : (IS_NULL == Z_TYPE_P(value) ? IS_NULL : IS_STRING)) {
            case IS_NULL:
                *((buffer->str + null_start_offset) + (index / 8)) |= (1UL << (index % 8));
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_NULL);
                break;
            case IS_TRUE:
            case IS_FALSE:
            case IS_LONG:
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_LONGLONG);
                sw_mysql_int8store(stack_buffer, zval_get_long(value));
                if (buffer->append(stack_buffer, mysql::get_static_type_size(SW_MYSQL_TYPE_LONGLONG)) < 0) {
                    RETURN_FALSE;
                }
                break;
            case IS_DOUBLE:
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_DOUBLE);
                sw_mysql_doublestore(stack_buffer, zval_get_double(value));
                if (buffer->append(stack_buffer, mysql::get_static_type_size(SW_MYSQL_TYPE_DOUBLE)) < 0) {
                    RETURN_FALSE;
                }
                break;
            default:
                zend::String str_value(value);
                uint8_t lcb_size = mysql::write_lcb(stack_buffer, str_value.len());
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_VAR_STRING);
                if (buffer->append(stack_buffer, lcb_size) < 0) {
                    RETURN_FALSE;
                }
                if (buffer->append(str_value.val(), str_value.len()) < 0) {
                    RETURN_FALSE;
                }
            }
            index++;
        }
        ZEND_HASH_FOREACH_END();
    }
    do {
        size_t length = buffer->length - SW_MYSQL_PACKET_HEADER_SIZE;
        size_t send_s = SW_MIN(length, SW_MYSQL_MAX_PACKET_BODY_SIZE);
        mysql::packet::set_header(buffer->str, send_s, 0);
        if (sw_unlikely(!client->send_raw(buffer->str, SW_MYSQL_PACKET_HEADER_SIZE + send_s))) {
            RETURN_FALSE;
        }
        if (sw_unlikely(length > SW_MYSQL_MAX_PACKET_BODY_SIZE)) {
            size_t send_n = SW_MYSQL_MAX_PACKET_BODY_SIZE, number = 1;
            /* MySQL single packet size is 16M, we must subpackage */
            while (send_n < length) {
                send_s = length - send_n;
                send_s = SW_MIN(send_s, SW_MYSQL_MAX_PACKET_BODY_SIZE);
                mysql::packet::set_header(buffer->str, send_s, number++);
                if (sw_unlikely(!client->send_raw(buffer->str, SW_MYSQL_PACKET_HEADER_SIZE)) ||
                    !client->send_raw(buffer->str + SW_MYSQL_PACKET_HEADER_SIZE + send_n, send_s)) {
                    RETURN_FALSE;
                }
                send_n += send_s;
            }
        }
    } while (0);
    client->state = SW_MYSQL_STATE_EXECUTE;
    RETURN_TRUE;
}

void mysql_statement::recv_execute_response(zval *return_value) {
    if (sw_unlikely(!is_available())) {
        RETURN_FALSE;
    }
    const char *data;
    if (sw_unlikely(!(data = client->recv_none_error_packet()))) {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_ok(data)) {
        mysql::ok_packet ok_packet(data);
        result.ok = ok_packet;
        client->state =
            ok_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_EXECUTE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_TRUE;
    }
    do {
        mysql::lcb_packet lcb_packet(data);
        if (sw_unlikely(lcb_packet.length == 0)) {
            // is it possible?
            client->proto_error(data, SW_MYSQL_PACKET_FIELD);
            RETURN_FALSE;
        }
        // although we have already known the field data when we prepared the statement,
        // we don't know if the data is always reliable, such as when we using stored procedure...
        // so we should not optimize here for the time being for stability
        result.alloc_fields(lcb_packet.length);
        for (size_t i = 0; i < result.get_fields_length(); i++) {
            if (sw_unlikely(!(data = client->recv_packet()))) {
                RETURN_FALSE;
            }
            result.set_field(i, data);
        }
    } while (0);
    // expect eof
    if (sw_unlikely(!(data = client->recv_eof_packet()))) {
        RETURN_FALSE;
    }
    client->state = SW_MYSQL_STATE_EXECUTE_FETCH;
    if (client->get_fetch_mode()) {
        RETURN_TRUE;
    }
    fetch_all(return_value);
}

void mysql_statement::fetch(zval *return_value) {
    if (sw_unlikely(!is_available())) {
        RETURN_FALSE;
    }
    if (sw_unlikely(client->state != SW_MYSQL_STATE_EXECUTE_FETCH)) {
        RETURN_NULL();
    }
    const char *data;
    if (sw_unlikely(!(data = client->recv_packet()))) {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_eof(data)) {
        mysql::eof_packet eof_packet(data);
        client->state =
            eof_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_EXECUTE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_NULL();
    }
    do {
        mysql::row_data row_data(data);
        uint32_t null_bitmap_size = mysql::null_bitmap::get_size(result.get_fields_length());
        mysql::null_bitmap null_bitmap(row_data.read(null_bitmap_size), null_bitmap_size);

        array_init_size(return_value, result.get_fields_length());
        for (uint32_t i = 0; i < result.get_fields_length(); i++) {
            mysql::field_packet *field = result.get_field(i);

            /* to check Null-Bitmap @see https://dev.mysql.com/doc/internals/en/null-bitmap.html */
            if (null_bitmap.is_null(i) || field->type == SW_MYSQL_TYPE_NULL) {
                swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s is null", field->name_length, field->name);
                add_assoc_null_ex(return_value, field->name, field->name_length);
                continue;
            }

            switch (field->type) {
            /* String */
            case SW_MYSQL_TYPE_TINY_BLOB:
            case SW_MYSQL_TYPE_MEDIUM_BLOB:
            case SW_MYSQL_TYPE_LONG_BLOB:
            case SW_MYSQL_TYPE_BLOB:
            case SW_MYSQL_TYPE_DECIMAL:
            case SW_MYSQL_TYPE_NEWDECIMAL:
            case SW_MYSQL_TYPE_BIT:
            case SW_MYSQL_TYPE_JSON:
            case SW_MYSQL_TYPE_STRING:
            case SW_MYSQL_TYPE_VAR_STRING:
            case SW_MYSQL_TYPE_VARCHAR:
            case SW_MYSQL_TYPE_NEWDATE:
            case SW_MYSQL_TYPE_GEOMETRY: {
            _add_string:
                zval ztext;
                client->handle_row_data_text(&ztext, &row_data, field);
                if (sw_unlikely(Z_TYPE_P(&ztext) == IS_FALSE)) {
                    zval_ptr_dtor(return_value);
                    RETURN_FALSE;
                }
                add_assoc_zval_ex(return_value, field->name, field->name_length, &ztext);
                break;
            }
            default: {
                const char *p = nullptr;
                uint8_t lcb = mysql::get_static_type_size(field->type);
                if (lcb == 0) {
                    client->handle_row_data_lcb(&row_data);
                    lcb = row_data.text.length;
                }
                p = client->handle_row_data_size(&row_data, lcb);
                if (sw_unlikely(!p)) {
                    zval_ptr_dtor(return_value);
                    RETURN_FALSE;
                }
                /* Date Time */
                switch (field->type) {
                case SW_MYSQL_TYPE_TIMESTAMP:
                case SW_MYSQL_TYPE_DATETIME: {
                    std::string datetime = mysql::datetime(p, row_data.text.length, field->decimals);
                    add_assoc_stringl_ex(
                        return_value, field->name, field->name_length, (char *) datetime.c_str(), datetime.length());
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, datetime.c_str());
                    break;
                }
                case SW_MYSQL_TYPE_TIME: {
                    std::string time = mysql::time(p, row_data.text.length, field->decimals);
                    add_assoc_stringl_ex(
                        return_value, field->name, field->name_length, (char *) time.c_str(), time.length());
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, time.c_str());
                    break;
                }
                case SW_MYSQL_TYPE_DATE: {
                    std::string date = mysql::date(p, row_data.text.length);
                    add_assoc_stringl_ex(
                        return_value, field->name, field->name_length, (char *) date.c_str(), date.length());
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, date.c_str());
                    break;
                }
                case SW_MYSQL_TYPE_YEAR: {
                    add_assoc_long_ex(return_value, field->name, field->name_length, sw_mysql_uint2korr2korr(p));
                    swoole_trace_log(
                        SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, sw_mysql_uint2korr2korr(p));
                    break;
                }
                /* Number */
                case SW_MYSQL_TYPE_TINY:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(uint8_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, *(uint8_t *) p);
                    } else {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(int8_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, *(int8_t *) p);
                    }
                    break;
                case SW_MYSQL_TYPE_SHORT:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(uint16_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, *(uint16_t *) p);
                    } else {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(int16_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, *(int16_t *) p);
                    }
                    break;
                case SW_MYSQL_TYPE_INT24:
                case SW_MYSQL_TYPE_LONG:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(uint32_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, *(uint32_t *) p);
                    } else {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(int32_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, *(int32_t *) p);
                    }
                    break;
                case SW_MYSQL_TYPE_LONGLONG:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG) {
                        add_assoc_ulong_safe_ex(return_value, field->name, field->name_length, *(uint64_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%lu", field->name_length, field->name, *(uint64_t *) p);
                    } else {
                        add_assoc_long_ex(return_value, field->name, field->name_length, *(int64_t *) p);
                        swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%ld", field->name_length, field->name, *(int64_t *) p);
                    }
                    break;
                case SW_MYSQL_TYPE_FLOAT: {
                    double dv = sw_php_math_round(*(float *) p, 7, PHP_ROUND_HALF_DOWN);
                    add_assoc_double_ex(return_value, field->name, field->name_length, dv);
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%.7f", field->name_length, field->name, dv);
                } break;
                case SW_MYSQL_TYPE_DOUBLE: {
                    add_assoc_double_ex(return_value, field->name, field->name_length, *(double *) p);
                    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "%.*s=%.16f", field->name_length, field->name, *(double *) p);
                } break;
                default:
                    swoole_warning("unknown type[%d] for field [%.*s].", field->type, field->name_length, field->name);
                    goto _add_string;
                }
            }
            }
        }
    } while (0);
}

void mysql_statement::fetch_all(zval *return_value) {
    if (sw_unlikely(!is_available())) {
        RETURN_FALSE;
    }

    zval zrow;
    array_init(return_value);
    while (true) {
        fetch(&zrow);
        if (sw_unlikely(ZVAL_IS_NULL(&zrow))) {
            // eof
            return;
        }
        if (sw_unlikely(Z_TYPE_P(&zrow) == IS_FALSE)) {
            // error
            zval_ptr_dtor(return_value);
            RETURN_FALSE;
        }
        (void) add_next_index_zval(return_value, &zrow);
    }
}

void mysql_statement::next_result(zval *return_value) {
    if (sw_unlikely(!is_available())) {
        RETURN_FALSE;
    }
    if (sw_unlikely(client->state == SW_MYSQL_STATE_EXECUTE_FETCH)) {
        // skip unread data
        fetch_all(return_value);
        zval_ptr_dtor(return_value);
        next_result(return_value);
    } else if (sw_likely(client->state == SW_MYSQL_STATE_EXECUTE_MORE_RESULTS)) {
        recv_execute_response(return_value);
    } else if (client->state == SW_MYSQL_STATE_IDLE) {
        RETURN_NULL();
    } else {
        RETURN_FALSE;
    }
}

static sw_inline mysql_coro_t *php_swoole_mysql_coro_fetch_object(zend_object *obj) {
    return (mysql_coro_t *) ((char *) obj - swoole_mysql_coro_handlers.offset);
}

static sw_inline mysql_client *php_swoole_get_mysql_client(zval *zobject) {
    return php_swoole_mysql_coro_fetch_object(Z_OBJ_P(zobject))->client;
}

static void php_swoole_mysql_coro_free_object(zend_object *object) {
    mysql_coro_t *zmc = php_swoole_mysql_coro_fetch_object(object);
    delete zmc->client;
    zend_object_std_dtor(&zmc->std);
}

static zend_object *php_swoole_mysql_coro_create_object(zend_class_entry *ce) {
    mysql_coro_t *zmc = (mysql_coro_t *) zend_object_alloc(sizeof(mysql_coro_t), ce);
    zend_object_std_init(&zmc->std, ce);
    object_properties_init(&zmc->std, ce);
    zmc->std.handlers = &swoole_mysql_coro_handlers;
    zmc->client = new mysql_client;
    return &zmc->std;
}

static sw_inline mysql_coro_statement_t *php_swoole_mysql_coro_statement_fetch_object(zend_object *obj) {
    return (mysql_coro_statement_t *) ((char *) obj - swoole_mysql_coro_statement_handlers.offset);
}

static sw_inline mysql_statement *php_swoole_get_mysql_statement(zval *zobject) {
    return php_swoole_mysql_coro_statement_fetch_object(Z_OBJ_P(zobject))->statement;
}

static void php_swoole_mysql_coro_statement_free_object(zend_object *object) {
    mysql_coro_statement_t *zms = php_swoole_mysql_coro_statement_fetch_object(object);
    delete zms->statement;
    OBJ_RELEASE(zms->zclient);
    zend_object_std_dtor(&zms->std);
}

static sw_inline zend_object *php_swoole_mysql_coro_statement_create_object(zend_class_entry *ce,
                                                                            mysql_statement *statement,
                                                                            zend_object *client) {
    zval zobject;
    mysql_coro_statement_t *zms = (mysql_coro_statement_t *) zend_object_alloc(sizeof(mysql_coro_statement_t), ce);
    zend_object_std_init(&zms->std, ce);
    object_properties_init(&zms->std, ce);
    zms->std.handlers = &swoole_mysql_coro_statement_handlers;
    ZVAL_OBJ(&zobject, &zms->std);
    zend_update_property_long(ce, SW_Z8_OBJ_P(&zobject), ZEND_STRL("id"), statement->info.id);
    zms->statement = statement;
    zms->zclient = client;
    GC_ADDREF(client);
    return &zms->std;
}

static sw_inline zend_object *php_swoole_mysql_coro_statement_create_object(mysql_statement *statement,
                                                                            zend_object *client) {
    return php_swoole_mysql_coro_statement_create_object(swoole_mysql_coro_statement_ce, statement, client);
}

static zend_object *php_swoole_mysql_coro_statement_create_object(zend_class_entry *ce) {
    php_swoole_fatal_error(E_ERROR, "you must create mysql statement object by prepare method");
    return nullptr;
}

static sw_inline void swoole_mysql_coro_sync_error_properties(zval *zobject,
                                                              int error_code,
                                                              const char *error_msg,
                                                              const bool connected = true) {
    SW_ASSERT(instanceof_function(Z_OBJCE_P(zobject), swoole_mysql_coro_ce) ||
              instanceof_function(Z_OBJCE_P(zobject), swoole_mysql_coro_statement_ce));
    zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("errno"), error_code);
    zend_update_property_string(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("error"), error_msg);
    if (!connected) {
        zend_update_property_bool(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("connected"), connected);
    }
}

static sw_inline void swoole_mysql_coro_sync_query_result_properties(zval *zobject,
                                                                     mysql_client *mc,
                                                                     zval *return_value) {
    switch (Z_TYPE_P(return_value)) {
    case IS_TRUE: {
        mysql::ok_packet *ok_packet = &mc->result.ok;
        zend_update_property_long(
            Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("affected_rows"), ok_packet->affected_rows);
        zend_update_property_long(
            Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("insert_id"), ok_packet->last_insert_id);
        break;
    }
    case IS_FALSE: {
        swoole_mysql_coro_sync_error_properties(zobject, mc->get_error_code(), mc->get_error_msg());
        break;
    }
    default:
        break;
    }
}

static sw_inline void swoole_mysql_coro_sync_execute_error_properties(zval *zobject,
                                                                      int error_code,
                                                                      const char *error_msg,
                                                                      const bool connected = true) {
    swoole_mysql_coro_sync_error_properties(zobject, error_code, error_msg, connected);

    /* backward compatibility (sync error info to client) */
    zval zclient;
    ZVAL_OBJ(&zclient, php_swoole_mysql_coro_statement_fetch_object(Z_OBJ_P(zobject))->zclient);
    swoole_mysql_coro_sync_error_properties(&zclient, error_code, error_msg, connected);
}

static sw_inline void swoole_mysql_coro_sync_execute_result_properties(zval *zobject, zval *return_value) {
    mysql_coro_statement_t *zms = php_swoole_mysql_coro_statement_fetch_object(Z_OBJ_P(zobject));
    mysql_statement *ms = zms->statement;

    switch (Z_TYPE_P(return_value)) {
    case IS_TRUE: {
        mysql::ok_packet *ok_packet = &ms->result.ok;
        zend_update_property_long(
            Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("affected_rows"), ok_packet->affected_rows);
        zend_update_property_long(
            Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("insert_id"), ok_packet->last_insert_id);

        /* backward compatibility (sync result info to client) */
        zval zclient;
        ZVAL_OBJ(&zclient, zms->zclient);
        zend_update_property_long(
            Z_OBJCE_P(&zclient), SW_Z8_OBJ_P(&zclient), ZEND_STRL("affected_rows"), ok_packet->affected_rows);
        zend_update_property_long(
            Z_OBJCE_P(&zclient), SW_Z8_OBJ_P(&zclient), ZEND_STRL("insert_id"), ok_packet->last_insert_id);
        break;
    }
    case IS_FALSE: {
        swoole_mysql_coro_sync_execute_error_properties(zobject, ms->get_error_code(), ms->get_error_msg());
        break;
    }
    default:
        break;
    }
}

void php_swoole_mysql_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_mysql_coro, "Swoole\\Coroutine\\MySQL", nullptr, "Co\\MySQL", swoole_mysql_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_mysql_coro);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_mysql_coro, php_swoole_mysql_coro_create_object, php_swoole_mysql_coro_free_object, mysql_coro_t, std);
#if PHP_VERSION_ID >= 80200
	zend_add_parameter_attribute((zend_function *) zend_hash_str_find_ptr(&swoole_mysql_coro_ce->function_table, SW_STRL("connect")), 0, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);
#endif

    SW_INIT_CLASS_ENTRY(swoole_mysql_coro_statement,
                        "Swoole\\Coroutine\\MySQL\\Statement",
                        nullptr,
                        "Co\\MySQL\\Statement",
                        swoole_mysql_coro_statement_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_mysql_coro_statement);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro_statement, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_statement, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_mysql_coro_statement,
                               php_swoole_mysql_coro_statement_create_object,
                               php_swoole_mysql_coro_statement_free_object,
                               mysql_coro_statement_t,
                               std);

    SW_INIT_CLASS_ENTRY_EX(swoole_mysql_coro_exception,
                           "Swoole\\Coroutine\\MySQL\\Exception",
                           nullptr,
                           "Co\\MySQL\\Exception",
                           nullptr,
                           swoole_exception);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_mysql_coro_exception);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro_exception, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_exception, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_mysql_coro_exception);

    zend_declare_property_null(swoole_mysql_coro_ce, ZEND_STRL("serverInfo"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_mysql_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("connect_errno"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce, ZEND_STRL("connect_error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_statement_ce, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_UNKNOWN_ERROR", MYSQLND_CR_UNKNOWN_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_CONNECTION_ERROR", MYSQLND_CR_CONNECTION_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_SERVER_GONE_ERROR", MYSQLND_CR_SERVER_GONE_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_OUT_OF_MEMORY", MYSQLND_CR_OUT_OF_MEMORY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_SERVER_LOST", MYSQLND_CR_SERVER_LOST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_COMMANDS_OUT_OF_SYNC", MYSQLND_CR_COMMANDS_OUT_OF_SYNC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_CANT_FIND_CHARSET", MYSQLND_CR_CANT_FIND_CHARSET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_MALFORMED_PACKET", MYSQLND_CR_MALFORMED_PACKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_NOT_IMPLEMENTED", MYSQLND_CR_NOT_IMPLEMENTED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_NO_PREPARE_STMT", MYSQLND_CR_NO_PREPARE_STMT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_PARAMS_NOT_BOUND", MYSQLND_CR_PARAMS_NOT_BOUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_INVALID_PARAMETER_NO", MYSQLND_CR_INVALID_PARAMETER_NO);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MYSQLND_CR_INVALID_BUFFER_USE", MYSQLND_CR_INVALID_BUFFER_USE);
}

static PHP_METHOD(swoole_mysql_coro, __construct) {}
static PHP_METHOD(swoole_mysql_coro, __destruct) {}

static PHP_METHOD(swoole_mysql_coro, connect) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    zval *zserver_info = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY_EX(zserver_info, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zserver_info) {
        HashTable *ht = Z_ARRVAL_P(zserver_info);
        zval *ztmp;

        if (php_swoole_array_get_value(ht, "host", ztmp)) {
            mc->host = std::string(zend::String(ztmp).val());
        } else {
            zend_throw_exception(swoole_mysql_coro_exception_ce, "Parameter [host] is required", EINVAL);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "port", ztmp)) {
            mc->port = zval_get_long(ztmp);
        }
        if (php_swoole_array_get_value(ht, "ssl", ztmp)) {
            mc->ssl = zval_is_true(ztmp);
#ifndef SW_USE_OPENSSL
            if (sw_unlikely(mc->ssl)) {
                zend_throw_exception_ex(
                    swoole_mysql_coro_exception_ce,
                    EPROTONOSUPPORT,
                    "you must configure with `--enable-openssl` to support ssl connection when compiling Swoole");
                RETURN_FALSE;
            }
#endif
        }
        if (php_swoole_array_get_value(ht, "user", ztmp)) {
            mc->user = std::string(zend::String(ztmp).val());
        } else {
            zend_throw_exception(swoole_mysql_coro_exception_ce, "Parameter [user] is required", EINVAL);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "password", ztmp)) {
            mc->password = std::string(zend::String(ztmp).val());
        } else {
            zend_throw_exception(swoole_mysql_coro_exception_ce, "Parameter [password] is required", EINVAL);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "database", ztmp)) {
            mc->database = std::string(zend::String(ztmp).val());
        } else {
            zend_throw_exception(swoole_mysql_coro_exception_ce, "Parameter [database] is required", EINVAL);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "timeout", ztmp)) {
            mc->connect_timeout = zval_get_double(ztmp);
        }
        if (php_swoole_array_get_value(ht, "charset", ztmp)) {
            zend::String zstr_charset(ztmp);
            char charset = mysql::get_charset(zstr_charset.val());
            if (UNEXPECTED(charset < 0)) {
                zend_throw_exception_ex(
                    swoole_mysql_coro_exception_ce, EINVAL, "Unknown charset [%s]", zstr_charset.val());
                RETURN_FALSE;
            }
            mc->charset = charset;
        }
        if (php_swoole_array_get_value(ht, "strict_type", ztmp)) {
            mc->strict_type = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(ht, "fetch_mode", ztmp)) {
            if (UNEXPECTED(!mc->set_fetch_mode(zval_is_true(ztmp)))) {
                zend_throw_exception_ex(
                    swoole_mysql_coro_exception_ce, mc->get_error_code(), "%s", mc->get_error_msg());
                RETURN_FALSE;
            }
        }
    }
    if (!mc->connect()) {
        zend_update_property_long(
            swoole_mysql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connect_errno"), mc->get_error_code());
        zend_update_property_string(
            swoole_mysql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connect_error"), mc->get_error_msg());
        RETURN_FALSE;
    }
    if (zserver_info && php_swoole_array_length(zserver_info) > 0) {
        php_array_merge(Z_ARRVAL_P(sw_zend_read_and_convert_property_array(
                            swoole_mysql_coro_ce, ZEND_THIS, ZEND_STRL("serverInfo"), 0)),
                        Z_ARRVAL_P(zserver_info));
    }
    zend_update_property_long(swoole_mysql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("sock"), mc->get_fd());
    zend_update_property_bool(swoole_mysql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connected"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql_coro, getDefer) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    RETURN_BOOL(mc->get_defer());
}

static PHP_METHOD(swoole_mysql_coro, setDefer) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    zend_bool defer = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(defer)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    bool ret = mc->set_defer(defer);
    if (UNEXPECTED(!ret)) {
        zend_throw_exception_ex(swoole_mysql_coro_exception_ce, mc->get_error_code(), "%s", mc->get_error_msg());
    }
    RETURN_BOOL(ret);
}

static PHP_METHOD(swoole_mysql_coro, query) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    char *sql;
    size_t sql_length;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(sql, sql_length)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    mc->query(return_value, sql, sql_length);
    mc->del_timeout_controller();
    swoole_mysql_coro_sync_query_result_properties(ZEND_THIS, mc, return_value);
}

static PHP_METHOD(swoole_mysql_coro, fetch) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    mc->fetch(return_value);
    mc->del_timeout_controller();
    if (sw_unlikely(Z_TYPE_P(return_value) == IS_FALSE)) {
        swoole_mysql_coro_sync_error_properties(
            ZEND_THIS, mc->get_error_code(), mc->get_error_msg(), mc->is_connected());
    }
}

static PHP_METHOD(swoole_mysql_coro, fetchAll) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    mc->fetch_all(return_value);
    mc->del_timeout_controller();
    if (sw_unlikely(Z_TYPE_P(return_value) == IS_FALSE)) {
        swoole_mysql_coro_sync_error_properties(
            ZEND_THIS, mc->get_error_code(), mc->get_error_msg(), mc->is_connected());
    }
}

static PHP_METHOD(swoole_mysql_coro, nextResult) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    mc->next_result(return_value);
    mc->del_timeout_controller();
    swoole_mysql_coro_sync_query_result_properties(ZEND_THIS, mc, return_value);
    if (Z_TYPE_P(return_value) == IS_TRUE) {
        if (mc->state == SW_MYSQL_STATE_IDLE) {
            // the end of procedure
            Z_TYPE_INFO_P(return_value) = mc->get_fetch_mode() ? IS_FALSE : IS_NULL;
        }
    }
}

static PHP_METHOD(swoole_mysql_coro, prepare) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    char *statement;
    size_t statement_length;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(statement, statement_length)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    if (UNEXPECTED(!mc->send_prepare_request(statement, statement_length))) {
    _failed:
        swoole_mysql_coro_sync_error_properties(
            ZEND_THIS, mc->get_error_code(), mc->get_error_msg(), mc->is_connected());
        RETVAL_FALSE;
    } else if (UNEXPECTED(mc->get_defer())) {
        RETVAL_TRUE;
    } else {
        mysql_statement *statement = mc->recv_prepare_response();
        if (UNEXPECTED(!statement)) {
            goto _failed;
        }
        RETVAL_OBJ(php_swoole_mysql_coro_statement_create_object(statement, Z_OBJ_P(ZEND_THIS)));
    }
    mc->del_timeout_controller();
}

static PHP_METHOD(swoole_mysql_coro, recv) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(!mc->check_connection())) {
        swoole_mysql_coro_sync_error_properties(ZEND_THIS, mc->get_error_code(), mc->get_error_msg(), false);
        RETURN_FALSE;
    }
    mc->add_timeout_controller(timeout, Socket::TIMEOUT_READ);
    switch (mc->state) {
    case SW_MYSQL_STATE_IDLE:
        swoole_mysql_coro_sync_error_properties(ZEND_THIS, ENOMSG, "no message to receive");
        RETVAL_FALSE;
        break;
    case SW_MYSQL_STATE_QUERY:
        mc->recv_query_response(return_value);
        break;
    case SW_MYSQL_STATE_PREPARE: {
        mysql_statement *statement = mc->recv_prepare_response();
        if (UNEXPECTED(!statement)) {
            RETVAL_FALSE;
        } else {
            RETVAL_OBJ(php_swoole_mysql_coro_statement_create_object(statement, Z_OBJ_P(ZEND_THIS)));
        }
        break;
    }
    default:
        if (UNEXPECTED(mc->state & SW_MYSQL_COMMAND_FLAG_EXECUTE)) {
            swoole_mysql_coro_sync_error_properties(ZEND_THIS, EPERM, "please use statement to receive data");
        } else {
            swoole_mysql_coro_sync_error_properties(
                ZEND_THIS, EPERM, "please use fetch/fetchAll/nextResult to get result");
        }
        RETVAL_FALSE;
    }
    mc->del_timeout_controller();
}

static void swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAMETERS,
                                                const char *command,
                                                size_t command_length) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(mc->get_defer())) {
        zend_throw_exception_ex(
            swoole_mysql_coro_exception_ce,
            EPERM,
            "you should not query transaction when defer mode is on, if you want, please use `query('%s')` instead",
            command);
        RETURN_FALSE;
    }

    mc->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    mc->query(return_value, command, command_length);
    mc->del_timeout_controller();
    swoole_mysql_coro_sync_query_result_properties(ZEND_THIS, mc, return_value);
}

static PHP_METHOD(swoole_mysql_coro, begin) {
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("BEGIN"));
}

static PHP_METHOD(swoole_mysql_coro, commit) {
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("COMMIT"));
}

static PHP_METHOD(swoole_mysql_coro, rollback) {
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ROLLBACK"));
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    char *str;
    size_t str_length;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(str, str_length)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    char *newstr = (char *) safe_emalloc(2, str_length + 1, 1);
    const MYSQLND_CHARSET *cset = mysqlnd_find_charset_nr(mc->charset);
    if (!cset) {
        php_swoole_fatal_error(E_ERROR, "unknown mysql charset[%d]", mc->charset);
        RETURN_FALSE;
    }
    zend_ulong newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str, str_length);
    if (newstr_len == (zend_ulong) ~0) {
        php_swoole_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed");
        RETURN_FALSE;
    }
    RETVAL_STRINGL(newstr, newstr_len);
    efree(newstr);
    return;
}
#endif

static PHP_METHOD(swoole_mysql_coro, close) {
    mysql_client *mc = php_swoole_get_mysql_client(ZEND_THIS);
    mc->close();
    zend_update_property_bool(swoole_mysql_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connected"), 0);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql_coro_statement, execute) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    zval *params = nullptr;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY_EX(params, 1, 0)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ms->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    ms->execute(return_value, params);
    ms->del_timeout_controller();
    swoole_mysql_coro_sync_execute_result_properties(ZEND_THIS, return_value);
}

static PHP_METHOD(swoole_mysql_coro_statement, fetch) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ms->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    ms->fetch(return_value);
    ms->del_timeout_controller();
    if (sw_unlikely(Z_TYPE_P(return_value) == IS_FALSE)) {
        swoole_mysql_coro_sync_execute_error_properties(ZEND_THIS, ms->get_error_code(), ms->get_error_msg());
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, fetchAll) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ms->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    ms->fetch_all(return_value);
    ms->del_timeout_controller();
    if (sw_unlikely(Z_TYPE_P(return_value) == IS_FALSE)) {
        swoole_mysql_coro_sync_execute_error_properties(ZEND_THIS, ms->get_error_code(), ms->get_error_msg());
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, nextResult) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ms->add_timeout_controller(timeout, Socket::TIMEOUT_RDWR);
    ms->next_result(return_value);
    ms->del_timeout_controller();
    swoole_mysql_coro_sync_execute_result_properties(ZEND_THIS, return_value);
    if (Z_TYPE_P(return_value) == IS_TRUE) {
        mysql_client *mc = ms->get_client();
        if (mc->state == SW_MYSQL_STATE_IDLE) {
            // the end of procedure
            Z_TYPE_INFO_P(return_value) = mc->get_fetch_mode() ? IS_FALSE : IS_NULL;
        }
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, recv) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    double timeout = 0;
    enum sw_mysql_state state;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(!ms->is_available())) {
        swoole_mysql_coro_sync_execute_error_properties(ZEND_THIS, ms->get_error_code(), ms->get_error_msg(), false);
        RETURN_FALSE;
    }
    ms->add_timeout_controller(timeout, Socket::TIMEOUT_READ);
    switch ((state = ms->get_client()->state)) {
    case SW_MYSQL_STATE_IDLE:
        swoole_mysql_coro_sync_execute_error_properties(ZEND_THIS, ENOMSG, "no message to receive");
        RETVAL_FALSE;
        break;
    case SW_MYSQL_STATE_EXECUTE:
        ms->recv_execute_response(return_value);
        break;
    default:
        if (UNEXPECTED(state & SW_MYSQL_COMMAND_FLAG_QUERY)) {
            swoole_mysql_coro_sync_execute_error_properties(ZEND_THIS, EPERM, "please use client to receive data");
        } else {
            swoole_mysql_coro_sync_execute_error_properties(
                ZEND_THIS, EPERM, "please use fetch/fetchAll/nextResult to get result");
        }
        RETVAL_FALSE;
    }
    ms->del_timeout_controller();
}

static PHP_METHOD(swoole_mysql_coro_statement, close) {
    mysql_statement *ms = php_swoole_get_mysql_statement(ZEND_THIS);
    ms->close();
    RETURN_TRUE;
}
