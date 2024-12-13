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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "php_swoole_private.h"
#include "php_swoole_coroutine.h"
#include "swoole_util.h"

#include <string>

// clang-format off
//----------------------------------Swoole known string------------------------------------

#define SW_ZEND_KNOWN_STRINGS(_) \
    _(SW_ZEND_STR_TYPE,                     "type") \
    _(SW_ZEND_STR_HOST,                     "host") \
    _(SW_ZEND_STR_USER_AGENT,               "user-agent") \
    _(SW_ZEND_STR_ACCEPT,                   "accept") \
    _(SW_ZEND_STR_CONTENT_TYPE,             "content-type") \
    _(SW_ZEND_STR_CONTENT_LENGTH,           "content-length") \
    _(SW_ZEND_STR_AUTHORIZATION,            "authorization") \
    _(SW_ZEND_STR_CONNECTION,               "connection") \
    _(SW_ZEND_STR_ACCEPT_ENCODING,          "accept-encoding") \
    _(SW_ZEND_STR_PORT,                     "port") \
    _(SW_ZEND_STR_SETTING,                  "setting") \
    _(SW_ZEND_STR_ID,                       "id") \
    _(SW_ZEND_STR_FD,                       "fd") \
    _(SW_ZEND_STR_SOCK,                     "sock") \
    _(SW_ZEND_STR_PIPE,                     "pipe") \
    _(SW_ZEND_STR_HEADERS,                  "headers") \
    _(SW_ZEND_STR_REQUEST_METHOD,           "requestMethod") \
    _(SW_ZEND_STR_REQUEST_HEADERS,          "requestHeaders") \
    _(SW_ZEND_STR_REQUEST_BODY,             "requestBody") \
    _(SW_ZEND_STR_UPLOAD_FILES,             "uploadFiles") \
    _(SW_ZEND_STR_COOKIES,                  "cookies") \
    _(SW_ZEND_STR_DOWNLOAD_FILE,            "downloadFile") \
    _(SW_ZEND_STR_DOWNLOAD_OFFSET,          "downloadOffset") \
    _(SW_ZEND_STR_SERVER,                   "server") \
    _(SW_ZEND_STR_HEADER,                   "header") \
    _(SW_ZEND_STR_GET,                      "get") \
    _(SW_ZEND_STR_POST,                     "post") \
    _(SW_ZEND_STR_FILES,                    "files") \
    _(SW_ZEND_STR_TMPFILES,                 "tmpfiles") \
    _(SW_ZEND_STR_COOKIE,                   "cookie") \
    _(SW_ZEND_STR_METHOD,                   "method") \
    _(SW_ZEND_STR_PATH,                     "path") \
    _(SW_ZEND_STR_DATA,                     "data") \
    _(SW_ZEND_STR_PIPELINE,                 "pipeline") \
    _(SW_ZEND_STR_USE_PIPELINE_READ,        "usePipelineRead") \
    _(SW_ZEND_STR_TRAILER,                  "trailer") \
    _(SW_ZEND_STR_MASTER_PID,               "master_pid") \
    _(SW_ZEND_STR_CALLBACK,                 "callback") \
    _(SW_ZEND_STR_OPCODE,                   "opcode") \
    _(SW_ZEND_STR_CODE,                     "code") \
    _(SW_ZEND_STR_REASON,                   "reason") \
    _(SW_ZEND_STR_FLAGS,                    "flags") \
    _(SW_ZEND_STR_FINISH,                   "finish") \
    _(SW_ZEND_STR_IN_COROUTINE,             "in_coroutine") \
    _(SW_ZEND_STR_PRIVATE_DATA,             "private_data") \
    _(SW_ZEND_STR_CLASS_NAME_RESOLVER,      "Swoole\\NameResolver") \
    _(SW_ZEND_STR_SOCKET,                   "socket") \
    _(SW_ZEND_STR_ADDR_LOOPBACK_V4,         "127.0.0.1") \
    _(SW_ZEND_STR_ADDR_LOOPBACK_V6,         "::1")  \
    _(SW_ZEND_STR_REQUEST_METHOD2,          "request_method")  \
    _(SW_ZEND_STR_REQUEST_URI,              "request_uri")  \
    _(SW_ZEND_STR_PATH_INFO,                "path_info")  \
    _(SW_ZEND_STR_REQUEST_TIME,             "request_time")  \
    _(SW_ZEND_STR_REQUEST_TIME_FLOAT,       "request_time_float")  \
    _(SW_ZEND_STR_SERVER_PROTOCOL,          "server_protocol")  \
    _(SW_ZEND_STR_SERVER_PORT,              "server_port")  \
    _(SW_ZEND_STR_REMOTE_PORT,              "remote_port")  \
    _(SW_ZEND_STR_REMOTE_ADDR,              "remote_addr")  \
    _(SW_ZEND_STR_MASTER_TIME,              "master_time") \
    _(SW_ZEND_STR_QUERY_STRING,             "query_string") \
    _(SW_ZEND_STR_HTTP10,                   "HTTP/1.0") \
    _(SW_ZEND_STR_HTTP11,                   "HTTP/1.1") \

typedef enum sw_zend_known_string_id {
#define _SW_ZEND_STR_ID(id, str) id,
SW_ZEND_KNOWN_STRINGS(_SW_ZEND_STR_ID)
#undef _SW_ZEND_STR_ID
    SW_ZEND_STR_LAST_KNOWN
} sw_zend_known_string_id;

// clang-format on

#define SW_ZSTR_KNOWN(idx) sw_zend_known_strings[idx]
extern zend_string **sw_zend_known_strings;

//----------------------------------Swoole known string------------------------------------

#define SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(module)                                                              \
    module##_ce->create_object = [](zend_class_entry *ce) { return sw_zend_create_object(ce, &module##_handlers); }

/**
 * It is safe across coroutines,
 * add reference count, prevent the socket pointer being released
 */
#define SW_CLIENT_GET_SOCKET_SAFE(__sock, __zsocket)                                                                   \
    Socket *__sock = nullptr;                                                                                          \
    zend::Variable tmp_socket;                                                                                         \
    if (ZVAL_IS_OBJECT(__zsocket)) {                                                                                   \
        __sock = php_swoole_get_socket(__zsocket);                                                                     \
        tmp_socket.assign(__zsocket);                                                                                  \
    }

#define SW_CLIENT_PRESERVE_SOCKET(__zsocket)                                                                           \
    zend::Variable tmp_socket;                                                                                         \
    if (ZVAL_IS_OBJECT(__zsocket)) {                                                                                   \
        tmp_socket.assign(__zsocket);                                                                                  \
    }

SW_API bool php_swoole_is_enable_coroutine();
SW_API zend_object *php_swoole_create_socket(enum swSocketType type);
SW_API zend_object *php_swoole_create_socket_from_fd(int fd, enum swSocketType type);
SW_API zend_object *php_swoole_create_socket_from_fd(int fd, int _domain, int _type, int _protocol);
SW_API bool php_swoole_export_socket(zval *zobject, swoole::coroutine::Socket *_socket);
SW_API zend_object *php_swoole_dup_socket(int fd, enum swSocketType type);
SW_API void php_swoole_init_socket_object(zval *zobject, swoole::coroutine::Socket *socket);
SW_API swoole::coroutine::Socket *php_swoole_get_socket(zval *zobject);
SW_API bool php_swoole_socket_is_closed(zval *zobject);
#ifdef SW_USE_OPENSSL
SW_API bool php_swoole_socket_set_ssl(swoole::coroutine::Socket *sock, zval *zset);
#endif
SW_API bool php_swoole_socket_set_protocol(swoole::coroutine::Socket *sock, zval *zset);
SW_API bool php_swoole_socket_set(swoole::coroutine::Socket *cli, zval *zset);
SW_API void php_swoole_socket_set_error_properties(zval *zobject, int code);
SW_API void php_swoole_socket_set_error_properties(zval *zobject, int code, const char *msg);
SW_API void php_swoole_socket_set_error_properties(zval *zobject, swoole::coroutine::Socket *socket);
#define php_swoole_client_set php_swoole_socket_set
SW_API php_stream *php_swoole_create_stream_from_socket(php_socket_t _fd,
                                                        int domain,
                                                        int type,
                                                        int protocol STREAMS_DC);
SW_API php_stream *php_swoole_create_stream_from_pipe(int fd, const char *mode, const char *persistent_id STREAMS_DC);
SW_API php_stream_ops *php_swoole_get_ori_php_stream_stdio_ops();
SW_API void php_swoole_register_rshutdown_callback(swoole::Callback cb, void *private_data);
SW_API zif_handler php_swoole_get_original_handler(const char *name, size_t len);
SW_API bool php_swoole_call_original_handler(const char *name, size_t len, INTERNAL_FUNCTION_PARAMETERS);

// timer
SW_API bool php_swoole_timer_clear(swoole::TimerNode *tnode);
SW_API bool php_swoole_timer_clear_all();

static inline bool php_swoole_is_fatal_error() {
    return PG(last_error_message) && (PG(last_error_type) & E_FATAL_ERRORS);
}

ssize_t php_swoole_length_func(const swoole::Protocol *, swoole::network::Socket *, swoole::PacketLength *);
SW_API zend_long php_swoole_parse_to_size(zval *zv);

#ifdef SW_HAVE_ZLIB
#define php_swoole_websocket_frame_pack php_swoole_websocket_frame_pack_ex
#define php_swoole_websocket_frame_object_pack php_swoole_websocket_frame_object_pack_ex
#else
#define php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags, mask, allow_compress)                            \
    php_swoole_websocket_frame_pack_ex(buffer, zdata, opcode, flags, mask, 0)
#define php_swoole_websocket_frame_object_pack(buffer, zdata, mask, allow_compress)                                    \
    php_swoole_websocket_frame_object_pack_ex(buffer, zdata, mask, 0)
#endif
int php_swoole_websocket_frame_pack_ex(
    swoole::String *buffer, zval *zdata, zend_long opcode, uint8_t flags, zend_bool mask, zend_bool allow_compress);
int php_swoole_websocket_frame_object_pack_ex(swoole::String *buffer,
                                              zval *zdata,
                                              zend_bool mask,
                                              zend_bool allow_compress);
void php_swoole_websocket_frame_unpack(swoole::String *data, zval *zframe);
void php_swoole_websocket_frame_unpack_ex(swoole::String *data, zval *zframe, uchar allow_uncompress);

#ifdef SW_HAVE_ZLIB
int php_swoole_zlib_decompress(z_stream *stream, swoole::String *buffer, char *body, int length);
#endif

swoole::NameResolver::Context *php_swoole_name_resolver_get_context(zval *zobject);
std::string php_swoole_name_resolver_lookup(const std::string &name,
                                            swoole::NameResolver::Context *ctx,
                                            void *_resolver);
bool php_swoole_name_resolver_add(zval *zresolver);

const swoole::Allocator *sw_php_allocator();
const swoole::Allocator *sw_zend_string_allocator();

#ifdef __APPLE__
#define SOL_TCP IPPROTO_TCP
#define TCP_INFO TCP_CONNECTION_INFO
using tcp_info = tcp_connection_info;
#endif

#ifdef TCP_INFO
std::unordered_map<std::string, uint64_t> sw_socket_parse_tcp_info(tcp_info *info);
#endif

static inline bool php_swoole_async(bool blocking, const std::function<void(void)> &fn) {
    if (!blocking && swoole_coroutine_is_in()) {
        return swoole::coroutine::async(fn);
    } else {
        fn();
        return true;
    }
}

namespace zend {
//-----------------------------------namespace begin--------------------------------------------
class String {
  public:
    String() {
        str = nullptr;
    }

    String(const char *_str, size_t len) {
        str = zend_string_init(_str, len, 0);
    }

    String(const std::string &_str) {
        str = zend_string_init(_str.c_str(), _str.length(), 0);
    }

    String(zval *v) {
        str = zval_get_string(v);
    }

    String(zend_string *v, bool copy) {
        if (copy) {
            str = zend_string_copy(v);
        } else {
            str = v;
        }
    }

    String(const String &o) {
        str = zend_string_copy(o.str);
    }

    String(String &&o) {
        str = o.str;
        o.str = nullptr;
    }

    void operator=(zval *v) {
        release();
        str = zval_get_string(v);
    }

    String &operator=(String &&o) {
        release();
        str = o.str;
        o.str = nullptr;
        return *this;
    }

    String &operator=(const String &o) {
        release();
        str = zend_string_copy(o.str);
        return *this;
    }

    char *val() {
        return ZSTR_VAL(str);
    }

    size_t len() {
        return ZSTR_LEN(str);
    }

    zend_string *get() {
        return str;
    }

    void rtrim() {
        ZSTR_LEN(str) = swoole::rtrim(val(), len());
    }

    const std::string to_std_string() {
        return std::string(val(), len());
    }

    char *dup() {
        return sw_likely(len() > 0) ? sw_strndup(val(), len()) : nullptr;
    }

    char *edup() {
        return sw_likely(len() > 0) ? estrndup(val(), len()) : nullptr;
    }

    void release() {
        if (str) {
            zend_string_release(str);
            str = nullptr;
        }
    }

    ~String() {
        release();
    }

  private:
    zend_string *str;
};

class KeyValue {
  public:
    zend_ulong index;
    zend_string *key;
    zval zvalue;

    KeyValue(zend_ulong _index, zend_string *_key, zval *_zvalue) {
        index = _index;
        key = _key ? zend_string_copy(_key) : nullptr;
        ZVAL_DEREF(_zvalue);
        zvalue = *_zvalue;
        Z_TRY_ADDREF(zvalue);
    }

    void add_to(zval *zarray) {
        HashTable *ht = Z_ARRVAL_P(zarray);
        zval *dest_elem = !key ? zend_hash_index_update(ht, index, &zvalue) : zend_hash_update(ht, key, &zvalue);
        Z_TRY_ADDREF_P(dest_elem);
    }

    ~KeyValue() {
        if (key) {
            zend_string_release(key);
        }
        zval_ptr_dtor(&zvalue);
    }
};

class ArrayIterator {
  public:
    ArrayIterator(Bucket *p) {
        _ptr = p;
        _key = _ptr->key;
        _val = &_ptr->val;
        _index = _ptr->h;
        pe = p;
    }

    ArrayIterator(Bucket *p, Bucket *_pe) {
        _ptr = p;
        _key = _ptr->key;
        _val = &_ptr->val;
        _index = _ptr->h;
        pe = _pe;
        skipUndefBucket();
    }

    void operator++(int i) {
        ++_ptr;
        skipUndefBucket();
    }

    bool operator!=(ArrayIterator b) {
        return b.ptr() != _ptr;
    }

    std::string key() {
        return std::string(_key->val, _key->len);
    }

    zend_ulong index() {
        return _index;
    }

    zval *value() {
        return _val;
    }

    Bucket *ptr() {
        return _ptr;
    }

  private:
    void skipUndefBucket() {
        while (_ptr != pe) {
            _val = &_ptr->val;
            if (_val && Z_TYPE_P(_val) == IS_INDIRECT) {
                _val = Z_INDIRECT_P(_val);
            }
            if (UNEXPECTED(Z_TYPE_P(_val) == IS_UNDEF)) {
                ++_ptr;
                continue;
            }
            if (_ptr->key) {
                _key = _ptr->key;
                _index = 0;
            } else {
                _index = _ptr->h;
                _key = nullptr;
            }
            break;
        }
    }

    zval *_val;
    zend_string *_key;
    Bucket *_ptr;
    Bucket *pe;
    zend_ulong _index;
};

class Array {
  public:
    zval *arr;

    Array(zval *_arr) {
        assert(Z_TYPE_P(_arr) == IS_ARRAY);
        arr = _arr;
    }

    size_t count() {
        return zend_hash_num_elements(Z_ARRVAL_P(arr));
    }

    bool set(zend_ulong index, zval *value) {
        return add_index_zval(arr, index, value) == SUCCESS;
    }

    bool append(zval *value) {
        return add_next_index_zval(arr, value) == SUCCESS;
    }

    bool set(zend_ulong index, zend_resource *res) {
        zval tmp;
        ZVAL_RES(&tmp, res);
        return set(index, &tmp);
    }

    ArrayIterator begin() {
        return ArrayIterator(Z_ARRVAL_P(arr)->arData, Z_ARRVAL_P(arr)->arData + Z_ARRVAL_P(arr)->nNumUsed);
    }

    ArrayIterator end() {
        return ArrayIterator(Z_ARRVAL_P(arr)->arData + Z_ARRVAL_P(arr)->nNumUsed);
    }
};

enum PipeType {
    PIPE_TYPE_NONE = 0,
    PIPE_TYPE_STREAM = 1,
    PIPE_TYPE_DGRAM = 2,
};

class Process {
  public:
    zend_object *zsocket = nullptr;
    enum PipeType pipe_type;
    bool enable_coroutine;

    Process(enum PipeType pipe_type, bool enable_coroutine)
        : pipe_type(pipe_type), enable_coroutine(enable_coroutine) {}

    ~Process() {
        if (zsocket) {
            OBJ_RELEASE(zsocket);
        }
    }
};

class Variable {
  public:
    zval value;

    Variable() {
        value = {};
    }

    Variable(zval *zvalue) {
        assign(zvalue);
    }

    Variable(const char *str, size_t l_str) {
        ZVAL_STRINGL(&value, str, l_str);
    }

    Variable(const char *str) {
        ZVAL_STRING(&value, str);
    }

    Variable(const Variable &&src) {
        value = src.value;
        add_ref();
    }

    Variable(Variable &&src) {
        value = src.value;
        src.reset();
    }

    void operator=(zval *zvalue) {
        assign(zvalue);
    }

    void operator=(const Variable &src) {
        value = src.value;
        add_ref();
    }

    void assign(zval *zvalue) {
        value = *zvalue;
        add_ref();
    }

    zval *ptr() {
        return &value;
    }

    void reset() {
        ZVAL_UNDEF(&value);
    }

    void add_ref() {
        Z_TRY_ADDREF_P(&value);
    }

    void del_ref() {
        Z_TRY_DELREF_P(&value);
    }

    ~Variable() {
        zval_ptr_dtor(&value);
    }
};

class CharPtr {
  private:
    char *str_;

  public:
    CharPtr() {
        str_ = nullptr;
    }

    CharPtr(char *str) {
        str_ = estrndup(str, strlen(str));
    }

    CharPtr(char *str, size_t len) {
        str_ = estrndup(str, len);
    }

    void operator=(char *str) {
        assign(str, strlen(str));
    }

    void release() {
        if (str_) {
            efree(str_);
            str_ = nullptr;
        }
    }

    void assign(char *str, size_t len) {
        release();
        str_ = estrndup(str, len);
    }

    void assign_tolower(const char *str, size_t len) {
        release();
        str_ = zend_str_tolower_dup(str, len);
    }

    ~CharPtr() {
        release();
    }

    char *get() {
        return str_;
    }
};

class Callable {
  private:
    zval zfn;
    zend_fcall_info_cache fcc;
    char *fn_name = nullptr;

    Callable() {}

  public:
    Callable(zval *_zfn) {
        ZVAL_UNDEF(&zfn);
        if (!zval_is_true(_zfn)) {
            php_swoole_fatal_error(E_WARNING, "illegal callback function");
            return;
        }
        if (!sw_zend_is_callable_ex(_zfn, nullptr, 0, &fn_name, nullptr, &fcc, nullptr)) {
            php_swoole_fatal_error(E_WARNING, "function '%s' is not callable", fn_name);
            return;
        }
        zfn = *_zfn;
        zval_add_ref(&zfn);
    }

    zend_fcall_info_cache *ptr() {
        return &fcc;
    }

    bool ready() {
        return !ZVAL_IS_UNDEF(&zfn);
    }

    Callable *dup() {
        auto copy = new Callable();
        copy->fcc = fcc;
        copy->zfn = zfn;
        zval_add_ref(&copy->zfn);
        if (fn_name) {
            copy->fn_name = estrdup(fn_name);
        }
        return copy;
    }

    bool call(uint32_t argc, zval *argv, zval *retval) {
        return sw_zend_call_function_ex(&zfn, &fcc, argc, argv, retval) == SUCCESS;
    }

    ~Callable() {
        if (!ZVAL_IS_UNDEF(&zfn)) {
            zval_ptr_dtor(&zfn);
        }
        if (fn_name) {
            efree(fn_name);
        }
    }
};

#define _CONCURRENCY_HASHMAP_LOCK_(code)                                                                               \
    if (locked_) {                                                                                                     \
        code;                                                                                                          \
    } else {                                                                                                           \
        lock_.lock();                                                                                                  \
        code;                                                                                                          \
        lock_.unlock();                                                                                                \
    }

template <typename KeyT, typename ValueT>
class ConcurrencyHashMap {
  private:
    std::unordered_map<KeyT, ValueT> map_;
    std::mutex lock_;
    bool locked_;
    ValueT default_value_;

  public:
    ConcurrencyHashMap(ValueT _default_value) : map_(), lock_() {
        default_value_ = _default_value;
        locked_ = false;
    }

    void set(const KeyT &key, const ValueT &value) {
        _CONCURRENCY_HASHMAP_LOCK_(map_[key] = value);
    }

    ValueT get(const KeyT &key) {
        ValueT value;
        auto fn = [&]() -> ValueT {
            auto iter = map_.find(key);
            if (iter == map_.end()) {
                return default_value_;
            }
            return iter->second;
        };
        _CONCURRENCY_HASHMAP_LOCK_(value = fn());
        return value;
    }

    void del(const KeyT &key) {
        _CONCURRENCY_HASHMAP_LOCK_(map_.erase(key));
    }

    void clear() {
        _CONCURRENCY_HASHMAP_LOCK_(map_.clear());
    }

    void each(const std::function<void(KeyT key, ValueT value)> &cb) {
        std::unique_lock<std::mutex> _lock(lock_);
        locked_ = true;
        for (auto &iter : map_) {
            cb(iter.first, iter.second);
        }
        locked_ = false;
    }
};

namespace function {
/* must use this API to call event callbacks to ensure that exceptions are handled correctly */
bool call(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *retval, const bool enable_coroutine);
Variable call(const std::string &func_name, int argc, zval *argv);

static inline bool call(Callable *cb, uint32_t argc, zval *argv, zval *retval, const bool enable_coroutine) {
    return call(cb->ptr(), argc, argv, retval, enable_coroutine);
}
}  // namespace function

struct Function {
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    bool call(zval *retval, const bool enable_coroutine) {
        return function::call(&fci_cache, fci.param_count, fci.params, retval, enable_coroutine);
    }
};

void known_strings_init(void);
void known_strings_dtor(void);
void unserialize(zval *return_value, const char *buf, size_t buf_len, HashTable *options);
void json_decode(zval *return_value, const char *str, size_t str_len, zend_long options, zend_long zend_long);

static inline zend_string *fetch_zend_string_by_val(void *val) {
    return (zend_string *) ((char *) val - XtOffsetOf(zend_string, val));
}

static inline void assign_zend_string_by_val(zval *zdata, char *addr, size_t length) {
    zend_string *zstr = fetch_zend_string_by_val(addr);
    addr[length] = 0;
    zstr->len = length;
    ZVAL_STR(zdata, zstr);
}

static inline void array_set(zval *arg, const char *key, size_t l_key, zval *zvalue) {
    Z_TRY_ADDREF_P(zvalue);
    add_assoc_zval_ex(arg, key, l_key, zvalue);
}

static inline void array_set(zval *arg, const char *key, size_t l_key, const char *value, size_t l_value) {
    zval ztmp;
    ZVAL_STRINGL(&ztmp, value, l_value);
    add_assoc_zval_ex(arg, key, l_key, &ztmp);
}

static inline void array_add(zval *arg, zval *zvalue) {
    Z_TRY_ADDREF_P(zvalue);
    add_next_index_zval(arg, zvalue);
}

/**
 * return reference
 */
static inline zval *array_get(zval *arg, const char *key, size_t l_key) {
    return zend_hash_str_find(Z_ARRVAL_P(arg), key, l_key);
}

static inline void array_unset(zval *arg, const char *key, size_t l_key) {
    zend_hash_str_del(Z_ARRVAL_P(arg), key, l_key);
}

static inline zend_long object_get_long(zval *obj, zend_string *key) {
    static zval rv;
    zval *property = zend_read_property_ex(Z_OBJCE_P(obj), Z_OBJ_P(obj), key, 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static inline zend_long object_get_long(zval *obj, const char *key, size_t l_key) {
    static zval rv;
    zval *property = zend_read_property(Z_OBJCE_P(obj), Z_OBJ_P(obj), key, l_key, 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static inline zend_long object_get_long(zend_object *obj, const char *key, size_t l_key) {
    static zval rv;
    zval *property = zend_read_property(obj->ce, obj, key, l_key, 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static inline void object_set(zval *obj, const char *name, size_t l_name, zval *zvalue) {
    zend_update_property(Z_OBJCE_P(obj), Z_OBJ_P(obj), name, l_name, zvalue);
}

static inline void object_set(zval *obj, const char *name, size_t l_name, const char *value) {
    zend_update_property_string(Z_OBJCE_P(obj), Z_OBJ_P(obj), name, l_name, value);
}

static inline void object_set(zval *obj, const char *name, size_t l_name, zend_long value) {
    zend_update_property_long(Z_OBJCE_P(obj), Z_OBJ_P(obj), name, l_name, value);
}

static inline zval *object_get(zval *obj, const char *name, size_t l_name) {
    static zval rv;
    return zend_read_property(Z_OBJCE_P(obj), Z_OBJ_P(obj), name, l_name, 1, &rv);
}

/**
 * print exception, The virtual machine will not be terminated.
 */
static inline void print_error(zend_object *exception, int severity) {
    zend_exception_error(exception, severity);
}

//-----------------------------------namespace end--------------------------------------------
}  // namespace zend

/* use void* to match some C callback function pointers */
static inline void sw_callable_free(void *ptr) {
    delete (zend::Callable *) ptr;
}

static inline zend::Callable *sw_callable_create(zval *zfn) {
    auto fn = new zend::Callable(zfn);
    if (fn->ready()) {
        return fn;
    } else {
        delete fn;
        return nullptr;
    }
}

static inline zend::Callable *sw_callable_create_ex(zval *zfn, const char *fname, bool allow_null = true) {
    if (zfn == nullptr || ZVAL_IS_NULL(zfn)) {
        if (!allow_null) {
            zend_throw_exception_ex(
                swoole_exception_ce, SW_ERROR_INVALID_PARAMS, "%s must be of type callable, null given", fname);
        }
        return nullptr;
    }
    auto cb = sw_callable_create(zfn);
    if (!cb) {
        zend_throw_exception_ex(swoole_exception_ce,
                                SW_ERROR_INVALID_PARAMS,
                                "%s must be of type callable, %s given",
                                fname,
                                zend_zval_type_name(zfn));
        return nullptr;
    }
    return cb;
}
