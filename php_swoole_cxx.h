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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "php_swoole.h"
#include "swoole_cxx.h"
#include "swoole_coroutine.h"
#include "swoole_api.h"

#include <string>

#define SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(module) \
    module##_ce->create_object = [](zend_class_entry *ce) { return sw_zend_create_object(ce, &module##_handlers); }

SW_API bool php_swoole_export_socket(zval *zobject, swoole::coroutine::Socket *_socket);
SW_API zend_object* php_swoole_dup_socket(int fd, enum swSocket_type type);
SW_API void php_swoole_init_socket_object(zval *zobject, swoole::coroutine::Socket *socket);
SW_API swoole::coroutine::Socket* php_swoole_get_socket(zval *zobject);
#ifdef SW_USE_OPENSSL
SW_API bool php_swoole_socket_set_ssl(swoole::coroutine::Socket *sock, zval *zset);
#endif
SW_API bool php_swoole_socket_set_protocol(swoole::coroutine::Socket *sock, zval *zset);

SW_API bool php_swoole_client_set(swoole::coroutine::Socket *cli, zval *zset);

php_stream *php_swoole_create_stream_from_socket(php_socket_t _fd, int domain, int type, int protocol STREAMS_DC);

// timer
SW_API bool php_swoole_timer_clear(swTimer_node *tnode);
SW_API bool php_swoole_timer_clear_all();

namespace zend {
//-----------------------------------namespace begin--------------------------------------------
class string
{
public:
    string()
    {
        str = nullptr;
    }

    string(zval *v)
    {
        str = zval_get_string(v);
    }

    string(zend_string *&v)
    {
        str = zend_string_copy(v);
    }

    string(zend_string *&&v)
    {
        str = v;
    }

    void operator =(zval* v)
    {
        if (str)
        {
            zend_string_release(str);
        }
        str = zval_get_string(v);
    }

    inline char* val()
    {
        return ZSTR_VAL(str);
    }

    inline size_t len()
    {
        return ZSTR_LEN(str);
    }

    zend_string* get()
    {
        return str;
    }

    std::string to_std_string()
    {
        return std::string(val(), len());
    }

    char* dup()
    {
        return sw_likely(len() > 0) ? sw_strndup(val(), len()) : nullptr;
    }

    char* edup()
    {
        return sw_likely(len() > 0) ? estrndup(val(), len()) : nullptr;
    }

    ~string()
    {
        if (str)
        {
            zend_string_release(str);
            str = nullptr;
        }
    }

private:
    zend_string *str;
};

class string_ptr
{
public:
    string_ptr(zend_string *str) :
            str(str)
    {
    }
    string_ptr(string_ptr &&o)
    {
        str = o.str;
        o.str = nullptr;
    }
    ~string_ptr()
    {
        if (str)
        {
            zend_string_release(str);
        }
    }
private:
    zend_string *str;
};

class key_value
{
public:
    zend_ulong index;
    zend_string *key;
    zval zvalue;

    key_value(zend_ulong _index, zend_string *_key, zval *_zvalue)
    {
        index = _index;
        key = _key ? zend_string_copy(_key) : nullptr;
        ZVAL_DEREF(_zvalue);
        zvalue = *_zvalue;
        Z_TRY_ADDREF(zvalue);
    }

    inline void add_to(zval *zarray)
    {
        HashTable *ht = Z_ARRVAL_P(zarray);
        zval *dest_elem = !key ? zend_hash_index_update(ht, index, &zvalue) : zend_hash_update(ht, key, &zvalue);
        Z_TRY_ADDREF_P(dest_elem);
    }

    ~key_value()
    {
        if (key)
        {
            zend_string_release(key);
        }
        zval_ptr_dtor(&zvalue);
    }
};

class ArrayIterator
{
public:
    ArrayIterator(Bucket *p)
    {
        _ptr = p;
        _key = _ptr->key;
        _val = &_ptr->val;
        _index = _ptr->h;
        pe = p;
    }
    ArrayIterator(Bucket *p, Bucket *_pe)
    {
        _ptr = p;
        _key = _ptr->key;
        _val = &_ptr->val;
        _index = _ptr->h;
        pe = _pe;
        skipUndefBucket();
    }
    void operator ++(int i)
    {
        ++_ptr;
        skipUndefBucket();
    }
    bool operator !=(ArrayIterator b)
    {
        return b.ptr() != _ptr;
    }
    std::string key()
    {
        return std::string(_key->val, _key->len);
    }
    zend_ulong index()
    {
        return _index;
    }
    zval* value()
    {
        return _val;
    }
    Bucket *ptr()
    {
        return _ptr;
    }
private:
    void skipUndefBucket()
    {
        while (_ptr != pe)
        {
            _val = &_ptr->val;
            if (_val && Z_TYPE_P(_val) == IS_INDIRECT)
            {
                _val = Z_INDIRECT_P(_val);
            }
            if (UNEXPECTED(Z_TYPE_P(_val) == IS_UNDEF))
            {
                ++_ptr;
                continue;
            }
            if (_ptr->key)
            {
                _key = _ptr->key;
                _index = 0;
            }
            else
            {
                _index = _ptr->h;
                _key = NULL;
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

class Array
{
public:
    zval *arr;

    Array(zval *_arr)
    {
        assert(Z_TYPE_P(_arr) == IS_ARRAY);
        arr = _arr;
    }

    inline size_t count()
    {
        return zend_hash_num_elements(Z_ARRVAL_P(arr));
    }

    inline bool set(zend_ulong index, zval *value)
    {
        return add_index_zval(arr, index, value) == SUCCESS;
    }

    inline bool append(zval *value)
    {
        return add_next_index_zval(arr, value) == SUCCESS;
    }

    inline bool set(zend_ulong index, zend_resource *res)
    {
        zval tmp;
        ZVAL_RES(&tmp, res);
        return set(index, &tmp);
    }

    ArrayIterator begin()
    {
        return ArrayIterator(Z_ARRVAL_P(arr)->arData, Z_ARRVAL_P(arr)->arData + Z_ARRVAL_P(arr)->nNumUsed);
    }

    ArrayIterator end()
    {
        return ArrayIterator(Z_ARRVAL_P(arr)->arData + Z_ARRVAL_P(arr)->nNumUsed);
    }
};

enum process_pipe_type
{
    PIPE_TYPE_NONE = 0,
    PIPE_TYPE_STREAM = 1,
    PIPE_TYPE_DGRAM = 2,
};

class process
{
public:
    zend_object *zsocket = nullptr;
    enum process_pipe_type pipe_type;
    bool enable_coroutine;

    process(enum process_pipe_type pipe_type, bool enable_coroutine) :
        pipe_type(pipe_type), enable_coroutine(enable_coroutine) { }

    ~process()
    {
        if (zsocket)
        {
            OBJ_RELEASE(zsocket);
        }
    }

};

namespace function
{
    /* must use this API to call event callbacks to ensure that exceptions are handled correctly */
    inline bool call(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *retval, const bool enable_coroutine)
    {
        bool success;
        if (enable_coroutine)
        {
            if (retval)
            {
                /* the coroutine has no return value */
                ZVAL_NULL(retval);
            }
            success = swoole::PHPCoroutine::create(fci_cache, argc, argv) >= 0;
        }
        else
        {
            success = sw_zend_call_function_ex(NULL, fci_cache, argc, argv, retval) == SUCCESS;
        }
        /* we have no chance to return to ZendVM to check the exception  */
        if (UNEXPECTED(EG(exception)))
        {
            zend_exception_error(EG(exception), E_ERROR);
        }
        return success;
    }
}

bool include(std::string file);
bool eval(std::string code, std::string filename = "");

#if PHP_VERSION_ID < 80000
#define ZEND_STR_CONST
#else
#define ZEND_STR_CONST const
#endif

zend_op_array* swoole_compile_string(zval *source_string, ZEND_STR_CONST char *filename);
//-----------------------------------namespace end--------------------------------------------
}
