#pragma once

#include "php_swoole.h"
#include "swoole_cxx.h"
#include "swoole_coroutine.h"

#define SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(module) \
    module##_ce->create_object = [](zend_class_entry *ce) { return sw_zend_create_object(ce, &module##_handlers); }

SW_API bool php_swoole_export_socket(zval *object, int fd, enum swSocket_type type);
SW_API zend_object* php_swoole_export_socket_ex(int fd, enum swSocket_type type);
SW_API void php_swoole_init_socket_object(zval *zobject, swoole::coroutine::Socket *socket);
SW_API swoole::coroutine::Socket* php_swoole_get_socket(zval *zobject);
SW_API void php_swoole_client_set(swoole::coroutine::Socket *cli, zval *zset);

namespace zend
{
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
        return likely(len() > 0) ? sw_strndup(val(), len()) : nullptr;
    }

    char* edup()
    {
        return likely(len() > 0) ? estrndup(val(), len()) : nullptr;
    }

    ~string()
    {
        if (str)
        {
            zend_string_release(str);
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

namespace array
{
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
}

namespace function
{
    inline bool call(zend_fcall_info_cache *fci_cache, uint32_t argc, zval *argv, zval *retval, bool enable_coroutine)
    {
        if (enable_coroutine)
        {
            if (retval)
            {
                ZVAL_NULL(retval);
            }
            return swoole::PHPCoroutine::create(fci_cache, argc, argv) >= 0;
        }
        else
        {
            return sw_call_user_function_fast_ex(NULL, fci_cache, argc, argv, retval) == SUCCESS;
        }
    }
}
}
