#pragma once

#include "php_swoole.h"
#include "swoole_coroutine.h"

SW_API bool php_swoole_export_socket(zval *object, int fd, enum swSocket_type type);
SW_API zend_object* php_swoole_export_socket_ex(int fd, enum swSocket_type type);
SW_API void php_swoole_client_set(swoole::Socket *cli, zval *zset);

namespace zend
{
class string
{
public:
    static char* dup(zval *v)
    {
        string str(v);
        return sw_strndup(str.val(), str.len());
    }

    static char* edup(zval *v)
    {
        string str(v);
        return estrndup(str.val(), str.len());
    }

    string()
    {
        str = nullptr;
    }

    string(zval *v)
    {
        str = zval_get_string(v);
    }

    string(zend_string *v)
    {
        str = zend_string_copy(v);
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

    std::string toStdString()
    {
        return std::string(val(), len());
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
}
