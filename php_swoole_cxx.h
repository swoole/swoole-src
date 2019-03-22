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
}

