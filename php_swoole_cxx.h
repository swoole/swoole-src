#pragma once

#include "php_swoole.h"

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

