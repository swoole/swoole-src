#pragma once

#include "php_swoole.h"

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
        return str->val;
    }

    inline size_t len()
    {
        return str->len;
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

inline char* string_dup(zval *v)
{
    zend::string str(v);
    return sw_strndup(str.val(), str.len());
}

class string_ptr
{
public:
    string_ptr(zend_string *_str)
    {
        str = _str;
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
    zend_string *str;
};
}

