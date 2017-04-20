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

extern "C"
{
#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "zend_API.h"
#include "php_streams.h"
#include "php_network.h"

#if PHP_MAJOR_VERSION < 7
#error "only supports PHP7 or later."
#endif

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"
#include "zend_inheritance.h"

#include <ext/date/php_date.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>
#include <ext/standard/php_array.h>
#include "ext/standard/php_var.h"
}

#include <unordered_map>
#include <string>
#include <vector>

#ifdef ECLIPSE_HELPER
#include <map>
#define unordered_map map
#define nullptr_t void*
#endif

#define MAX_ARGC        20
#define VAR_DUMP_LEVEL  10

using namespace std;

namespace PHP
{
struct Resource
{
    const char *name;
    int type;
};
static unordered_map<string, Resource *> resource_map;

class Variant
{
public:
    Variant()
    {
        init();
        ZVAL_NULL(&val);
    }
    Variant(nullptr_t v)
    {
        init();
        ZVAL_NULL(&val);
    }
    Variant(long v)
    {
        init();
        ZVAL_LONG(&val, v);
    }
    Variant(int v)
    {
        init();
        ZVAL_LONG(&val, (long )v);
    }
    Variant(const char *str)
    {
        init();
        ZVAL_STRING(&val, str);
    }
    Variant(const char *str, size_t len)
    {
        init();
        ZVAL_STRINGL(&val, str, len);
    }
    Variant(string &str)
    {
        init();
        ZVAL_STRINGL(&val, str.c_str(), str.length());
    }
    Variant(double v)
    {
        init();
        ZVAL_DOUBLE(&val, v);
    }
    Variant(float v)
    {
        init();
        ZVAL_DOUBLE(&val, (double )v);
    }
    Variant(bool v)
    {
        init();
        ZVAL_BOOL(&val, v);
    }
    Variant(zval *v)
    {
        reference = false;
        ref_val = NULL;
        memcpy(&val, v, sizeof(zval));
        zval_add_ref(&val);
    }
    Variant(zval *v, bool ref)
    {
        ref_val = v;
        reference = ref;
    }
    Variant(zend_resource *res)
    {
        init();
        ZVAL_RES(ptr(), res);
    }
    ~Variant()
    {
        if (!reference)
        {
            zval_ptr_dtor(&val);
        }
    }
    void operator =(int v)
    {
        ZVAL_LONG(ptr(), (long )v);
    }
    void operator =(long v)
    {
        ZVAL_LONG(ptr(), v);
    }
    void operator =(string &str)
    {
        ZVAL_STRINGL(ptr(), str.c_str(), str.length());
    }
    void operator =(const char *str)
    {
        ZVAL_STRING(ptr(), str);
    }
    void operator =(double v)
    {
        ZVAL_DOUBLE(ptr(), v);
    }
    void operator =(float v)
    {
        ZVAL_DOUBLE(ptr(), (double )v);
    }
    void operator =(bool v)
    {
        ZVAL_BOOL(ptr(), v);
    }
    inline zval *ptr(void)
    {
        if (reference)
        {
            return ref_val;
        }
        else
        {
            return &val;
        }
    }
    inline void addRef()
    {
        zval_add_ref(ptr());
    }
    inline int type()
    {
        return Z_TYPE_P(ptr());
    }
    inline bool isString()
    {
        return Z_TYPE_P(ptr()) == IS_STRING;
    }
    inline bool isArray()
    {
        return Z_TYPE_P(ptr()) == IS_ARRAY;
    }
    inline bool isObject()
    {
        return Z_TYPE_P(ptr()) == IS_OBJECT;
    }
    inline bool isInt()
    {
        return Z_TYPE_P(ptr()) == IS_LONG;
    }
    inline bool isFloat()
    {
        return Z_TYPE_P(ptr()) == IS_DOUBLE;
    }
    inline bool isBool()
    {
        return Z_TYPE_P(ptr()) == IS_TRUE || Z_TYPE_P(ptr()) == IS_FALSE;
    }
    inline bool isNull()
    {
        return Z_TYPE_P(ptr()) == IS_NULL;
    }
    inline bool isResource()
    {
        return Z_TYPE_P(ptr()) == IS_RESOURCE;
    }
    inline bool isReference()
    {
        return Z_TYPE_P(ptr()) == IS_REFERENCE;
    }
    inline string toString()
    {
        if (!isString())
        {
            convert_to_string(ptr());
        }
        return string(Z_STRVAL_P(ptr()), Z_STRLEN_P(ptr()));
    }
    inline char* toCString()
    {
        if (!isString())
        {
            convert_to_string(ptr());
        }
        return Z_STRVAL_P(ptr());
    }
    inline long toInt()
    {
        if (!isInt())
        {
            convert_to_long(ptr());
        }
        return Z_LVAL_P(ptr());
    }
    inline double toFloat()
    {
        if (!isFloat())
        {
            convert_to_double(ptr());
        }
        return Z_DVAL_P(ptr());
    }
    inline bool toBool()
    {
        if (!isBool())
        {
            convert_to_boolean(ptr());
        }
        return Z_TYPE_P(ptr()) == IS_TRUE;
    }
    void copy(Variant &v)
    {
        ZVAL_COPY_VALUE(ptr(), v.ptr());
        addRef();
    }
    void copy(char *str, size_t size)
    {
        ZVAL_STRINGL(ptr(), str, size);
    }
    inline int length()
    {
        if (!isString())
        {
            convert_to_string(ptr());
        }
        return Z_STRLEN_P(ptr());
    }
    template<class T>
    T* toResource(const char *name)
    {
        if (!isResource())
        {
            php_error_docref(NULL, E_WARNING, "Variant is not a resource type.");
            return NULL;
        }
        void *_ptr = NULL;
        Resource *_c = resource_map[name];
        if ((_ptr = zend_fetch_resource(Z_RES_P(ptr()), name, _c->type)) == NULL)
        {
            return NULL;
        }
        return static_cast<T *>(_ptr);
    }
protected:
    bool reference;
    zval *ref_val;
    zval val;
    inline void init()
    {
        reference = false;
        ref_val = NULL;
        memset(&val, 0, sizeof(val));
    }
};

class String
{
public:
    String(const char *str)
    {
        value = zend_string_init(str, strlen(str), 0);
    }
    String(const char *str, size_t len)
    {
        value = zend_string_init(str, len, 0);
    }
    String(string &str)
    {
        value = zend_string_init(str.c_str(), str.length(), 0);
    }
    size_t length()
    {
        return value->len;
    }
    char* c_str()
    {
        return value->val;
    }
    ~String()
    {
        zend_string_free(value);
    }
    void extend(size_t new_size)
    {
        value = zend_string_extend(value, new_size, 0);
    }
    void tolower()
    {
        zend_str_tolower(value->val, value->len);
    }
    zend_string* ptr()
    {
        return value;
    }
protected:
    zend_string *value;
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
    }
    void operator ++(int i)
    {
        while (1)
        {
            _ptr++;
            _val = &_ptr->val;
            if (_val && Z_TYPE_P(_val) == IS_INDIRECT)
            {
                _val = Z_INDIRECT_P(_val);
            }
            if (UNEXPECTED(Z_TYPE_P(_val) == IS_UNDEF) && pe != _ptr)
            {
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
    bool operator !=(ArrayIterator b)
    {
        return b.ptr() != _ptr;
    }
    Variant key()
    {
        if (_key)
        {
            return Variant(_key->val, _key->len);
        }
        else
        {
            return Variant((long) _index);
        }
    }
    Variant value()
    {
        return Variant(_val);
    }
    Bucket *ptr()
    {
        return _ptr;
    }
private:
    zval *_val;
    zend_string *_key;
    Bucket *_ptr;
    Bucket *pe;
    zend_ulong _index;
};

class Array: public Variant
{
public:
    Array() :
            Variant()
    {
        array_init(&val);
    }
    Array(zval *v) :
            Variant(v)
    {
        ref_val = v;
        reference = true;
        if (Z_TYPE_P(v) == IS_NULL)
        {
            array_init(v);
        }
        else if (Z_TYPE_P(v) != IS_ARRAY)
        {
            php_error_docref(NULL, E_ERROR, "cpp moudle array construct args must be zend array");
        }
    }
    Array(Variant &v)
    {
        ref_val = v.ptr();
        reference = true;
        if (v.isNull())
        {
            array_init(ref_val);
        }
        else if (!v.isArray())
        {
            php_error_docref(NULL, E_ERROR, "cpp moudle array construct args must be zend array");
        }
    }
    void append(Variant v)
    {
        v.addRef();
        add_next_index_zval(ptr(), v.ptr());
    }
    void append(const char *str)
    {
        add_next_index_string(ptr(), str);
    }
    void append(string &str)
    {
        add_next_index_stringl(ptr(), str.c_str(), str.length());
    }
    void append(long v)
    {
        add_next_index_long(ptr(), v);
    }
    void append(int v)
    {
        add_next_index_long(ptr(), (long) v);
    }
    void append(bool v)
    {
        add_next_index_bool(ptr(), v ? 1 : 0);
    }
    void append(double v)
    {
        add_next_index_double(ptr(), (double) v);
    }
    void append(float v)
    {
        add_next_index_double(ptr(), (double) v);
    }
    void append(zval *v)
    {
        zval_add_ref(v);
        add_next_index_zval(ptr(), v);
    }
    void append(void *v)
    {
        add_next_index_null(ptr());
    }
    void append(Array &v)
    {
        zend_array *arr = zend_array_dup(Z_ARR_P(v.ptr()));
        zval array;
        ZVAL_ARR(&array, arr);
        add_next_index_zval(ptr(), &array);
    }
    //------------------assoc-array------------------
    void set(const char *key, Variant &v)
    {
        add_assoc_zval(ptr(), key, v.ptr());
    }
    void set(const char *key, int v)
    {
        add_assoc_long(ptr(), key, (long) v);
    }
    void set(const char *key, long v)
    {
        add_assoc_long(ptr(), key, v);
    }
    void set(const char *key, const char *v)
    {
        add_assoc_string(ptr(), key, (char * )v);
    }
    void set(const char *key, string &v)
    {
        add_assoc_stringl(ptr(), key, (char* )v.c_str(), v.length());
    }
    void set(const char *key, double v)
    {
        add_assoc_double(ptr(), key, v);
    }
    void set(const char *key, float v)
    {
        add_assoc_double(ptr(), key, (double ) v);
    }
    void set(const char *key, bool v)
    {
        add_assoc_bool(ptr(), key, v ? 1 : 0);
    }
    void set(int i, Variant &v)
    {
        add_index_zval(ptr(), (zend_ulong) i, v.ptr());
    }
    //-------------------------------------------
    Variant operator [](int i)
    {
        zval *ret = zend_hash_index_find(Z_ARRVAL_P(ptr()), (zend_ulong) i);
        if (ret == NULL)
        {
            return Variant(nullptr);
        }
        return Variant(ret);
    }
    Variant operator [](const char *key)
    {
        zval *ret = zend_hash_str_find(Z_ARRVAL_P(ptr()), key, strlen(key));
        if (ret == NULL)
        {
            return Variant(nullptr);
        }
        return Variant(ret);
    }
    bool remove(const char *key)
    {
        String _key(key);
        bool ret = zend_hash_del(Z_ARRVAL_P(ptr()),  _key.ptr()) == SUCCESS;
        return ret;
    }
    void clean()
    {
        zend_hash_clean(Z_ARRVAL_P(ptr()));
    }
    bool exists(const char *key)
    {
        String _key(key);
        bool ret = zend_hash_exists(Z_ARRVAL_P(ptr()), _key.ptr()) == SUCCESS;
        return ret;
    }
    ArrayIterator begin()
    {
        return ArrayIterator(Z_ARRVAL_P(ptr())->arData, Z_ARRVAL_P(ptr())->arData + Z_ARRVAL_P(ptr())->nNumUsed);
    }
    ArrayIterator end()
    {
        return ArrayIterator(Z_ARRVAL_P(ptr())->arData + Z_ARRVAL_P(ptr())->nNumUsed);
    }
    size_t count()
    {
        return Z_ARRVAL_P(ptr())->nNumOfElements;
    }
    bool empty()
    {
        return Z_ARRVAL_P(ptr())->nNumOfElements == 0;
    }
};

class Args
{
public:
    Args()
    {
        argc = 0;
    }
    void append(zval *v)
    {
        assert(argc < MAX_ARGC);
        argv[argc++] = v;
    }
    size_t count()
    {
        return argc;
    }
    bool empty()
    {
        return argc == 0;
    }
    Array toArray()
    {
        Array array;
        for (int i = 0; i < argc; i++)
        {
            array.append(Variant(argv[i]));
        }
        array.addRef();
        return array;
    }
    Variant operator [](int i)
    {
        if (i >= argc)
        {
            return Variant(nullptr);
        }
        return Variant(argv[i], true);
    }
private:
    int argc;
    zval *argv[MAX_ARGC];
};

static inline Variant _call(zval *object, zval *func, Array &args)
{
    Variant retval = false;
    if (args.count() > MAX_ARGC)
    {
        return retval;
    }
    zval params[MAX_ARGC];
    for (int i = 0; i < args.count(); i++)
    {
        ZVAL_COPY_VALUE(&params[i], args[i].ptr());
    }
    zval _retval;
    if (call_user_function(EG(function_table), object, func, &_retval, args.count(), params) == 0)
    {
        retval = Variant(&_retval);
        retval.addRef();
    }
    return retval;
}

static inline Variant _call(zval *object, zval *func)
{
    Variant retval = false;
    zval params[0];
    zval _retval;
    if (call_user_function(EG(function_table), object, func, &_retval, 0, params) == 0)
    {
        retval = Variant(&_retval);
    }
    return retval;
}

Variant call(Variant &func, Array &args)
{
    return _call(NULL, func.ptr(), args);
}

Variant call(const char *func, Array &args)
{
    Variant _func(func);
    return _call(NULL, _func.ptr(), args);
}
/*generator*/
Variant exec(const char *func, Variant v1)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    args.append(v16.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    args.append(v16.ptr());
    args.append(v17.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    args.append(v16.ptr());
    args.append(v17.ptr());
    args.append(v18.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    args.append(v16.ptr());
    args.append(v17.ptr());
    args.append(v18.ptr());
    args.append(v19.ptr());
    return _call(NULL, _func.ptr(), args);
}
Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19, Variant v20)
{
    Variant _func(func);
    Array args;
    args.append(v1.ptr());
    args.append(v2.ptr());
    args.append(v3.ptr());
    args.append(v4.ptr());
    args.append(v5.ptr());
    args.append(v6.ptr());
    args.append(v7.ptr());
    args.append(v8.ptr());
    args.append(v9.ptr());
    args.append(v10.ptr());
    args.append(v11.ptr());
    args.append(v12.ptr());
    args.append(v13.ptr());
    args.append(v14.ptr());
    args.append(v15.ptr());
    args.append(v16.ptr());
    args.append(v17.ptr());
    args.append(v18.ptr());
    args.append(v19.ptr());
    args.append(v20.ptr());
    return _call(NULL, _func.ptr(), args);
}/*generator*/
void var_dump(Variant &v)
{
    php_var_dump(v.ptr(), VAR_DUMP_LEVEL);
}

static inline zend_class_entry *getClassEntry(const char *name)
{
    String class_name(name, strlen(name));
    return zend_lookup_class(class_name.ptr());
}

void throwException(const char *name, const char *message, int code = 0)
{
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' undefined.", name);
        return;
    }
    zend_throw_exception(ce, message, code TSRMLS_CC);
}

Variant getGlobalVariant(const char *name)
{
    zend_string *key = zend_string_init(name, strlen(name), 0);
    zval *var = zend_hash_find_ind(&EG(symbol_table), key);
    if (!var)
    {
        return false;
    }
    return Variant(var, true);
}

class Object: public Variant
{
public:
    Object(Variant &v) :
            Variant()
    {
        memcpy(&val, v.ptr(), sizeof(val));
        zval_add_ref(&val);
    }
    Object(zval *v) :
            Variant(v)
    {
    }
    Object(zval *v, bool ref) :
            Variant(v, ref)
    {

    }
    Object() :
            Variant()
    {

    }
    Variant call(Variant &func, Array &args)
    {
        return _call(ptr(), func.ptr(), args);
    }
    Variant call(const char *func, Array &args)
    {
        Variant _func(func);
        return _call(ptr(), _func.ptr(), args);
    }
    /**
     * call php function with 0 params.
     */
    Variant call(Variant &func)
    {
        return _call(ptr(), func.ptr());
    }
    Variant call(const char *func)
    {
        Variant _func(func);
        return _call(ptr(), _func.ptr());
    }
    /*generator*/
    Variant exec(const char *func, Variant v1)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        args.append(v16.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        args.append(v16.ptr());
        args.append(v17.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        args.append(v16.ptr());
        args.append(v17.ptr());
        args.append(v18.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        args.append(v16.ptr());
        args.append(v17.ptr());
        args.append(v18.ptr());
        args.append(v19.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    Variant exec(const char *func, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19, Variant v20)
    {
        Variant _func(func);
        Array args;
        args.append(v1.ptr());
        args.append(v2.ptr());
        args.append(v3.ptr());
        args.append(v4.ptr());
        args.append(v5.ptr());
        args.append(v6.ptr());
        args.append(v7.ptr());
        args.append(v8.ptr());
        args.append(v9.ptr());
        args.append(v10.ptr());
        args.append(v11.ptr());
        args.append(v12.ptr());
        args.append(v13.ptr());
        args.append(v14.ptr());
        args.append(v15.ptr());
        args.append(v16.ptr());
        args.append(v17.ptr());
        args.append(v18.ptr());
        args.append(v19.ptr());
        args.append(v20.ptr());
        return _call(ptr(), _func.ptr(), args);
    }
    /*generator*/
    Variant get(const char *name)
    {
        Variant retval;
        zval rv;
        zval *member_p = zend_read_property(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), 0, &rv);
        if (member_p != &rv)
        {
            ZVAL_COPY(retval.ptr(), member_p);
        }
        else
        {
            ZVAL_COPY_VALUE(retval.ptr(), member_p);
        }
        retval.addRef();
        return retval;
    }

    void set(const char *name, Variant &v)
    {
        zend_update_property(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.ptr());
    }

    void set(const char *name, Array &v)
    {
        v.addRef();
        zend_update_property(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.ptr());
    }
    void set(const char *name, string &v)
    {
        zend_update_property_stringl(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.c_str(), v.length());
    }
    void set(const char *name, string v)
    {
        zend_update_property_stringl(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.c_str(), v.length());
    }
    void set(const char *name, const char *v)
    {
        zend_update_property_string(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    void set(const char *name, long v)
    {
        zend_update_property_long(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    void set(const char *name, double v)
    {
        zend_update_property_double(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    void set(const char *name, float v)
    {
        zend_update_property_double(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), (double) v);
    }
    void set(const char *name, bool v)
    {
        zend_update_property_bool(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v ? 1 : 0);
    }
    string getClassName()
    {
        return string(Z_OBJCE_P(ptr())->name->val, Z_OBJCE_P(ptr())->name->len);
    }
    uint32_t getId()
    {
        return Z_OBJ_HANDLE(*ptr());
    }
    bool methodExists(const char *name)
    {
        return zend_hash_str_exists(&Z_OBJCE_P(ptr())->function_table, name, strlen(name));
    }
    bool propertyExists(const char *name)
    {
        return zend_hash_str_exists(&Z_OBJCE_P(ptr())->properties_info, name, strlen(name));
    }
};

Object create(const char *name, Array &args)
{
    zend_class_entry *ce = getClassEntry(name);
    Object object;
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    object.call("__construct", args);
    return object;
}

Object create(const char *name)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    return object;
}

#define function(f) #f, f
#define defineMethod(c, m) void c##_##m(Object &_this, Args &args, Variant &retval)
typedef void (*function_t)(Args &, Variant &retval);
typedef void (*resource_dtor)(zend_resource *);
typedef void (*method_t)(Object &, Args &, Variant &retval);
static unordered_map<string, function_t> function_map;
static unordered_map<string, unordered_map<string, method_t> > method_map;

static void _exec_function(zend_execute_data *data, zval *return_value)
{
    const char *name = data->func->common.function_name->val;
    function_t func = function_map[name];
    Args args;

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    while (arg_count-- > 0)
    {
        args.append(param_ptr);
        param_ptr++;
    }
    Variant _retval(return_value, true);
    func(args, _retval);
}

static void _exec_method(zend_execute_data *data, zval *return_value)
{
    const char *method_name = data->func->common.function_name->val;
    const char *class_name = data->func->common.scope->name->val;

    method_t func = method_map[class_name][method_name];
    Args args;

    Object _this(&data->This, true);

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    while (arg_count-- > 0)
    {
        args.append(param_ptr);
        param_ptr++;
    }
    Variant _retval(return_value, true);
    func(_this, args, _retval);
}

typedef struct _zend_internal_arg_info ArgInfo;

bool registerFunction(const char *name, function_t func)
{
    zend_function_entry _functions[] = {
        {name, _exec_function, NULL, 0, 0},
        {NULL, NULL, NULL,}
    };
    if (zend_register_functions(NULL, _functions, NULL, MODULE_PERSISTENT) == SUCCESS)
    {
        function_map[name] = func;
        return true;
    }
    else
    {
        return false;
    }
}

bool registerResource(const char *name, resource_dtor dtor)
{
    Resource *res = new Resource;
    int type = zend_register_list_destructors_ex(dtor, NULL, name, 0);
    if (type < 0)
    {
        return false;
    }
    res->type = type;
    res->name = name;
    resource_map[name] = res;
    return true;
}

void unregisterFunction(string &name)
{
    zend_function_entry _functions[] = {
        {name.c_str(), _exec_function, NULL, 0, 0},
        {NULL, NULL, NULL,}
    };
    zend_unregister_functions(_functions, 1, NULL);
}

void registerConstant(const char *name, long v)
{
    zend_constant c;
    ZVAL_LONG(&c.value, v);
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, int v)
{
    zend_constant c;
    ZVAL_LONG(&c.value, v);
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, bool v)
{
    zend_constant c;
    if (v)
    {
        ZVAL_TRUE(&c.value);
    }
    else
    {
        ZVAL_FALSE(&c.value);
    }
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, double v)
{
    zend_constant c;
    ZVAL_DOUBLE(&c.value, v);
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, float v)
{
    zend_constant c;
    ZVAL_DOUBLE(&c.value, v);
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, const char *v)
{
    zend_constant c;
    ZVAL_STRING(&c.value, (char* )v);
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, string &v)
{
    zend_constant c;
    ZVAL_STRINGL(&c.value, (char * )v.c_str(), v.length());
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
void registerConstant(const char *name, Variant &v)
{
    zend_constant c;
    ZVAL_COPY(&c.value, v.ptr());
    c.flags = CONST_CS;
    c.name = zend_string_init(name, strlen(name), c.flags);
    c.module_number = 0;
    zend_register_constant(&c);
}
Variant constant(const char *name)
{
    zend_string *_name = zend_string_init(name, strlen(name), 0);
    zval *val = zend_get_constant_ex(_name, NULL, ZEND_FETCH_CLASS_SILENT);
    zend_string_free(_name);
    if (val == NULL)
    {
        return nullptr;
    }
    Variant retval(val);
    return retval;
}

enum ClassFlags
{
    STATIC = ZEND_ACC_STATIC,
    ABSTRACT = ZEND_ACC_ABSTRACT,
    FINAL = ZEND_ACC_FINAL,
    INTERFACE = ZEND_ACC_INTERFACE,
    TRAIT = ZEND_ACC_TRAIT,
    PUBLIC = ZEND_ACC_PUBLIC,
    PROTECTED = ZEND_ACC_PROTECTED,
    PRIVATE = ZEND_ACC_PRIVATE,
    CONSTRUCT = ZEND_ACC_CTOR,
    DESTRUCT = ZEND_ACC_DTOR,
    CLONE = ZEND_ACC_CLONE,
};

class Class
{
    struct Method
    {
        string name;
        int flags;
        method_t method;
    };

    struct Property
    {
        string name;
        zval value;
        int flags;
    };

    struct Constant
    {
        string name;
        zval value;
    };

public:
    Class(const char *name)
    {
        class_name = name;
        INIT_CLASS_ENTRY_EX(_ce, name, strlen(name), NULL);
        parent_ce = NULL;
        ce = NULL;
        activated = false;
    }
    bool extends(const char *_parent_class)
    {
        if (activated)
        {
            return false;
        }
        parent_class_name = _parent_class;
        parent_ce = getClassEntry(_parent_class);
        return parent_ce != NULL;
    }
    bool implements(const char *name)
    {
        if (activated)
        {
            return false;
        }
        if (interfaces.find(name) != interfaces.end())
        {
            return false;
        }
        zend_class_entry *interface_ce = getClassEntry(name);
        if (interface_ce == NULL)
        {
            return false;
        }
        printf("name%s\n", name);
        interfaces[name] = interface_ce;
        return true;
    }
    bool addConstant(const char *name, Variant v)
    {
        if (activated)
        {
            return false;
        }
        Constant c;
        c.name = name;
        ZVAL_COPY(&c.value, v.ptr());
        constants.push_back(c);
        return true;
    }
    bool addProperty(const char *name, Variant v, int flags = PUBLIC)
    {
        if (activated)
        {
            return false;
        }
        Property p;
        p.name = name;
        ZVAL_COPY(&p.value, v.ptr());
        p.flags = flags;
        propertys.push_back(p);
        return true;
    }
    bool addMethod(const char *name, method_t method, int flags = PUBLIC)
    {
        if (activated)
        {
            return false;
        }
        if ((flags & CONSTRUCT) || (flags & DESTRUCT) || !(flags & ZEND_ACC_PPP_MASK))
        {
            flags |= PUBLIC;
        }
        Method m;
        m.flags = flags;
        m.method = method;
        m.name = name;
        methods.push_back(m);
        return false;
    }
    bool activate()
    {
        if (activated)
        {
            return false;
        }
        /**
         * register methods
         */
        int n = methods.size();
        zend_function_entry *_methods = (zend_function_entry *) ecalloc(n + 1, sizeof(zend_function_entry));
        for (int i = 0; i < n; i++)
        {
            _methods[i].fname = methods[i].name.c_str();
            _methods[i].handler = _exec_method;
            _methods[i].arg_info = NULL;
            _methods[i].num_args = (uint32_t) (sizeof(void*) / sizeof(struct _zend_internal_arg_info) - 1);
            _methods[i].flags = methods[i].flags;
            method_map[class_name][methods[i].name] = methods[i].method;
        }
        memset(&_methods[n], 0, sizeof(zend_function_entry));
        _ce.info.internal.builtin_functions = _methods;
        if (parent_ce)
        {
            ce = zend_register_internal_class_ex(ce, parent_ce);
        }
        else
        {
            ce = zend_register_internal_class(&_ce TSRMLS_CC);
        }
        efree(_methods);
        if (ce == NULL)
        {
            return false;
        }
        /**
         * implements interface
         */
        for (auto i = interfaces.begin(); i != interfaces.end(); i++)
        {
            zend_do_implement_interface(ce, interfaces[i->first]);
        }
        /**
         * register property
         */
        for (int i = 0; i != propertys.size(); i++)
        {
            Property p = propertys[i];
            zval_add_ref(&p.value);
            zend_declare_property(ce, p.name.c_str(), p.name.length(), &p.value, p.flags);
        }
        /**
         * register constant
         */
        for (int i = 0; i != constants.size(); i++)
        {
            if (Z_TYPE(constants[i].value) == IS_STRING)
            {
                zend_declare_class_constant_stringl(ce, constants[i].name.c_str(), constants[i].name.length(),
                        Z_STRVAL(constants[i].value), Z_STRLEN(constants[i].value));
            }
            else
            {
                zend_declare_class_constant(ce, constants[i].name.c_str(), constants[i].name.length(),
                        &constants[i].value);
            }
        }
        activated = true;
        return true;
    }
    bool deactivate()
    {
        if (!activated)
        {
            return false;
        }
        zend_string *lowercase_name = zend_string_alloc(class_name.length(), 1);
        zend_str_tolower_copy(ZSTR_VAL(lowercase_name), class_name.c_str(), class_name.length());
        lowercase_name = zend_new_interned_string(lowercase_name);
        zend_hash_del(CG(class_table), lowercase_name);
        zend_string_release(lowercase_name);
        activated = false;
        return true;
    }
    bool alias(const char *alias_name)
    {
        if (!activated)
        {
            php_error_docref(NULL, E_WARNING, "Please execute alias method after activate.");
            return false;
        }
        if (zend_register_class_alias_ex(alias_name, strlen(alias_name), ce) < 0)
        {
            return false;
        }
        return true;
    }
    string getName()
    {
        return class_name;
    }
    Variant getStaticProperty(string p_name)
    {
        if (!activated)
        {
            return nullptr;
        }
        return Variant(zend_read_static_property(ce, p_name.c_str(), p_name.length(), 1));
    }
    bool setStaticProperty(string p_name, Variant value)
    {
        if (!activated)
        {
            return false;
        }
        value.addRef();
        return zend_update_static_property(ce, p_name.c_str(), p_name.length(), value.ptr()) == SUCCESS;
    }
    static Variant get(const char *name, string p_name)
    {
        zend_class_entry *_tmp_ce = getClassEntry(name);
        if (!_tmp_ce)
        {
            return nullptr;
        }
        return Variant(zend_read_static_property(_tmp_ce, p_name.c_str(), p_name.length(), 1));
    }
    static bool set(const char *name, string p_name, Variant value)
    {
        zend_class_entry *_tmp_ce = getClassEntry(name);
        if (!_tmp_ce)
        {
            return false;
        }
        value.addRef();
        return zend_update_static_property(_tmp_ce, p_name.c_str(), p_name.length(), value.ptr()) == SUCCESS;
    }
protected:
    bool activated;
    string class_name;
    string parent_class_name;
    zend_class_entry *parent_ce;
    zend_class_entry _ce;
    zend_class_entry *ce;
    unordered_map<string, zend_class_entry *> interfaces;
    vector<Method> methods;
    vector<Property> propertys;
    vector<Constant> constants;
};

static unordered_map<string, Class*> classes;

void registerClass(Class *c)
{
    /**
     * 激活类
     */
    c->activate();
    classes[c->getName()] = c;
}

void destroy()
{
    for (auto i = classes.begin(); i != classes.end(); i++)
    {
        Class *c = i->second;
        c->deactivate();
        //delete c;
    }
    for (auto i = function_map.begin(); i != function_map.end(); i++)
    {
        string name = i->first;
        unregisterFunction(name);
    }
}

template<typename T>
Variant newResource(const char *name, T *v)
{
    Resource *_c = resource_map[name];
    if (!_c)
    {
        return nullptr;
    }
    zend_resource *res = zend_register_resource(static_cast<void*>(v), _c->type);
    return Variant(res);
}

/*generator*/
Object newObject(const char *name, Variant v1)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    v16.addRef();
    args.append(v16.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    v16.addRef();
    args.append(v16.ptr());
    v17.addRef();
    args.append(v17.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    v16.addRef();
    args.append(v16.ptr());
    v17.addRef();
    args.append(v17.ptr());
    v18.addRef();
    args.append(v18.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    v16.addRef();
    args.append(v16.ptr());
    v17.addRef();
    args.append(v17.ptr());
    v18.addRef();
    args.append(v18.ptr());
    v19.addRef();
    args.append(v19.ptr());
    object.call("__construct", args);
    return object;
}
Object newObject(const char *name, Variant v1, Variant v2, Variant v3, Variant v4, Variant v5, Variant v6, Variant v7, Variant v8, Variant v9, Variant v10, Variant v11, Variant v12, Variant v13, Variant v14, Variant v15, Variant v16, Variant v17, Variant v18, Variant v19, Variant v20)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    zval zobject;
    if (object_init_ex(&zobject, ce) == FAILURE)
    {
        return object;
    }
    object = Object(&zobject);
    Array args;
    v1.addRef();
    args.append(v1.ptr());
    v2.addRef();
    args.append(v2.ptr());
    v3.addRef();
    args.append(v3.ptr());
    v4.addRef();
    args.append(v4.ptr());
    v5.addRef();
    args.append(v5.ptr());
    v6.addRef();
    args.append(v6.ptr());
    v7.addRef();
    args.append(v7.ptr());
    v8.addRef();
    args.append(v8.ptr());
    v9.addRef();
    args.append(v9.ptr());
    v10.addRef();
    args.append(v10.ptr());
    v11.addRef();
    args.append(v11.ptr());
    v12.addRef();
    args.append(v12.ptr());
    v13.addRef();
    args.append(v13.ptr());
    v14.addRef();
    args.append(v14.ptr());
    v15.addRef();
    args.append(v15.ptr());
    v16.addRef();
    args.append(v16.ptr());
    v17.addRef();
    args.append(v17.ptr());
    v18.addRef();
    args.append(v18.ptr());
    v19.addRef();
    args.append(v19.ptr());
    v20.addRef();
    args.append(v20.ptr());
    object.call("__construct", args);
    return object;
}
/*generator*/

//namespace end
}
