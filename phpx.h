/*
  +----------------------------------------------------------------------+
  | PHP-X                                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 The Swoole Group                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the GPL license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.gnu.org/licenses/                                         |
  | If you did not receive a copy of the GPL3.0 license and are unable   |
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
#include "zend_types.h"

#include <ext/date/php_date.h>
#include <ext/json/php_json.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>
#include <ext/standard/html.h>
#include <ext/standard/php_http.h>
#include <ext/standard/php_standard.h>
#include <ext/spl/php_spl.h>

}

#include <unordered_map>
#include <string>
#include <vector>
#include <functional>
#include <map>

typedef unsigned char uchar;

#define PHPX_MAX_ARGC        10
#define PHPX_VAR_DUMP_LEVEL  10

namespace php
{

void error(int level, const char *format, ...);
void echo(const char *format, ...);

struct Resource
{
    const char *name;
    int type;
};

extern std::unordered_map<std::string, Resource *> resource_map;
extern std::map<int, void *> object_array;

class Variant
{
public:
    Variant()
    {
        init();
        ZVAL_NULL(&val);
    }
    Variant(std::nullptr_t v)
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
    Variant(std::string &str)
    {
        init();
        ZVAL_STRINGL(&val, str.c_str(), str.length());
    }
    Variant(zend_string *str)
    {
        init();
        ZVAL_STR(&val, str);
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
    Variant(zval *v, bool ref = false)
    {
        init();
        reference = ref;
        if (reference)
        {
            ref_val = v;
        }
        else
        {
            memcpy(&val, v, sizeof(zval));
            zval_add_ref(&val);
        }
    }
    Variant(zend_resource *res)
    {
        init();
        ZVAL_RES(ptr(), res);
    }
    Variant(const Variant& v)
    {
        init();
        ZVAL_COPY_VALUE(ptr(), const_cast<Variant &>(v).ptr());
        const_cast<Variant &>(v).addRef();
    }
    ~Variant()
    {
        destroy();
    }
    void operator =(int v)
    {
        destroy();
        ZVAL_LONG(ptr(), (long )v);
    }
    void operator =(long v)
    {
        destroy();
        ZVAL_LONG(ptr(), v);
    }
    void operator =(std::string &str)
    {
        destroy();
        ZVAL_STRINGL(ptr(), str.c_str(), str.length());
    }
    void operator =(const char *str)
    {
        destroy();
        ZVAL_STRING(ptr(), str);
    }
    void operator =(double v)
    {
        destroy();
        ZVAL_DOUBLE(ptr(), v);
    }
    void operator =(float v)
    {
        destroy();
        ZVAL_DOUBLE(ptr(), (double )v);
    }
    void operator =(bool v)
    {
        destroy();
        ZVAL_BOOL(ptr(), v);
    }
    void operator =(std::nullptr_t _null)
    {
        destroy();
        ZVAL_NULL(ptr());
    }
    void operator =(zval *v)
    {
        destroy();
        memcpy(&val, v, sizeof(zval));
        zval_add_ref(&val);
    }
    void operator =(const Variant &v)
    {
        destroy();
        ZVAL_COPY_VALUE(ptr(), const_cast<Variant &>(v).ptr());
        const_cast<Variant &>(v).addRef();
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
    inline void delRef()
    {
        zval_delref_p(ptr());
    }
    inline int getRefCount()
    {
        zend_refcounted *counted = Z_COUNTED_P(ptr());
        if (!counted)
        {
            return 0;
        }
        return GC_REFCOUNT(counted);
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
#ifdef IS_TYPE_IMMUTABLE
    inline bool isImmutable()
    {
        return Z_TYPE_FLAGS_P(ptr()) & IS_TYPE_IMMUTABLE;
    }
#endif
    inline bool isEmpty()
    {
        switch(type())
        {
        case IS_UNDEF:
        case IS_NULL:
        case IS_FALSE:
            return true;
        case IS_LONG:
            return toInt() == 0;
        case IS_DOUBLE:
            return toFloat() == 0.0;
        case IS_STRING:
            return length() == 0;
        case IS_ARRAY:
            return Z_ARRVAL_P(ptr())->nNumOfElements == 0;
        default:
            return true;
        }
    }
    inline std::string toString()
    {
        if (!isString())
        {
            convert_to_string(ptr());
        }
        return std::string(Z_STRVAL_P(ptr()), Z_STRLEN_P(ptr()));
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
    Variant* dup()
    {
        return new Variant(*this);
    }
    inline size_t length()
    {
        if (isString())
        {
            return Z_STRLEN_P(ptr());
        }
        else if (isArray())
        {
            return zend_hash_num_elements(Z_ARRVAL_P(ptr()));
        }
        else
        {
            return 0;
        }
    }
    template<class T>
    T* toResource(const char *name)
    {
        if (!isResource())
        {
            error(E_WARNING, "This variant is not a resource type.");
            return nullptr;
        }
        void *_ptr = nullptr;
        Resource *_c = resource_map[name];
        if (_c == nullptr)
        {
            error(E_WARNING, "The %s type of resource is undefined.", name);
            return nullptr;
        }
        if ((_ptr = zend_fetch_resource(Z_RES_P(ptr()), name, _c->type)) == NULL)
        {
            error(E_WARNING, "The %s type of resource is undefined.", name);
            return nullptr;
        }
        return static_cast<T *>(_ptr);
    }
    bool operator ==(Variant &v)
    {
        return equals(v);
    }
    bool operator ==(bool v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(int v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(long v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(float v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(double v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(std::nullptr_t v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(std::string &v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool operator ==(const char *v)
    {
        Variant _tmp(v);
        return equals(_tmp);
    }
    bool isZvalRef() const
    {
        return reference;
    }
    bool equals(Variant &v, bool strict = false);
    Variant jsonEncode(zend_long options = 0, zend_long depth = PHP_JSON_PARSER_DEFAULT_DEPTH);
    Variant jsonDecode(zend_long options = 0, zend_long depth = PHP_JSON_PARSER_DEFAULT_DEPTH);
    Variant serialize();
    Variant unserialize();
    bool isCallable();
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
    void destroy()
    {
        if (!reference)
        {
            zval_ptr_dtor(&val);
            init();
        }
    }
};

template<typename T>
Variant newResource(const char *name, T *v)
{
    Resource *_c = resource_map[name];
    if (!_c)
    {
        error(E_WARNING, "%s type of resource is undefined.", name);
        return nullptr;
    }
    zend_resource *res = zend_register_resource(static_cast<void*>(v), _c->type);
    return Variant(res);
}

static inline void var_dump(Variant &v)
{
    php_var_dump(v.ptr(), PHPX_VAR_DUMP_LEVEL);
}

static inline bool is_callable(const Variant &fn)
{
    return zend_is_callable(const_cast<Variant &>(fn).ptr(), 0, nullptr);
}

Variant include(std::string file);

static inline int version_compare(std::string s1, std::string s2)
{
	return php_version_compare(s1.c_str(), s2.c_str());
}

class String
{
public:
    String(const char *str)
    {
        value = zend_string_init(str, strlen(str), 0);
    }
    String(int v)
    {
        value = zend_long_to_str(v);
    }
    String(long v)
    {
        value = zend_long_to_str(v);
    }
    String(float v)
    {
        value = zend_strpprintf(0, "%.*G", (int) EG(precision), v);
    }
    String(double v)
    {
        value = zend_strpprintf(0, "%.*G", (int) EG(precision), v);
    }
    String(bool v)
    {
        value = zend_string_init(v ? "1" : "0", 1, 0);
    }
    String(const char *str, size_t len)
    {
        value = zend_string_init(str, len, 0);
    }
    String(std::string &str)
    {
        value = zend_string_init(str.c_str(), str.length(), 0);
    }
    String(zend_string *str)
    {
        value = str;
    }
    String(zval *str, bool ref = false)
    {
        value = Z_STR_P(str);
        if (ref)
        {
        	free_memory = false;
        }
    }
    String(Variant &v)
    {
        if (v.type() != IS_STRING)
        {
            error(E_ERROR, "parameter 1 must be zend_string.");
        }
        value = Z_STR_P(v.ptr());
        free_memory = false;
    }
    ~String()
    {
        if (free_memory)
        {
            zend_string_release(value);
        }
    }
    inline long toInt()
    {
        return ZEND_STRTOL(ZSTR_VAL(value), nullptr, 10);
    }
    inline double toFloat()
    {
        return zend_strtod(ZSTR_VAL(value), nullptr);
    }
    inline size_t length()
    {
        return value->len;
    }
    inline char* c_str()
    {
        return value->val;
    }
    inline uint64_t hashCode()
    {
        return zend_string_hash_val(value);
    }
    inline void extend(size_t new_size)
    {
        value = zend_string_extend(value, new_size, 0);
    }
    inline bool equals(const char *str)
    {
        return memcmp(str, value->val, value->len) == 0;
    }
    inline bool equals(std::string &str)
    {
        if (str.length() != value->len)
        {
            return false;
        }
        return memcmp(str.c_str(), value->val, value->len) == 0;
    }
    inline bool operator ==(String &v)
    {
        return equals(v);
    }
    inline static String format(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        zend_string *s = vstrpprintf(0, format, args);
        va_end(args);
        return s;
    }
    bool equals(String &str, bool ci = false)
    {
        if (str.length() != value->len)
        {
            return false;
        }
        if (ci)
        {
            return zend_binary_strcasecmp(str.c_str(), str.length(), value->val, value->len) == 0;
        }
        return memcmp(str.c_str(), value->val, value->len) == 0;
    }
    inline String trim(String &what, int mode = 3)
	{
		return php_trim(value, (char *) what.c_str(), what.length(), mode);
	}
    inline void tolower()
    {
        zend_str_tolower(value->val, value->len);
    }
    inline String base64Encode(bool raw = false)
    {
		return php_base64_decode_ex((const unsigned char *) value->val, value->len, raw);
    }

	inline String escape(int flags = ENT_QUOTES | ENT_SUBSTITUTE, std::string charset = SG(default_charset))
	{
		return php_escape_html_entities((unsigned char *) value->val,
				value->len, 0, flags, (char *) charset.c_str());
	}

	inline String unescape(int flags, std::string charset)
	{
#if PHP_VERSION_ID < 70200
		return php_unescape_html_entities((unsigned char *) value->val,
				value->len, 1, flags, (char *) charset.c_str());
#else
		return php_unescape_html_entities(value, 1, flags, (char *) charset.c_str());
#endif
	}

	Variant split(String &delim, long = ZEND_LONG_MAX);
    String substr(long _offset, long _length = -1);
    void stripTags(String &allow, bool allow_tag_spaces = false);
    String addSlashes();
    void stripSlashes();
    String basename(String &suffix);
    String dirname();

    inline zend_string* ptr()
    {
        return value;
    }
protected:
    bool free_memory = true;
    zend_string *value;
};

static inline String ini_get(String varname)
{
    char *value = zend_ini_string((char *) varname.c_str(), (uint) varname.length(), 0);
    if (!value)
    {
        return "";
    }
    return value;
}

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
        while (++_ptr != pe)
        {
            _val = &_ptr->val;
            if (_val && Z_TYPE_P(_val) == IS_INDIRECT)
            {
                _val = Z_INDIRECT_P(_val);
            }
            if (UNEXPECTED(Z_TYPE_P(_val) == IS_UNDEF))
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

extern int array_data_compare(const void *a, const void *b);
extern String md5(String data, bool raw_output = false);
extern String sha1(String data, bool raw_output = false);
extern String crc32(String data, bool raw_output = false);
extern String hash(String algo, String data, bool raw_output = false);
extern String hash_hmac(String algo, String data, String key, bool raw_output = false);

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
        if (isReference())
        {
            zval_delref_p(&val);
            ZVAL_COPY(&val, Z_REFVAL_P(&val));
        }
        if (isNull())
        {
            array_init(ptr());
        }
        else if (!isArray())
        {
            error(E_ERROR, "parameter 1 must be zend_array.");
        }
    }
    Array(const Variant &v)
    {
        reference = v.isZvalRef();

        zval* zv = const_cast<Variant &>(v).ptr();
        if (Z_TYPE_P(zv) == IS_REFERENCE)
        {
            zv = Z_REFVAL_P(zv);
        }
        if (reference)
        {
            ref_val = zv;
        }
        else
        {
            memcpy(&val, zv, sizeof(*zv));
            addRef();
        }
        if (isNull())
        {
            array_init(ptr());
        }
        else if (!isArray())
        {
            error(E_ERROR, "parameter 1 must be zend_array.");
        }
#ifdef HT_ALLOW_COW_VIOLATION
        HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(ptr()));
#endif
    }
    void separate()
    {
        SEPARATE_ARRAY(ptr());
    }
    void append(const Variant &v)
    {
        const_cast<Variant &>(v).addRef();
        add_next_index_zval(ptr(), const_cast<Variant &>(v).ptr());
    }
    void append(const char *str)
    {
        add_next_index_string(ptr(), str);
    }
    void append(std::string &str)
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
    inline void set(const char *key, const Variant &v)
    {
        const_cast<Variant &>(v).addRef();
        add_assoc_zval(ptr(), key, const_cast<Variant &>(v).ptr());
    }
    inline void set(const char *key, int v)
    {
        add_assoc_long(ptr(), key, (long) v);
    }
    inline void set(const char *key, long v)
    {
        add_assoc_long(ptr(), key, v);
    }
    inline void set(const char *key, const char *v)
    {
        add_assoc_string(ptr(), key, (char * )v);
    }
    inline void set(const char *key, std::string &v)
    {
        add_assoc_stringl(ptr(), key, (char* )v.c_str(), v.length());
    }
    inline void set(const char *key, double v)
    {
        add_assoc_double(ptr(), key, v);
    }
    inline void set(const char *key, float v)
    {
        add_assoc_double(ptr(), key, (double ) v);
    }
    inline void set(const char *key, bool v)
    {
        add_assoc_bool(ptr(), key, v ? 1 : 0);
    }
    inline void set(const String &s, const Variant & v)
    {
        set(const_cast<String &>(s).c_str(), v);
    }
    inline void del(const char *key)
    {
        zend_hash_str_del(Z_ARRVAL_P(ptr()), key, strlen(key));
    }
    inline void del(const String &key)
    {
        const char* s = const_cast<String &>(key).c_str();
        zend_hash_str_del(Z_ARRVAL_P(ptr()), s, strlen(s));
    }
    //------------------index-array------------------
    inline void set(int i, const Variant & v)
    {
        const_cast<Variant &>(v).addRef();
        add_index_zval(ptr(), (zend_ulong) i, const_cast<Variant &>(v).ptr());
    }
    inline void del(int i)
    {
        zend_hash_index_del(Z_ARRVAL_P(ptr()), (zend_ulong) i);
    }
    //-------------------------------------------
    inline Variant get(const char *key)
    {
        zval *ret = zend_hash_str_find(Z_ARRVAL_P(ptr()), key, strlen(key));
        if (ret == NULL)
        {
            return nullptr;
        }
        return ret;
    }
    inline Variant get(int i)
    {
        zval *ret = zend_hash_index_find(Z_ARRVAL_P(ptr()), (zend_ulong) i);
        if (ret == NULL)
        {
            return nullptr;
        }
        return ret;
    }
    inline Variant operator [](int i)
    {
        return get(i);
    }
    inline Variant operator [](const char *key)
    {
        return get(key);
    }
    inline bool remove(const char *key)
    {
        String _key(key);
        bool ret = zend_hash_del(Z_ARRVAL_P(ptr()),  _key.ptr()) == SUCCESS;
        return ret;
    }
    inline void clean()
    {
        zend_hash_clean(Z_ARRVAL_P(ptr()));
    }
    inline bool exists(const char *key)
    {
        return zend_hash_str_exists(Z_ARRVAL_P(ptr()), key, strlen(key));
    }
    inline bool exists(std::string &key)
    {
        return zend_hash_str_exists(Z_ARRVAL_P(ptr()), key.c_str(), key.length());
    }
    ArrayIterator begin()
    {
        return ArrayIterator(Z_ARRVAL_P(ptr())->arData, Z_ARRVAL_P(ptr())->arData + Z_ARRVAL_P(ptr())->nNumUsed);
    }
    ArrayIterator end()
    {
        return ArrayIterator(Z_ARRVAL_P(ptr())->arData + Z_ARRVAL_P(ptr())->nNumUsed);
    }
    inline size_t count()
    {
        return zend_hash_num_elements(Z_ARRVAL_P(ptr()));
    }
    bool empty()
    {
        return count() == 0;
    }
    Variant search(Variant &_other_var, bool strict = false)
    {
        for (auto i = this->begin(); i != this->end(); i++)
        {
            if (i.value().equals(_other_var, strict))
            {
                return i.key();
            }
        }
        return false;
    }
    bool contains(Variant &_other_var, bool strict = false)
    {
        for (auto i = this->begin(); i != this->end(); i++)
        {
            if (i.value().equals(_other_var, strict))
            {
                return true;
            }
        }
        return false;
    }
    String join(String &delim)
    {
        Variant retval;
        php_implode(delim.ptr(), ptr(), retval.ptr());
        retval.addRef();
        return retval.ptr();
    }
    void merge(Array &source, bool overwrite = false)
    {
        zend_hash_merge(Z_ARRVAL_P(ptr()), Z_ARRVAL_P(source.ptr()), zval_add_ref, overwrite);
    }
    bool sort()
    {
        return zend_hash_sort(Z_ARRVAL_P(ptr()), array_data_compare, 1) == SUCCESS;
    }
    Array slice(long offset, long length = -1, bool preserve_keys = false);
};


class Args
{
public:
    ~Args()
    {
        if (ptr_list)
        {
            efree(ptr_list);
        }
        if (zval_list)
        {
            efree(zval_list);
        }
    }
    inline void append(zval *v)
    {
        if (UNEXPECTED(argc == size))
        {
            if (UNEXPECTED(!extend()))
            {
                return;
            }
        }
        ptr_list[argc++] = v;
    }
    inline void append(const Variant &v)
    {
        if (UNEXPECTED(argc == size))
        {
            if (UNEXPECTED(!extend()))
            {
                return;
            }
        }
        int index = argc++;
        ptr_list[index] = &zval_list[index];
        memcpy(&zval_list[index], const_cast<Variant &>(v).ptr(), sizeof(zval));
        zval_add_ref(ptr_list[index]);
    }
    inline size_t count()
    {
        return argc;
    }
    inline bool exists(int i)
    {
        return i < argc;
    }
    inline bool empty()
    {
        return argc == 0;
    }
    Array toArray()
    {
        Array array;
        for (int i = 0; i < argc; i++)
        {
            array.append(Variant(ptr_list[i]));
        }
        return array;
    }
    inline Variant operator [](int i)
    {
        if (UNEXPECTED(i >= argc))
        {
            return Variant(nullptr);
        }
        zval *value = ptr_list[i];
        if (Z_TYPE_P(value) == IS_REFERENCE)
        {
            value = static_cast<zval *>(Z_REFVAL_P(value));
        }
        return Variant(value, true);
    }
private:
    bool extend()
    {
        int _new_size = size == 0 ? PHPX_MAX_ARGC : size * 2;
        zval** _new_ptr = (zval**) ecalloc(_new_size, sizeof(zval*));
        if (UNEXPECTED(_new_ptr == nullptr))
        {
            return false;
        }
        zval* _new_zval_ptr = (zval*) ecalloc(_new_size, sizeof(zval));
        if (UNEXPECTED(_new_zval_ptr == nullptr))
        {
            efree(_new_ptr);
            return false;
        }
        ptr_list = _new_ptr;
        zval_list = _new_zval_ptr;
        size = _new_size;
        return true;
    }
    int argc = 0;
    int size = 0;
    zval **ptr_list = nullptr;
    zval *zval_list = nullptr;
};

class ArgInfo
{
public:
    ArgInfo(int required_num, bool return_reference = false)
    {
        this->required_num = required_num;
        this->return_reference = return_reference;
        this->info = nullptr;
    }
#if PHP_VERSION_ID >= 70200
    ~ArgInfo()
    {
        for (int i = 1; i <= list.size(); i++)
        {
            if (ZEND_TYPE_IS_CLASS(info[i].type))
            {
                efree((void* )info[i].type);
            }
        }
    }
#endif

    void add(const char *name, const char *class_name = nullptr, int type_hint = 0, bool pass_by_reference = false,
            bool allow_null = false, bool variadic = false)
    {
#if PHP_VERSION_ID >= 70200
        zend_type type;
        if (class_name)
        {
            if (allow_null)
            {
                int _l = strlen(class_name);
                char *_s = (char *) emalloc(_l + 2);
                _s[0] = '?';
                _s[_l + 1] = 0;
                type = (zend_type) _s;
            }
            else
            {
                type = (zend_type) estrdup(class_name);
            }
        }
        else
        {
            type = ZEND_TYPE_ENCODE(type_hint, allow_null);
        }
        zend_internal_arg_info val =
        { name, type, pass_by_reference, variadic, };
#else
        zend_internal_arg_info val =
        { name, class_name, (zend_uchar)type_hint, pass_by_reference, allow_null, variadic, };
#endif
        list.push_back(val);
    }
    zend_internal_arg_info* get()
    {
        if (info != nullptr)
        {
            return info;
        }
        zend_internal_arg_info *_info = (zend_internal_arg_info*) calloc(list.size() + 1,
                sizeof(zend_internal_arg_info));
        if (_info == nullptr)
        {
            return nullptr;
        }
        _info[0].name = (const char*) (zend_uintptr_t) (required_num);
        _info[0].pass_by_reference = return_reference;
        for (int i = 1; i <= list.size(); i++)
        {
            memcpy(&_info[i], &list[i - 1], sizeof(zend_internal_arg_info));
        }
        info = _info;
        return _info;
    }
    size_t count()
    {
        return list.size();
    }
protected:
    int required_num;
    bool return_reference;
    zend_internal_arg_info *info;
    std::vector<zend_internal_arg_info> list;
};

extern Variant _call(zval *object, zval *func, Args &args);
extern Variant _call(zval *object, zval *func);

static inline Variant call(const Variant &func)
{
    return _call(nullptr, const_cast<Variant &>(func).ptr());
}

static inline Variant call(const Variant &func, Args &args)
{
    return _call(NULL, const_cast<Variant &>(func).ptr(), args);
}

static inline Variant call(const Variant &func, Array &args)
{
    Args _args;
    for (int i = 0; i < args.count(); i++)
    {
        _args.append(args[i].ptr());
    }
    return _call(NULL, const_cast<Variant &>(func).ptr(), _args);
}

static inline Variant exec(const char *func)
{
    Variant _func(func);
    Args args;
    return _call(NULL, _func.ptr(), args);
}
/*generator*/
extern Variant exec(const char *func, const Variant &v1);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9);
extern Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9, const Variant &v10);
/*generator*/

static inline zend_class_entry *getClassEntry(const char *name)
{
    String class_name(name, strlen(name));
    return zend_lookup_class(class_name.ptr());
}

static void throwException(const char *name, const char *message, int code = 0)
{
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' undefined.", name);
        return;
    }
    zend_throw_exception(ce, message, code TSRMLS_CC);
}

static Variant global(const char *name)
{
    zend_string *key = zend_string_init(name, strlen(name), 0);
    zend_is_auto_global(key);
    zval *var = zend_hash_find_ind(&EG(symbol_table), key);
    zend_string_free(key);
    if (!var)
    {
        return false;
    }
    return Variant(var, true);
}

class Object: public Variant
{
public:
    Object(const Variant &v) :
            Variant()
    {
        if (!const_cast<Variant &>(v).isObject())
        {
            error(E_ERROR, "parameter 1 must be zend_object.");
            return;
        }
        ref_val = const_cast<Variant &>(v).ptr();
        reference = true;
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
    inline Variant call(Variant &func, Args &args)
    {
        return _call(ptr(), func.ptr(), args);
    }
    inline Variant call(const char *func, Args &args)
    {
        Variant _func(func);
        return _call(ptr(), _func.ptr(), args);
    }
    inline Variant callParentMethod(const char *func)
    {
        Variant retval;
        zend_call_method_with_0_params(ptr(), Z_OBJCE_P(ptr())->parent, NULL, func, retval.ptr());
        return retval;
    }
    inline Variant callParentMethod(const char *func, const Variant &v1)
    {
        Variant retval;
        zend_call_method_with_1_params(ptr(), Z_OBJCE_P(ptr())->parent, NULL, func, retval.ptr(),
                const_cast<Variant &>(v1).ptr());
        return retval;
    }
    inline Variant callParentMethod(const char *func, const Variant &v1, const Variant &v2)
    {
        Variant retval;
        echo("%p\n", Z_OBJCE_P(ptr())->parent);
        zend_call_method_with_2_params(ptr(), Z_OBJCE_P(ptr())->parent, NULL, func, retval.ptr(),
                const_cast<Variant &>(v1).ptr(), const_cast<Variant &>(v2).ptr());
        return retval;
    }
    inline Variant exec(const char *func)
    {
        Variant _func(func);
        return _call(ptr(), _func.ptr());
    }

    /*generator*/
    Variant exec(const char *func, const Variant &v1);
    Variant exec(const char *func, const Variant &v1, const Variant &v2);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9);
    Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9, const Variant &v10);
    /*generator*/

    inline Variant get(const char *name)
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
        return retval;
    }
    inline void set(const char *name, const Variant &v)
    {
        zend_update_property(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), const_cast<Variant &>(v).ptr());
    }
    inline void set(const char *name, Array &v)
    {
        zend_update_property(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.ptr());
    }
    inline void set(const char *name, std::string &v)
    {
        zend_update_property_stringl(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.c_str(), v.length());
    }
    inline void set(const char *name, std::string v)
    {
        zend_update_property_stringl(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v.c_str(), v.length());
    }
    inline void set(const char *name, const char *v)
    {
        zend_update_property_string(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    inline void set(const char *name, int v)
    {
        zend_update_property_long(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    inline void set(const char *name, long v)
    {
        zend_update_property_long(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    inline void set(const char *name, double v)
    {
        zend_update_property_double(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v);
    }
    inline void set(const char *name, float v)
    {
        zend_update_property_double(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), (double) v);
    }
    inline void set(const char *name, bool v)
    {
        zend_update_property_bool(Z_OBJCE_P(ptr()), ptr(), name, strlen(name), v ? 1 : 0);
    }
    template<class T>
    inline T* oGet(const char *key, const char *resource_name)
    {
        Variant p = this->get(key);
        return p.toResource<T>(resource_name);
    }
    template<class T>
    inline void oSet(const char *key, const char *resource_name, T *ptr)
    {
        Variant res = newResource<T>(resource_name, ptr);
        this->set(key, res);
    }
    template<class T>
    inline T* oPtr(const char *key, const char *resource_name)
    {
        Variant p = this->get(key);
        return p.toResource<T>(resource_name);
    }
    template<class T>
    inline void store(T *ptr)
    {
        if (ptr == nullptr)
        {
            object_array.erase(getId());
            delete ptr;
        }
        else
        {
            object_array[getId()] = ptr;
        }
    }
    template<class T>
    inline T* fetch()
    {
        return static_cast<T*>(object_array[this->getId()]);
    }
    inline std::string getClassName()
    {
        return std::string(Z_OBJCE_P(ptr())->name->val, Z_OBJCE_P(ptr())->name->len);
    }
    inline uint32_t getId()
    {
        return Z_OBJ_HANDLE(*ptr());
    }
    String hash()
    {
        return php_spl_object_hash(ptr());
    }
    inline bool methodExists(const char *name)
    {
        return zend_hash_str_exists(&Z_OBJCE_P(ptr())->function_table, name, strlen(name));
    }
    inline bool propertyExists(const char *name)
    {
        return zend_hash_str_exists(&Z_OBJCE_P(ptr())->properties_info, name, strlen(name));
    }
};

static Object create(const char *name, Args &args)
{
    zend_class_entry *ce = getClassEntry(name);
    Object object;
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    if (object_init_ex(object.ptr(), ce) == FAILURE)
    {
        return object;
    }
    object.call("__construct", args);
    return object;
}

static Object create(const char *name)
{
    Object object;
    zend_class_entry *ce = getClassEntry(name);
    if (ce == NULL)
    {
        php_error_docref(NULL, E_WARNING, "class '%s' is undefined.", name);
        return object;
    }
    if (object_init_ex(object.ptr(), ce) == FAILURE)
    {
        return object;
    }
    return object;
}

#define PHPX_FN(n)              #n, n
#define PHPX_ME(c,m)            #m, c##_##m
#define PHPX_FUNCTION(c)        void c(Args &args, Variant &retval)
#define PHPX_METHOD(c, m)       void c##_##m(Object &_this, Args &args, Variant &retval)
#define PHPX_EXTENSION()        extern "C" { ZEND_DLEXPORT Extension* get_module(); } ZEND_DLEXPORT Extension* get_module()

typedef void (*function_t)(Args &, Variant &retval);
typedef void (*resource_dtor)(zend_resource *);
typedef void (*method_t)(Object &, Args &, Variant &retval);

struct strCmp
{
    bool operator()( const char * s1, const char * s2 ) const
    {
        return strcmp( s1, s2 ) < 0;
    }
};

extern std::map<const char *, std::map<const char *, method_t, strCmp>, strCmp> method_map;
extern std::map<const char *, function_t, strCmp> function_map;

extern void _exec_function(zend_execute_data *data, zval *return_value);
extern void _exec_method(zend_execute_data *data, zval *return_value);

String number_format(double num, int decimals = 0, char dec_point = '.', char thousands_sep = ',');
Variant http_build_query(const Variant &data, const char* prefix = nullptr, const char* arg_sep = nullptr,
        int enc_type = PHP_QUERY_RFC1738);

extern Variant constant(const char *name);
extern bool define(const char *name, const Variant &v, bool case_sensitive = true);

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
#ifdef ZEND_ACC_CLONE
    CLONE = ZEND_ACC_CLONE,
#endif
};

enum SortFlags
{
    SORT_REGULAR = 0,
    SORT_NUMERIC = 1,
    SORT_STRING = 2,
    SORT_DESC = 3,
    SORT_ASC = 4,
    SORT_LOCALE_STRING = 5,
    SORT_NATURAL = 6,
    SORT_FLAG_CASE = 8,
};

struct Method
{
    std::string name;
    int flags;
    method_t method;
    ArgInfo *info;
};

class Class
{
    struct Property
    {
        std::string name;
        zval value;
        int flags;
    };

    struct Constant
    {
        std::string name;
        zval value;
    };

public:
    Class(const char *name);
    bool extends(zend_class_entry *_parent_class);
    bool extends(Class *parent);
    bool implements(const char *name);
    bool implements(zend_class_entry *interface_ce);
    bool addConstant(const char *name, Variant v);
    bool addProperty(const char *name, Variant v, int flags = PUBLIC);
    bool addMethod(const char *name, method_t method, int flags = PUBLIC, ArgInfo *info = nullptr);
    bool activate();
    bool alias(const char *alias_name);

    std::string getName()
    {
        return class_name;
    }
    zend_class_entry* ptr()
    {
        return ce;
    }
    Variant getStaticProperty(std::string p_name)
    {
        if (!activated)
        {
            return nullptr;
        }
        return Variant(zend_read_static_property(ce, p_name.c_str(), p_name.length(), 1));
    }
    bool setStaticProperty(std::string p_name, Variant value)
    {
        if (!activated)
        {
            return false;
        }
        value.addRef();
        return zend_update_static_property(ce, p_name.c_str(), p_name.length(), value.ptr()) == SUCCESS;
    }
    static Variant get(const char *name, std::string p_name)
    {
        zend_class_entry *_tmp_ce = getClassEntry(name);
        if (!_tmp_ce)
        {
            return nullptr;
        }
        return Variant(zend_read_static_property(_tmp_ce, p_name.c_str(), p_name.length(), 1));
    }
    static bool set(const char *name, std::string p_name, Variant value)
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
    std::string class_name;
    std::string parent_class_name;
    zend_class_entry *parent_ce;
    zend_class_entry _ce;
    zend_class_entry *ce;
    std::unordered_map<std::string, zend_class_entry *> interfaces;
    std::vector<Method> methods;
    std::vector<Property> propertys;
    std::vector<Constant> constants;
    std::vector<std::string> aliases;
};

class Interface
{
public:
    Interface(const char *name)
    {
        this->name = name;
        INIT_CLASS_ENTRY_EX(_ce, name, strlen(name), NULL);
        ce = NULL;
    }
    bool addMethod(const char *name, ArgInfo *info)
    {
        if (activated)
        {
            return false;
        }
        Method m;
        m.flags = 0;
        m.method = nullptr;
        m.name = name;
        m.info = info;
        methods.push_back(m);
        return false;
    }
    inline std::string getName()
    {
        return name;
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
            _methods[i].handler = nullptr;
            _methods[i].arg_info = methods[i].info->get();
            _methods[i].num_args = (uint32_t) methods[i].info->count();
            _methods[i].flags = ZEND_ACC_PUBLIC | ZEND_ACC_ABSTRACT;
        }
        memset(&_methods[n], 0, sizeof(zend_function_entry));
        _ce.info.internal.builtin_functions = _methods;
        ce = zend_register_internal_interface(&_ce TSRMLS_CC);
        efree(_methods);
        if (ce == nullptr)
        {
            return false;
        }
        activated = true;
        return true;
    }
protected:
    bool activated = false;
    std::string name;
    zend_class_entry _ce;
    zend_class_entry *ce;
    std::vector<Method> methods;
};

extern std::unordered_map<std::string, Class*> class_map;
extern std::unordered_map<std::string, Interface*> interface_map;

extern int extension_startup(int type, int module_number);
extern void extension_info(zend_module_entry *module);
extern int extension_shutdown(int type, int module_number);
extern int extension_before_request(int type, int module_number);
extern int extension_after_request(int type, int module_number);

class Extension
{
    friend int extension_startup(int type, int module_number);
    friend int extension_shutdown(int type, int module_number);

protected:
    zend_module_entry module =
    {
    STANDARD_MODULE_HEADER_EX,
    NULL,
    NULL,
    NULL,    //name
    NULL, //functions
    extension_startup, //MINIT
    extension_shutdown,  //MSHUTDOWN
    extension_before_request, //RINIT
    extension_after_request, //RSHUTDOWN
    extension_info, //MINFO
    NULL, //version
    STANDARD_MODULE_PROPERTIES,
    };

    // INI
    struct IniEntry {
        std::string name;
        std::string default_value;
        int modifiable;
    };

    void registerIniEntries(int module_number);
    void unregisterIniEntries(int module_number);

public:

    enum StartupStatus
    {
        BEFORE_START, AFTER_START,
    };

    Extension(const char*name, const char *version);

    void inline checkStartupStatus(enum StartupStatus status, const char *func)
    {
        if (status == AFTER_START && !this->started)
        {
            zend_error(E_CORE_ERROR, "php::%s must be called after startup.", func);
        }
        else if (status == BEFORE_START && this->started)
        {
            zend_error(E_CORE_ERROR, "php::%s must be called before startup.", func);
        }
    }

    bool registerClass(Class *c);
    bool registerInterface(Interface *i);
    bool registerFunction(const char *name, function_t func, ArgInfo *info = nullptr);
    bool registerResource(const char *name, resource_dtor dtor);
    void registerConstant(const char *name, long v);
    void registerConstant(const char *name, int v);
    void registerConstant(const char *name, bool v);
    void registerConstant(const char *name, double v);
    void registerConstant(const char *name, float v);
    void registerConstant(const char *name, const char *v);
    void registerConstant(const char *name, const char *v, size_t len);
    void registerConstant(const char *name, std::string &v);

    bool require(const char *name, const char *version = nullptr);

    void info(std::vector<std::string> header, std::vector<std::vector<std::string> > body)
    {
        this->header = header;
        this->body = body;
    }

    // modifiable can be one of these:PHP_INI_SYSTEM/PHP_INI_PERDIR/PHP_INI_USER/PHP_INI_ALL
    void addIniEntry(const char* name, const char* default_value = "", int modifiable = PHP_INI_ALL)
    {
        IniEntry entry;
        entry.name = name;
        entry.default_value = default_value;
        entry.modifiable = modifiable;
        ini_entries.push_back(entry);
    }

    std::string name;
    std::string version;
    bool started = false;

    std::function<void(void)> onStart = nullptr;
    std::function<void(void)> onShutdown = nullptr;
    std::function<void(void)> onBeforeRequest = nullptr;
    std::function<void(void)> onAfterRequest = nullptr;

    std::vector<std::string> header;
    std::vector<std::vector<std::string> > body;

protected:
    int function_count = 0;
    int function_array_size = 0;
    int deps_count = 0;
    int deps_array_size = 0;

    std::vector<IniEntry> ini_entries;
};

extern std::unordered_map<std::string, Extension*> _name_to_extension;
extern std::unordered_map<int, Extension*> _module_number_to_extension;

extern Object newObject(const char *name);

/*generator*/
extern Object newObject(const char *name, const Variant &v1);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9);
extern Object newObject(const char *name, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9, const Variant &v10);
/*generator*/

//namespace end
}
