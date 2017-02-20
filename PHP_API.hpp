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
extern "C"
{
#include "ext/standard/php_var.h"
}

#include <unordered_map>
#include <string>
#include <vector>

#define MAX_ARGC        20
#define VAR_DUMP_LEVEL  10

using namespace std;

namespace PHP
{
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
    ~Variant()
    {
        if (!reference)
        {
            zval_ptr_dtor(&val);
        }
    }
    void operator =(int v)
    {
        ZVAL_LONG(&val, (long )v);
    }
    void operator =(long v)
    {
        ZVAL_LONG(&val, v);
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
    zval *ptr(void)
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
    int type()
    {
        return Z_TYPE(val);
    }
    bool isString()
    {
        return Z_TYPE(val) == IS_STRING;
    }
    bool isArray()
    {
        return Z_TYPE(val) == IS_ARRAY;
    }
    bool isObject()
    {
        return Z_TYPE(val) == IS_OBJECT;
    }
    bool isInt()
    {
        return Z_TYPE(val) == IS_LONG;
    }
    bool isFloat()
    {
        return Z_TYPE(val) == IS_DOUBLE;
    }
    bool isBool()
    {
        return Z_TYPE(val) == IS_TRUE || Z_TYPE(val) == IS_FALSE;
    }
    bool isNull()
    {
        return Z_TYPE(val) == IS_NULL;
    }
    bool isResource()
    {
        return Z_TYPE(val) == IS_RESOURCE;
    }
    bool isReference()
    {
        return Z_TYPE(val) == IS_REFERENCE;
    }
    string toString()
    {
        return string(Z_STRVAL_P(&val), Z_STRLEN_P(&val));
    }
    char* toCString()
    {
        return Z_STRVAL_P(&val);
    }
    long toInt()
    {
        return Z_LVAL_P(&val);
    }
    double toFloat()
    {
        return Z_DVAL_P(&val);
    }
    bool toBool()
    {
        return Z_BVAL_P(&val) == 1;
    }
protected:
    bool reference;
    zval *ref_val;
    zval val;
    void init()
    {
        reference = false;
        ref_val = NULL;
        memset(&val, 0, sizeof(val));
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
            if (UNEXPECTED(Z_TYPE_P(_val) == IS_UNDEF))
            {
                continue;
            }
            if (_key)
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

    }
    Array(Variant &v) :
            Variant()
    {
        memcpy(&val, v.ptr(), sizeof(val));
        zval_add_ref(&val);
    }
    void append(Variant &v)
    {
        add_next_index_zval(&val, v.ptr());
    }
    void append(Variant v)
    {
        add_next_index_zval(&val, v.ptr());
    }
    void append(const char *str)
    {
        add_next_index_string(&val, str);
    }
    void append(string &str)
    {
        add_next_index_stringl(&val, str.c_str(), str.length());
    }
    void append(long v)
    {
        add_next_index_long(&val, v);
    }
    void append(int v)
    {
        add_next_index_long(&val, (long) v);
    }
    void append(bool v)
    {
        add_next_index_bool(&val, v ? 1 : 0);
    }
    void append(double v)
    {
        add_next_index_double(&val, (double) v);
    }
    void append(float v)
    {
        add_next_index_double(&val, (double) v);
    }
    void append(void *v)
    {
        add_next_index_null(&val);
    }
    void append(Array &v)
    {
        zval_add_ref(v.ptr());
        add_next_index_zval(&val, v.ptr());
    }
    //------------------------------------
    void set(const char *key, Variant &v)
    {
        add_assoc_zval(&val, key, v.ptr());
    }
    void set(const char *key, long v)
    {
        add_assoc_long(&val, key, v);
    }
    void set(const char *key, const char *v)
    {
        add_assoc_string(&val, key, (char * )v);
    }
    void set(const char *key, string &v)
    {
        add_assoc_stringl(&val, key, (char* )v.c_str(), v.length());
    }
    void set(const char *key, double v)
    {
        add_assoc_double(&val, key, v);
    }
    void set(const char *key, float v)
    {
        add_assoc_double(&val, key, (double ) v);
    }
    void set(const char *key, bool v)
    {
        add_assoc_bool(&val, key, v ? 1 : 0);
    }
    void set(int i, Variant &v)
    {
        add_index_zval(&val, (zend_ulong) i, v.ptr());
    }
    Variant operator [](int i) const
    {
        zval *ret = zend_hash_index_find(Z_ARRVAL(val), (zend_ulong) i);
        return Variant(ret);
    }
    Variant operator [](const char *key) const
    {
        zval *ret = zend_hash_str_find(Z_ARRVAL(val), key, strlen(key));
        return Variant(ret);
    }
    bool remove(const char *key)
    {
        zend_string *_key = zend_string_init(key, strlen(key), 0);
        bool ret = zend_hash_del(Z_ARRVAL(val), _key) == SUCCESS;
        zend_string_free(_key);
        return ret;
    }
    void clean()
    {
        zend_hash_clean(Z_ARRVAL(val));
    }
    bool exists(const char *key)
    {
        zend_string *_key = zend_string_init(key, strlen(key), 0);
        bool ret = zend_hash_exists(Z_ARRVAL(val), _key) == SUCCESS;
        zend_string_free(_key);
        return ret;
    }
    ArrayIterator begin()
    {
        return ArrayIterator(Z_ARRVAL(val)->arData);
    }
    ArrayIterator end()
    {
        return ArrayIterator(Z_ARRVAL(val)->arData + Z_ARRVAL(val)->nNumUsed);
    }
    size_t count()
    {
        return Z_ARRVAL(val)->nNumOfElements;
    }
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

void var_dump(Variant &v)
{
    php_var_dump(v.ptr(), VAR_DUMP_LEVEL);
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
    Variant get(const char *name)
    {
        Variant retval;
        zval rv;
        zval *member_p = zend_read_property(Z_OBJCE_P(&val), &val, name, strlen(name), 0, &rv);
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

    void set(const char *name, Variant &v)
    {
        zend_update_property(Z_OBJCE_P(&val), &val, name, strlen(name), v.ptr());
    }

    void set(const char *name, Array &v)
    {
        zend_update_property(Z_OBJCE_P(&val), &val, name, strlen(name), v.ptr());
    }

    void set(const char *name, string &v)
    {
        zend_update_property_stringl(Z_OBJCE_P(&val), &val, name, strlen(name), v.c_str(), v.length());
    }
    void set(const char *name, const char *v)
    {
        zend_update_property_string(Z_OBJCE_P(&val), &val, name, strlen(name), v);
    }
    void set(const char *name, long v)
    {
        zend_update_property_long(Z_OBJCE_P(&val), &val, name, strlen(name), v);
    }
    void set(const char *name, double v)
    {
        zend_update_property_double(Z_OBJCE_P(&val), &val, name, strlen(name), v);
    }
    void set(const char *name, float v)
    {
        zend_update_property_double(Z_OBJCE_P(&val), &val, name, strlen(name), (double) v);
    }
    void set(const char *name, bool v)
    {
        zend_update_property_bool(Z_OBJCE_P(&val), &val, name, strlen(name), v ? 1 : 0);
    }
    string getClassName()
    {
        return string(Z_OBJCE_P(&val)->name->val, Z_OBJCE_P(&val)->name->len);
    }
};

Object create(const char *name, Array &args)
{
    zend_string *class_name = zend_string_init(name, strlen(name), 0);
    Object object;

    zend_class_entry *ce = zend_lookup_class(class_name);
    zend_string_free(class_name);
    if (ce == NULL)
    {
        swoole_php_error(E_WARNING, "class '%s' is undefined.", name);
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
    zend_string *class_name = zend_string_init(name, strlen(name), 0);
    Object object;

    zend_class_entry *ce = zend_lookup_class(class_name);
    zend_string_free(class_name);
    if (ce == NULL)
    {
        swoole_php_error(E_WARNING, "class '%s' is undefined.", name);
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
typedef Variant (*function_t)(Array &);
typedef Variant (*method_t)(Object &, Array &);
static unordered_map<string, function_t> function_map;
static unordered_map<string, unordered_map<string, method_t> > method_map;

static void _exec_function(zend_execute_data *data, zval *return_value)
{
    const char *name = data->func->common.function_name->val;
    function_t func = function_map[name];
    Array args;

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    while (arg_count-- > 0)
    {
        args.append(Variant(param_ptr, true));
        param_ptr++;
    }
    Variant retval = func(args);
    ZVAL_COPY_VALUE(return_value, retval.ptr());
    return;
}

static void _exec_method(zend_execute_data *data, zval *return_value)
{
    const char *method_name = data->func->common.function_name->val;
    const char *class_name = data->func->common.scope->name->val;

    method_t func = method_map[class_name][method_name];
    Array args;

    Object _this(&data->This);

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    while (arg_count-- > 0)
    {
        args.append(Variant(param_ptr, true));
        param_ptr++;
    }
    Variant retval = func(_this, args);
    ZVAL_COPY_VALUE(return_value, retval.ptr());
    return;
}

void registerFunction(const char *name, function_t func)
{
    zend_function_entry functions[] = {
        {name, _exec_function, NULL, (uint32_t) (sizeof(void*) / sizeof(struct _zend_internal_arg_info) - 1), 0 },
        {NULL, NULL, NULL,}
    };
    if (zend_register_functions(NULL, functions, NULL, MODULE_PERSISTENT) == SUCCESS)
    {
        function_map[name] = func;
    }
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
    Variant retval(zend_get_constant(_name));
    zend_string_free(_name);
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
        zend_string *parent_class_name = zend_string_init(_parent_class, strlen(_parent_class), 0);
        parent_ce = zend_lookup_class(parent_class_name);
        return parent_ce != NULL;
    }
    bool implements()
    {
        if (activated)
        {
            return false;
        }
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
        ZVAL_COPY_VALUE(&c.value, v.ptr());
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
        ZVAL_COPY_VALUE(&p.value, v.ptr());
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
         * register property
         */
        for(int i =0; i != propertys.size(); i++)
        {
            zend_declare_property(ce, propertys[i].name.c_str(), propertys[i].name.length(), &propertys[i].value, propertys[i].flags);
        }
        /**
         * register constant
         */
        for(int i =0; i != constants.size(); i++)
        {
            zend_declare_class_constant(ce, constants[i].name.c_str(), constants[i].name.length(), &constants[i].value);
        }
        return true;
    }
private:
    bool activated;
    string class_name;
    string parent_class_name;
    zend_class_entry *parent_ce;
    zend_class_entry _ce;
    zend_class_entry *ce;
    vector<Method> methods;
    vector<Property> propertys;
    vector<Constant> constants;
};
}
