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

#include "phpx.h"

using namespace std;

namespace php
{

Class::Class(const char *name)
{
    class_name = name;
    INIT_CLASS_ENTRY_EX(_ce, name, strlen(name), NULL);
    parent_ce = NULL;
    ce = NULL;
    activated = false;
}

bool Class::extends(zend_class_entry *_parent_class)
{
    if (activated)
    {
        return false;
    }
    parent_class_name = string(_parent_class->name->val, _parent_class->name->len);
    parent_ce = _parent_class;
    return parent_ce != NULL;
}

bool Class::extends(Class *parent)
{
    if (activated)
    {
        return false;
    }
    parent_class_name = parent->getName();
    parent_ce = parent->ptr();
    return parent_ce != NULL;
}

bool Class::implements(const char *name)
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
    interfaces[name] = interface_ce;
    return true;
}

bool Class::implements(zend_class_entry *interface_ce)
{
    if (activated)
    {
        return false;
    }
    interfaces[interface_ce->name->val] = interface_ce;
    return true;
}

bool Class::addConstant(const char *name, Variant v)
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

bool Class::addProperty(const char *name, Variant v, int flags)
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

bool Class::addMethod(const char *name, method_t method, int flags, ArgInfo *info)
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
    m.info = info;
    methods.push_back(m);
    return false;
}

bool Class::alias(const char *alias_name)
{
    if (activated)
    {
        error(E_WARNING, "Please execute alias method before activate.");
        return false;
    }
    aliases.push_back(alias_name);
    return true;
}

bool Class::activate()
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
        if (methods[i].info)
        {
            _methods[i].arg_info = methods[i].info->get();
            _methods[i].num_args = methods[i].info->count();
        }
        else
        {
            _methods[i].arg_info = nullptr;
            _methods[i].num_args = 0;
        }
        _methods[i].flags = methods[i].flags;
        method_map[class_name.c_str()][methods[i].name.c_str()] = methods[i].method;
    }
    memset(&_methods[n], 0, sizeof(zend_function_entry));
    _ce.info.internal.builtin_functions = _methods;
    if (parent_ce)
    {
        ce = zend_register_internal_class_ex(&_ce, parent_ce);
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
        if (Z_TYPE(p.value) == IS_STRING)
        {
            zend_declare_property_stringl(ce, p.name.c_str(), p.name.length(), Z_STRVAL(p.value), Z_STRLEN(p.value), p.flags);
        }
        else
        {
            zend_declare_property(ce, p.name.c_str(), p.name.length(), &p.value, p.flags);
        }
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
            zend_declare_class_constant(ce, constants[i].name.c_str(), constants[i].name.length(), &constants[i].value);
        }
    }
    for (int i = 0; i < aliases.size(); i++)
    {
        string alias = aliases[i];
        if (zend_register_class_alias_ex(alias.c_str(), alias.length(), ce) < 0)
        {
            return false;
        }
    }
    activated = true;
    return true;
}

}
