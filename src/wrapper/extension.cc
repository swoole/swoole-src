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

Extension::Extension(const char *name, const char *version)
{
    module.name = name;
    module.version = version;
    this->name = name;
    this->version = version;
    _name_to_extension[name] = this;
}

bool Extension::require(const char *name, const char *version)
{
    this->checkStartupStatus(BEFORE_START, __func__);
    if (module.deps == NULL)
    {
        module.deps = (const zend_module_dep*) calloc(16, sizeof(zend_module_dep));
        if (module.deps == NULL)
        {
            return false;
        }
        deps_array_size = 16;
    }
    else if (deps_count + 1 == deps_array_size)
    {
        deps_array_size *= 2;
        void* new_array = realloc((void*) module.deps, deps_array_size * sizeof(zend_module_dep));
        if (new_array == NULL)
        {
            return false;
        }
        module.deps = (const zend_module_dep*) new_array;
    }

    zend_module_dep *deps_array = (zend_module_dep *) module.deps;
    deps_array[deps_count].name = name;
    deps_array[deps_count].rel = NULL;
    deps_array[deps_count].version = version;
    deps_array[deps_count].type = MODULE_DEP_REQUIRED;

    deps_array[deps_count + 1].name = NULL;
    deps_array[deps_count + 1].rel = NULL;
    deps_array[deps_count + 1].version = NULL;
    deps_array[deps_count + 1].type = 0;

    deps_count++;
    return true;
}

bool Extension::registerClass(Class *c)
{
    this->checkStartupStatus(AFTER_START, __func__);
    c->activate();
    class_map[c->getName()] = c;
    return true;
}

bool Extension::registerInterface(Interface *i)
{
    this->checkStartupStatus(AFTER_START, __func__);
    i->activate();
    interface_map[i->getName()] = i;
    return true;
}

bool Extension::registerResource(const char *name, resource_dtor dtor)
{
    this->checkStartupStatus(AFTER_START, __func__);
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

void Extension::registerConstant(const char *name, long v)
{
    zend_register_long_constant(name, strlen(name), v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, int v)
{
    zend_register_long_constant(name, strlen(name), v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, bool v)
{
    zend_register_bool_constant(name, strlen(name), v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, const char *v)
{
    zend_register_string_constant(name, strlen(name), (char *) v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, const char *v, size_t len)
{
    zend_register_stringl_constant(name, strlen(name), (char *) v, len, CONST_CS | CONST_PERSISTENT,
            module.module_number);
}

void Extension::registerConstant(const char *name, double v)
{
    zend_register_double_constant(name, strlen(name), v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, float v)
{
    zend_register_double_constant(name, strlen(name), v, CONST_CS | CONST_PERSISTENT, module.module_number);
}

void Extension::registerConstant(const char *name, string &v)
{
    zend_register_stringl_constant(name, strlen(name), (char *) v.c_str(), v.length(), CONST_CS | CONST_PERSISTENT, module.module_number);
}

bool Extension::registerFunction(const char *name, function_t func, ArgInfo *info)
{
    this->checkStartupStatus(BEFORE_START, __func__);
    if (module.functions == NULL)
    {
        module.functions = (const zend_function_entry*) calloc(16, sizeof(zend_function_entry));
        if (module.functions == NULL)
        {
            return false;
        }
        function_array_size = 16;
    }
    else if (function_count + 1 == function_array_size)
    {
        function_array_size *= 2;
        void* new_array = realloc((void*) module.functions, function_array_size * sizeof(zend_function_entry));
        if (new_array == NULL)
        {
            return false;
        }
        module.functions = (const zend_function_entry*) new_array;
    }

    zend_function_entry *function_array = (zend_function_entry *) module.functions;
    function_array[function_count].fname = name;

    function_array[function_count].handler = _exec_function;
    function_array[function_count].arg_info = NULL;
    function_array[function_count].num_args = 0;
    function_array[function_count].flags = 0;
    if (info)
    {
        function_array[function_count].arg_info = info->get();
        function_array[function_count].num_args = info->count();
    }
    else
    {
        function_array[function_count].arg_info = NULL;
        function_array[function_count].num_args = 0;
    }

    function_array[function_count + 1].fname = NULL;
    function_array[function_count + 1].handler = NULL;
    function_array[function_count + 1].flags = 0;

    function_map[name] = func;

    function_count++;
    return true;
}

void Extension::registerIniEntries(int module_number) {
    if (!ini_entries.size()) {
        return;
    }

    zend_ini_entry_def* entry_defs = new zend_ini_entry_def[ini_entries.size() + 1];

    for (auto i = 0; i < ini_entries.size(); ++i) {
        IniEntry& entry = ini_entries[i];
        zend_ini_entry_def def = {
                entry.name.c_str(), // name
                NULL,   // on_modify
                NULL,   // mh_arg1
                NULL,   // mh_arg2
                NULL,   // mh_arg3
                entry.default_value.c_str(), // value
                NULL,   // displayer
                entry.modifiable, // modifiable
                (uint)entry.name.size(), // name_length
                (uint)entry.default_value.size(), // value_length
        };
        entry_defs[i] = def;
    }
    memset(entry_defs + ini_entries.size(), 0, sizeof(*entry_defs));

    zend_register_ini_entries(entry_defs, module_number);
    delete []entry_defs;
}

void Extension::unregisterIniEntries(int module_number) {
    if (ini_entries.size()) {
        zend_unregister_ini_entries(module_number);
    }
}

}
