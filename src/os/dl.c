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

#include "swoole.h"
#include "module.h"
#include <dlfcn.h>

#define SW_MODULE_INIT_FUNC    "swModule_init"

swModule* swModule_load(char *so_file)
{
    int (*init_func)(swModule*);
    void *handle = dlopen(so_file, RTLD_LAZY);

    if (!handle)
    {
        swWarn("dlopen() failed. Error: %s", dlerror());
        return NULL;
    }
    //malloc
    swModule *module = (swModule *) sw_malloc(sizeof(swModule));
    if (module == NULL)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_MALLOC_FAIL, "malloc failed.");
        dlclose(handle);
        return NULL;
    }
    //get init function
    init_func = (int (*)(swModule*)) dlsym(handle, SW_MODULE_INIT_FUNC);
    char *error = dlerror();
    if (error != NULL)
    {
        swWarn("dlsym() failed. Error: %s", error);
        sw_free(module);
        dlclose(handle);
        return NULL;
    }
    module->file = strdup(so_file);
    //create function hashmap
    module->functions = swHashMap_new(64, NULL);
    if (module->functions == NULL)
    {
        sw_free(module);
        dlclose(handle);
        return NULL;
    }
    //init module
    if ((*init_func)(module) < 0)
    {
        sw_free(module);
        dlclose(handle);
        return NULL;
    }
    module->handle = handle;
    return module;
}

int swModule_register_function(swModule *module, const char *name, swModule_function func)
{
    return swHashMap_add(module->functions, (char *) name, strlen(name), (void *) func);
}

int swModule_register_global_function(const char *name, void* func)
{
    if (SwooleG.functions == NULL)
    {
        SwooleG.functions = swHashMap_new(64, NULL);
        if (SwooleG.functions == NULL)
        {
            return SW_ERR;
        }
    }
    if (swHashMap_find(SwooleG.functions, (char *) name, strlen(name)) != NULL)
    {
        swWarn("Function '%s' already exists.", name);
        return SW_ERR;
    }
    return swHashMap_add(SwooleG.functions, (char *) name, strlen(name), func);
}

void* swModule_get_global_function(char *name, uint32_t length)
{
    if (!SwooleG.functions)
    {
        return NULL;
    }
    return swHashMap_find(SwooleG.functions, name, length);
}
