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
#include <dlfcn.h>

#define SW_MODULE_INIT_FUNC    "swModule_init"

int swModule_load(char *so_file)
{
    swModule* (*init_func)(void);
    void *handle = dlopen(so_file, RTLD_LAZY);

    if (!handle)
    {
        swWarn("dlopen() failed. Error: %s", dlerror());
        return SW_ERR;
    }

    init_func = (swModule* (*)(void)) dlsym(handle, SW_MODULE_INIT_FUNC);

    char *error = dlerror();
    if (error != NULL)
    {
        swWarn("dlsym() failed. Error: %s", error);
        return SW_ERR;
    }

    swModule *module = (*init_func)();
    if (module == NULL)
    {
        swWarn("module init failed.");
        return SW_ERR;
    }
    printf("module_name=%s\n", module->name);
    module->test();
    return SW_OK;
}
