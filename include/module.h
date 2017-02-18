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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */
#ifndef SW_MODULE_H_
#define SW_MODULE_H_

#include "swoole.h"
#include "Server.h"
#include "Client.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _swModule
{
    void *handle;
    char *file;
    char *name;
    int (*beforeDispatch)(struct _swModule*, swServer *, swEventData *data);
    int (*beforeReceive)(struct _swModule*, swServer *, swEventData *data);
    int (*shutdown)(struct _swModule*);
} swModule;

swModule* swModule_load(char *so_file);
int swModule_register_global_function(const char *name, void* func);
void* swModule_get_global_function(char *name, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* SW_MODULE_H_ */
