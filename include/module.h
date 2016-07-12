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

typedef struct _swModule
{
    char *name;
    void (*test)(void);
    int (*beforeDispatch)(struct _swModule*, swServer *, swEventData *data);
    int (*beforeReceive)(struct _swModule*, swServer *, swEventData *data);
    int (*shutdown)(struct _swModule*);
} swModule;

int swModule_load(char *so_file);

#endif /* SW_MODULE_H_ */
