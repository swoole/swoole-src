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
#include "tests.h"
#include "uthash.h"

typedef struct
{
    swUnitTest_Func func;
    char *comment;
    int run_times;
    char *key;
} swHashTable_unitTest;

static swHashMap *utmap = NULL;

void _swUnitTest_setup(swUnitTest_Func func, char *func_name, int run_times, char *comment)
{
    if (!utmap)
    {
        utmap = swHashMap_new(32, free);
    }
    swHashTable_unitTest *u;
    u = (swHashTable_unitTest *) malloc(sizeof(swHashTable_unitTest));
    u->key = func_name;
    u->func = func;
    u->run_times = run_times;
    u->comment = comment;
    swHashMap_add(utmap, func_name, strlen(func_name), u);
}

int swUnitTest_run(swUnitTest *object)
{
    int max_len = 128;
    int argc = object->argc;
    char **argv = object->argv;
    int ret;
    char *key;

    swUnitTest_Func func;
    swHashTable_unitTest *tmp;

    int i = 0;

    if (argc < 2)
    {
        printf("Please enter %s unitTest_name\n", argv[0]);

        while (1)
        {
            tmp = swHashMap_each(utmap, &key);
            if (!tmp)
                break;
            printf("#%d.\t%s: %s\n", ++i, tmp->key, tmp->comment);
        }
        return 0;
    }

    do
    {
        tmp = swHashMap_each(utmap, &key);
        if (strncmp(argv[1], key, max_len) == 0)
        {
            func = tmp->func;
            printf("running\n");
            ret = func(object);
            break;
        }
    } while (tmp);

    printf("finish\n");
    return ret;
}

void p_str(void *str)
{
    printf("Str: %s|len=%ld\n", (char *) str, strlen((char *) str));
}
