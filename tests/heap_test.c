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
#include "heap.h"
#include "tests.h"

typedef struct node_t
{
    int pri;
    int val;
} node_t;

swUnitTest(heap_test1)
{
    swHeap *pq;
    node_t *ns;
    node_t *n;

#define SIZE    100

    pq = swHeap_new(SIZE, SW_MAX_HEAP);
    if (!pq)
    {
        return 1;
    }

    int i;
    for (i = 0; i < SIZE - 1; i++)
    {
        int pri = swoole_system_random(10000, 99999);
        ns = malloc(sizeof(node_t));
        ns->val = i;
        ns->pri = pri;
        swHeap_push(pq, pri, ns);
    }

    //n = swHeap_peek(pq);
    //printf("peek: %d [%d]\n", n->pri, n->val);

    //swHeap_change_priority(pq, 8, &ns[4]);
    //swHeap_change_priority(pq, 7, &ns[2]);

    while ((n = swHeap_pop(pq)))
    {
        printf("pop: %d [%d]\n", n->pri, n->val);
        free(n);
    }

    swHeap_free(pq);
    free(ns);

    return 0;
}
