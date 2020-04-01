#include "swoole/swoole.h"
#include "swoole/heap.h"
#include <gtest/gtest.h>
#include <map>

typedef struct node_t
{
    int pri;
    int val;
} node_t;

#define SIZE    100

TEST(heap, random)
{
    swHeap *pq;
    node_t *ns;
    node_t *n;

    pq = swHeap_new(SIZE, SW_MAX_HEAP);
    ASSERT_NE(pq, nullptr);

    std::map<int, int> _map;

    int i;
    for (i = 0; i < SIZE - 1; i++)
    {
        int pri = swoole_system_random(10000, 99999);
        ns = (node_t*) malloc(sizeof(node_t));
        ns->val = i;
        ns->pri = pri;
        swHeap_push(pq, pri, ns);
        _map[i] = pri;
    }

    while ((n = (node_t*) swHeap_pop(pq)))
    {
        ASSERT_EQ(_map[n->val], n->pri);
        free(n);
    }

    swHeap_free(pq);
}
