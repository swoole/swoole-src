#include "test_core.h"
#include "swoole_heap.h"
#include <map>

typedef struct node_t {
    int pri;
    int val;
} node_t;

#define SIZE 100

TEST(heap, random) {
    node_t *ns;
    node_t *n;
    swoole::Heap pq(SIZE, swoole::Heap::MAX_HEAP);
    std::map<int, int> _map;
    ASSERT_EQ(pq.peek(), nullptr);

    int i;
    for (i = 0; i < SIZE * 2 - 1; i++) {
        int pri = swoole_system_random(10000, 99999);
        ns = (node_t *) malloc(sizeof(node_t));
        ns->val = i;
        ns->pri = pri;
        pq.push(pri, ns);
        _map[i] = pri;

        if (0 == i) {
            pq.print(); // print once
        }
    }

    n = (node_t *) pq.peek();
    ASSERT_EQ(_map[n->val], n->pri);
    while ((n = (node_t *) pq.pop())) {
        ASSERT_EQ(_map[n->val], n->pri);
        free(n);
    }
}
