#include "test_core.h"
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

    int i;
    for (i = 0; i < SIZE - 1; i++) {
        int pri = swoole_system_random(10000, 99999);
        ns = (node_t *) malloc(sizeof(node_t));
        ns->val = i;
        ns->pri = pri;
        pq.push(pri, ns);
        _map[i] = pri;
    }

    while ((n = (node_t *) pq.pop())) {
        ASSERT_EQ(_map[n->val], n->pri);
        free(n);
    }
}
