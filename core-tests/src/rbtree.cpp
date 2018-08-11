#include "tests.h"
#include "rbtree.h"
#include <set>

TEST(rbtree, insert)
{
    swRbtree *tree = swRbtree_new();
    int i;
    std::set<uint32_t> lists;

    for (i = 1; i < 20000; i++)
    {
        uint32_t key = i * 37;
        swRbtree_insert(tree, key, (void *) (long) (i * 8));
    }

    for (i = 1; i < 1024; i++)
    {
        uint32_t key = ((rand() % 19999) + 1) * 37;
        int ret = (int) (long) swRbtree_find(tree, key);
        ASSERT_GT(ret, 0);
        lists.insert(key);
    }

    for (i = 1; i < 1024; i++)
    {
        uint32_t key = (rand() % (20000 * 37));
        if (key % 37 == 0)
        {
            continue;
        }
        int ret = (int) (long) swRbtree_find(tree, key);
        ASSERT_EQ(ret, 0);
    }

    for (auto i = lists.begin(); i != lists.end(); i++)
    {
        int ret = swRbtree_delete(tree, *i);
        ASSERT_EQ(ret, 0);
    }

    for (auto i = lists.begin(); i != lists.end(); i++)
    {
        int ret = (int) (long) swRbtree_find(tree, *i);
        ASSERT_EQ(ret, 0);
    }
}
