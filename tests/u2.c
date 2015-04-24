#include "swoole.h"
#include "tests.h"

typedef struct _test_node
{
    struct _test_node *next, *prev;
    void *data;
    int exectime;
} test_node;

static struct
{
    test_node *root;
} timer;

void list_add(int exectime);
void list_dump();

swUnitTest(list_test1)
{
    int i = 0;
    for (i = 0; i < 10000; i++)
    {
        list_add(swoole_system_random(10000, 99999));
    }
//    list_add(1200);
//    list_add(1800);
//    list_add(800);
//    list_add(900);
//    list_add(900);
//    list_add(200);
//    list_add(2000);
//    list_add(700);

    list_dump();
}

void list_dump()
{
    test_node *tmp = timer.root;
    printf("root=%d\n", tmp->exectime);

    while (tmp->next)
    {
        tmp = tmp->next;
        printf("node=%d\n", tmp->exectime);

    }
}

void list_add(int exectime)
{

    test_node *node = malloc(sizeof(test_node));
    bzero(node, sizeof(test_node));
    node->data = NULL;
    node->exectime = exectime;

    if (timer.root == NULL)
    {
        timer.root = node;
        return;
    }

    test_node *tmp = timer.root;
    while (1)
    {
        if (tmp->exectime >= node->exectime)
        {
            node->prev = tmp->prev;
            node->next = tmp;
            if (node->prev)
            {
                node->prev->next = node;
            }

            tmp->prev = node;

            if (tmp == timer.root)
            {
                timer.root = node;
            }
            break;
        }
        else if (tmp->next)
        {
            tmp = tmp->next;
        }
        else
        {
            tmp->next = node;
            node->prev = tmp;
            break;
        }
    }
}
