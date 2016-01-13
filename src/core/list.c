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

swLinkedList* swLinkedList_new(uint8_t type, swDestructor dtor)
{
    swLinkedList *q = sw_malloc(sizeof(swLinkedList));
    if (q == NULL)
    {
        swWarn("malloc(%ld) failed.", sizeof(swLinkedList));
        return NULL;
    }
    bzero(q, sizeof(swLinkedList));
    q->type = type;
    q->dtor = dtor;
    return q;
}

int swLinkedList_append(swLinkedList *ll, void *data)
{
    swLinkedList_node *node = sw_malloc(sizeof(swLinkedList_node));
    if (node == NULL)
    {
        swWarn("malloc(%ld) failed.", sizeof(swLinkedList_node));
        return SW_ERR;
    }
    node->data = data;
    node->next = NULL;
    ll->num++;
    if (ll->tail)
    {
        ll->tail->next = node;
        node->prev = ll->tail;
        ll->tail = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        ll->head = node;
        ll->tail = node;
    }
    return SW_OK;
}

int swLinkedList_prepend(swLinkedList *ll, void *data)
{
    swLinkedList_node *node = sw_malloc(sizeof(swLinkedList_node));
    if (node == NULL)
    {
        swWarn("malloc(%ld) failed.", sizeof(swLinkedList_node));
        return SW_ERR;
    }
    node->data = data;
    node->prev = NULL;
    ll->num ++;
    if (ll->head)
    {
        ll->head->prev = node;
        node->next = ll->head;
        ll->head = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        ll->head = node;
        ll->tail = node;
    }
    return SW_OK;
}

void* swLinkedList_pop(swLinkedList *ll)
{
    if (ll->tail == NULL)
    {
        return NULL;
    }

    swLinkedList_node *node = ll->tail;
    if (node == ll->head)
    {
        ll->head = NULL;
        ll->tail = NULL;
    }
    else
    {
        swLinkedList_node *prev = ll->tail->prev;
        prev->next = NULL;
        ll->tail = prev;
    }
    ll->num--;
    void *data = node->data;
    sw_free(node);
    return data;
}

void swLinkedList_remove_node(swLinkedList *ll, swLinkedList_node *remove_node)
{
    swLinkedList_node *prev = remove_node->prev;
    swLinkedList_node *next = remove_node->next;

    if (remove_node == ll->head)
    {
        ll->head = next;
        if (next == NULL)
        {
            ll->tail = NULL;
        }
        else
        {
            next->prev = NULL;
        }
    }
    else if (remove_node == ll->tail)
    {
        ll->tail = prev;
        if (prev == NULL)
        {
            ll->head = NULL;
        }
        else
        {
            prev->next = NULL;
        }
    }
    else
    {
        next->prev = prev;
        prev->next = next;
    }
    ll->num--;
    sw_free(remove_node);
}

void* swLinkedList_shift(swLinkedList *ll)
{
    if (ll->head == NULL)
    {
        return NULL;
    }
    swLinkedList_node *node = ll->head;
    if (node == ll->tail)
    {
        ll->head = NULL;
        ll->tail = NULL;
    }
    else
    {
        swLinkedList_node *next = ll->head->next;
        next->prev = NULL;
        ll->head = next;
    }
    ll->num--;
    void *data = node->data;
    sw_free(node);
    return data;
}

void swLinkedList_free(swLinkedList *ll)
{
    swLinkedList_node *node = ll->head;
    swLinkedList_node *tmp;

    do
    {
        tmp = node->next;
        if (ll->dtor)
        {
            ll->dtor(node->data);
        }
        sw_free(node);
        node = tmp;
    } while (node);

    sw_free(ll);
}
