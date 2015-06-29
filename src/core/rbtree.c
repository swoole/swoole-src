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
#include "rbtree.h"

static inline void swRbtree_left_rotate(swRbtree_node **root, swRbtree_node *sentinel, swRbtree_node *node);
static inline void swRbtree_right_rotate(swRbtree_node **root, swRbtree_node *sentinel, swRbtree_node *node);
static inline void swRbtree_insert_value(swRbtree_node *temp, swRbtree_node *node, swRbtree_node *sentinel);

void swRbtree_insert_value(swRbtree_node *temp, swRbtree_node *node, swRbtree_node *sentinel)
{
    swRbtree_node **p;
    while (1)
    {
        p = (node->key < temp->key) ? &temp->left : &temp->right;
        if (*p == sentinel)
        {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    swRbtree_red(node);
}

void swRbtree_insert(swRbtree *tree, uint32_t key, void *value)
{
    swRbtree_node **root, *temp, *sentinel;

    root = (swRbtree_node **) &tree->root;
    sentinel = tree->sentinel;

    swRbtree_node *node = (swRbtree_node *) malloc(sizeof(swRbtree_node));

    node->value = value;
    node->key = key;
    if (*root == sentinel)
    {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        swRbtree_black(node);
        *root = node;
        return;
    }

    swRbtree_insert_value(*root, node, sentinel);

    /* re-balance tree */

    while (node != *root && swRbtree_is_red(node->parent))
    {
        if (node->parent == node->parent->parent->left)
        {
            temp = node->parent->parent->right;
            if (swRbtree_is_red(temp))
            {
                swRbtree_black(node->parent);
                swRbtree_black(temp);
                swRbtree_red(node->parent->parent);
                node = node->parent->parent;
            }
            else
            {
                if (node == node->parent->right)
                {
                    node = node->parent;
                    swRbtree_left_rotate(root, sentinel, node);
                }

                swRbtree_black(node->parent);
                swRbtree_red(node->parent->parent);
                swRbtree_right_rotate(root, sentinel, node->parent->parent);
            }
        }
        else
        {
            temp = node->parent->parent->left;

            if (swRbtree_is_red(temp))
            {
                swRbtree_black(node->parent);
                swRbtree_black(temp);
                swRbtree_red(node->parent->parent);
                node = node->parent->parent;
            }
            else
            {
                if (node == node->parent->left)
                {
                    node = node->parent;
                    swRbtree_right_rotate(root, sentinel, node);
                }

                swRbtree_black(node->parent);
                swRbtree_red(node->parent->parent);
                swRbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }
    swRbtree_black(*root);
}

void swRbtree_delete(swRbtree *tree, uint32_t key)
{
    uint32_t red;
    swRbtree_node find_node;
    swRbtree_node **root, *sentinel, *subst, *temp, *w;
    swRbtree_node *node = &find_node;
    node->key = key;

    root = (swRbtree_node **) &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel)
    {
        temp = node->right;
        subst = node;
    }
    else if (node->right == sentinel)
    {
        temp = node->left;
        subst = node;
    }
    else
    {
        subst = swRbtree_min(node->right, sentinel);

        if (subst->left != sentinel)
        {
            temp = subst->left;
        }
        else
        {
            temp = subst->right;
        }
    }

    if (subst == *root)
    {
        *root = temp;
        swRbtree_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = swRbtree_is_red(subst);

    if (subst == subst->parent->left)
    {
        subst->parent->left = temp;
    }
    else
    {
        subst->parent->right = temp;
    }

    if (subst == node)
    {
        temp->parent = subst->parent;
    }
    else
    {
        if (subst->parent == node)
        {
            temp->parent = subst;
        }
        else
        {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        swRbtree_copy_color(subst, node);

        if (node == *root)
        {
            *root = subst;
        }
        else
        {
            if (node == node->parent->left)
            {
                node->parent->left = subst;
            }
            else
            {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel)
        {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel)
        {
            subst->right->parent = subst;
        }
    }

    if (red)
    {
        return;
    }

    /* a delete fixup */

    while (temp != *root && swRbtree_is_black(temp))
    {
        if (temp == temp->parent->left)
        {
            w = temp->parent->right;

            if (swRbtree_is_red(w))
            {
                swRbtree_black(w);
                swRbtree_red(temp->parent);
                swRbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (swRbtree_is_black(w->left) && swRbtree_is_black(w->right))
            {
                swRbtree_red(w);
                temp = temp->parent;
            }
            else
            {
                if (swRbtree_is_black(w->right))
                {
                    swRbtree_black(w->left);
                    swRbtree_red(w);
                    swRbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                swRbtree_copy_color(w, temp->parent);
                swRbtree_black(temp->parent);
                swRbtree_black(w->right);
                swRbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
        else
        {
            w = temp->parent->left;

            if (swRbtree_is_red(w))
            {
                swRbtree_black(w);
                swRbtree_red(temp->parent);
                swRbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (swRbtree_is_black(w->left) && swRbtree_is_black(w->right))
            {
                swRbtree_red(w);
                temp = temp->parent;
            }
            else
            {
                if (swRbtree_is_black(w->left))
                {
                    swRbtree_black(w->right);
                    swRbtree_red(w);
                    swRbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                swRbtree_copy_color(w, temp->parent);
                swRbtree_black(temp->parent);
                swRbtree_black(w->left);
                swRbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }
    swRbtree_black(temp);
}

static inline void swRbtree_left_rotate(swRbtree_node **root, swRbtree_node *sentinel, swRbtree_node *node)
{
    swRbtree_node *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel)
    {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root)
    {
        *root = temp;

    }
    else if (node == node->parent->left)
    {
        node->parent->left = temp;

    }
    else
    {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}

static inline void swRbtree_right_rotate(swRbtree_node **root, swRbtree_node *sentinel, swRbtree_node *node)
{
    swRbtree_node *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel)
    {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root)
    {
        *root = temp;
    }
    else if (node == node->parent->right)
    {
        node->parent->right = temp;
    }
    else
    {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}

void *swRbtree_find(swRbtree *tree, uint32_t key)
{
    swRbtree_node *tmp = tree->root;
    swRbtree_node *sentinel = tree->sentinel;
    while (tmp != sentinel)
    {
        if (key != tmp->key)
        {
            tmp = (key < tmp->key) ? tmp->left : tmp->right;
            continue;
        }
        return tmp->value;
    }
    return NULL;
}

swRbtree* swRbtree_new()
{
    swRbtree *rbtree = sw_malloc(sizeof(swRbtree));
    swRbtree_node *sentinel = sw_malloc(sizeof(swRbtree_node));

    sentinel->color = 0;
    rbtree->root = sentinel;
    rbtree->sentinel = sentinel;
    return rbtree;
}

void swRbtree_free(swRbtree* rbtree)
{
    sw_free(rbtree->root);
    sw_free(rbtree);
}
