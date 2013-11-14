#include "swoole.h"

void swHashMap_free(swHashMap* hm)
{
	swHashMap_node *cur, *tmp;
	HASH_ITER(hh, hm->root, cur, tmp)
	{
		HASH_DEL(hm->root, cur);
		sw_free(cur);
	}
}

void swHashMap_add(swHashMap* hm, char *key, void *data)
{
	swHashMap_node *node = sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_str = key;
	node->data = data;
	HASH_ADD_KEYPTR(hh, hm->root, node->key_str, strnlen(node->key_str, SW_HASHMAP_KEY_LEN), node);
}

void swHashMap_add_int(swHashMap* hm, int key, void *data)
{
	swHashMap_node *node = (swHashMap_node *) sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_int = key;
	node->data = data;
	HASH_ADD_INT(hm->root, key_int, node);
}

void* swHashMap_find(swHashMap* hm, char *key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(hm->root, key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void* swHashMap_find_int(swHashMap* hm, int key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(hm->root, &key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void swHashMap_update(swHashMap* hm, char *key, void *data)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(hm->root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_update_int(swHashMap* hm, int key, void *data)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(hm->root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_del(swHashMap* hm, char *key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(hm->root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(hm->root, ret);
}

void swHashMap_del_int(swHashMap* hm, int key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(hm->root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(hm->root, ret);
}
