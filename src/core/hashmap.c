#include "swoole.h"
#include "uthash.h"

#define SW_HASHMAP_KEY_LEN  128

typedef struct swHashMap_node
{
	int key_int;
	char *key_str;
	void *data;
	UT_hash_handle hh;
} swHashMap_node;

#define SWHASH_ROOT(hm) (swHashMap_node *)(hm->root)

void swHashMap_free(swHashMap* hm)
{
	swHashMap_node *root = SWHASH_ROOT(hm);
	swHashMap_node *cur, *tmp;
	HASH_ITER(hh, SWHASH_ROOT(hm), cur, tmp)
	{
		HASH_DEL(root, cur);
		sw_free(cur);
	}
}

void swHashMap_add(swHashMap* hm, char *key, void *data)
{
	swHashMap_node *node = sw_malloc(sizeof(swHashMap_node));
	swHashMap_node *root = SWHASH_ROOT(hm);
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_str = key;
	node->data = data;
	HASH_ADD_KEYPTR(hh, root, node->key_str, strnlen(node->key_str, SW_HASHMAP_KEY_LEN), node);
}

void swHashMap_add_int(swHashMap* hm, int key, void *data)
{
	swHashMap_node *node = (swHashMap_node *) sw_malloc(sizeof(swHashMap_node));
	swHashMap_node *root = SWHASH_ROOT(hm);
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_int = key;
	node->data = data;
	HASH_ADD_INT(root, key_int, node);
}

void* swHashMap_find(swHashMap* hm, char *key)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_STR(root, key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void* swHashMap_find_int(swHashMap* hm, int key)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_INT(root, &key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void swHashMap_update(swHashMap* hm, char *key, void *data)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_STR(root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_update_int(swHashMap* hm, int key, void *data)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_INT(root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_del(swHashMap* hm, char *key)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_STR(root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(root, ret);
}

void swHashMap_del_int(swHashMap* hm, int key)
{
	swHashMap_node *ret = NULL;
	swHashMap_node *root = SWHASH_ROOT(hm);
	HASH_FIND_INT(root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(root, ret);
}
