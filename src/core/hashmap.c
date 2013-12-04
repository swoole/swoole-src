#include "swoole.h"
#include "uthash.h"

#define SW_HASHMAP_KEY_LEN  128

typedef struct swHashMap_node
{
	uint64_t key_int;
	char *key_str;
	void *data;
	UT_hash_handle hh;
} swHashMap_node;

void swHashMap_free(swHashMap_node** root)
{
	swHashMap_node *cur, *tmp;
	HASH_ITER(hh, *root, cur, tmp)
	{
		HASH_DEL(*root, cur);
		sw_free(cur);
	}
}

void swHashMap_add(swHashMap_node** root, char *key, void *data)
{
	swHashMap_node *node = sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_str = strndup(key, SW_HASHMAP_KEY_LEN);
	node->data = data;
	HASH_ADD_KEYPTR(hh, *root, node->key_str, strlen(node->key_str), node);
}

void swHashMap_add_int(swHashMap_node** root, uint64_t key, void *data)
{
	swHashMap_node *node = (swHashMap_node *) sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("[swHashMap_insert] malloc fail");
		return;
	}
	node->key_int = key;
	node->data = data;
	HASH_ADD_INT(*root, key_int, node);
}

void* swHashMap_find(swHashMap_node** root, char *key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(*root, key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void* swHashMap_find_int(swHashMap_node** root, uint64_t key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(*root, &key, ret);
	if (ret == NULL)
	{
		return NULL;
	}
	return ret->data;
}

void swHashMap_update(swHashMap_node** root, char *key, void *data)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(*root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_update_int(swHashMap_node** root, uint64_t key, void *data)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(*root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	ret->data = data;
}

void swHashMap_del(swHashMap_node** root, char *key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_STR(*root, key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(*root, ret);
}

void* swHashMap_foreach(swHashMap_node** root, char **key, void **data, swHashMap_node *head)
{
	swHashMap_node *find = NULL, *tmp = NULL;
	if (head == NULL)
	{
		head = *root;
	}
	HASH_ITER(hh, head, find, tmp)
	{
		*key = find->key_str;
		*data = find->data;
		break;
	}
	return tmp;
}

void* swHashMap_foreach_int(swHashMap_node** root, uint64_t *key, void **data, swHashMap_node *head)
{
	swHashMap_node *find = NULL, *tmp = NULL;
	if (head == NULL)
	{
		head = *root;
	}
	*data = NULL;
	HASH_ITER(hh, head, find, tmp)
	{
		*key = find->key_int;
		*data = find->data;
		break;
	}
	return tmp;
}

void swHashMap_del_int(swHashMap_node** root, uint64_t key)
{
	swHashMap_node *ret = NULL;
	HASH_FIND_INT(*root, &key, ret);
	if (ret == NULL)
	{
		return;
	}
	HASH_DEL(*root, ret);
}

void swHashMap_destory(swHashMap_node** root)
{
	swHashMap_node *find, *tmp = NULL;
	HASH_ITER(hh, *root, find, tmp)
	{
		HASH_DELETE(hh, *root, find);
		free(find);
	}
}

