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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "uthash.h"

typedef struct swHashMap_node
{
	uint64_t key_int;
	char *key_str;
	void *data;
	UT_hash_handle hh;
} swHashMap_node;

SWINLINE static int swHashMap_add_keyptr(swHashMap_node **root, swHashMap_node *add);
SWINLINE static uint64_t swHashMap_jenkins_hash(char *key, uint64_t keylen, uint32_t num_bkts);
SWINLINE static swHashMap_node *swHashMap_find_node(swHashMap_node *head, char *key_str, uint16_t key_len);
SWINLINE static int swHashMap_delete_node(swHashMap_node *head, swHashMap_node *del_node);

static int swHashMap_create(swHashMap_node *head);

void swHashMap_free(swHashMap_node** root)
{
	swHashMap_node *cur, *tmp;
	HASH_ITER(hh, *root, cur, tmp)
	{
		HASH_DEL(*root, cur);
		sw_free(cur);
	}
}

SWINLINE static uint64_t swHashMap_jenkins_hash(char *key, uint64_t keylen, uint32_t num_bkts)
{
	uint64_t hashv;
	do
	{
		unsigned _hj_i, _hj_j, _hj_k;
		unsigned char *_hj_key = (unsigned char*) (key);
		hashv = 0xfeedbeef;
		_hj_i = _hj_j = 0x9e3779b9;
		_hj_k = (unsigned) (keylen);

		while (_hj_k >= 12)
		{
			_hj_i += (_hj_key[0] + ((unsigned) _hj_key[1] << 8) + ((unsigned) _hj_key[2] << 16)
					+ ((unsigned) _hj_key[3] << 24));
			_hj_j += (_hj_key[4] + ((unsigned) _hj_key[5] << 8) + ((unsigned) _hj_key[6] << 16)
					+ ((unsigned) _hj_key[7] << 24));
			hashv += (_hj_key[8] + ((unsigned) _hj_key[9] << 8) + ((unsigned) _hj_key[10] << 16)
					+ ((unsigned) _hj_key[11] << 24));

			HASH_JEN_MIX(_hj_i, _hj_j, hashv);

			_hj_key += 12;
			_hj_k -= 12;
		}
		hashv += keylen;
		switch (_hj_k)
		{
		case 11:
			hashv += ((unsigned) _hj_key[10] << 24);
		case 10:
			hashv += ((unsigned) _hj_key[9] << 16);
		case 9:
			hashv += ((unsigned) _hj_key[8] << 8);
		case 8:
			_hj_j += ((unsigned) _hj_key[7] << 24);
		case 7:
			_hj_j += ((unsigned) _hj_key[6] << 16);
		case 6:
			_hj_j += ((unsigned) _hj_key[5] << 8);
		case 5:
			_hj_j += _hj_key[4];
		case 4:
			_hj_i += ((unsigned) _hj_key[3] << 24);
		case 3:
			_hj_i += ((unsigned) _hj_key[2] << 16);
		case 2:
			_hj_i += ((unsigned) _hj_key[1] << 8);
		case 1:
			_hj_i += _hj_key[0];
		}
		HASH_JEN_MIX(_hj_i, _hj_j, hashv);

	} while (0);
	return hashv;
}

SWINLINE static int swHashMap_add_keyptr(swHashMap_node **root, swHashMap_node *add)
{
	unsigned _ha_bkt;
	add->hh.next = NULL;
	add->hh.key = add->key_str;
	add->hh.keylen = add->key_int;

	if (!(*root))
	{
		(*root) = add;
		(*root)->hh.prev = NULL;
		if (swHashMap_create(*root) < 0)
		{
			return SW_ERR;
		}
	}
	else
	{
		(*root)->hh.tbl->tail->next = add;
		add->hh.prev = ELMT_FROM_HH((*root)->hh.tbl, (*root)->hh.tbl->tail);
		(*root)->hh.tbl->tail = &(add->hh);
	}

	(*root)->hh.tbl->num_items++;
	add->hh.tbl = (*root)->hh.tbl;
	add->hh.hashv = swHashMap_jenkins_hash(add->key_str, add->key_int, (*root)->hh.tbl->num_buckets);
	_ha_bkt = add->hh.hashv & ((*root)->hh.tbl->num_buckets - 1);
	HASH_ADD_TO_BKT((*root)->hh.tbl->buckets[_ha_bkt], &add->hh);

	return SW_OK;
}

static int swHashMap_create(swHashMap_node *head)
{
	head->hh.tbl = (UT_hash_table*) sw_malloc(sizeof(UT_hash_table));
	if (!(head->hh.tbl))
	{
		swWarn("malloc for table failed.");
		return SW_ERR;
	}

	memset(head->hh.tbl, 0, sizeof(UT_hash_table));
	head->hh.tbl->tail = &(head->hh);
	head->hh.tbl->num_buckets = SW_HASHMAP_INIT_BUCKET_N;
	head->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;
	head->hh.tbl->hho = (char*) (&head->hh) - (char*) head;
	head->hh.tbl->buckets = (UT_hash_bucket*) sw_malloc(SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
	if (!head->hh.tbl->buckets)
	{
		swWarn("malloc for buckets failed.");
		return SW_ERR;
	}
	memset(head->hh.tbl->buckets, 0, SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
	head->hh.tbl->signature = HASH_SIGNATURE;

	return SW_OK;
}

int swHashMap_add(swHashMap_node** root, char *key, uint16_t key_len, void *data)
{
	swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("malloc fail");
		return SW_ERR;
	}
	node->key_str = strndup(key, key_len);
	node->key_int = key_len;
	node->data = data;
	return swHashMap_add_keyptr(root, node);
}

void swHashMap_add_int(swHashMap_node** root, uint64_t key, void *data)
{
	swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
	if (node == NULL)
	{
		swWarn("malloc fail");
		return;
	}
	node->key_int = key;
	node->data = data;
	HASH_ADD_INT(*root, key_int, node);
}

SWINLINE static swHashMap_node *swHashMap_find_node(swHashMap_node *head, char *key_str, uint16_t key_len)
{
	swHashMap_node *out;
	unsigned bucket, hash;
	out = NULL;
	if (head)
	{
		hash = swHashMap_jenkins_hash(key_str, key_len, head->hh.tbl->num_buckets);
		bucket = hash & (head->hh.tbl->num_buckets - 1);
		HASH_FIND_IN_BKT(head->hh.tbl, hh, (head)->hh.tbl->buckets[bucket], key_str, key_len, out);
	}
	return out;
}

static int swHashMap_delete_node(swHashMap_node *head, swHashMap_node *del_node)
{
	unsigned bucket;
	struct UT_hash_handle *_hd_hh_del;
	if ((del_node->hh.prev == NULL) && (del_node->hh.next == NULL))
	{
		sw_free(head->hh.tbl->buckets);
		sw_free(head->hh.tbl);
		head = NULL;
	}
	else
	{
		_hd_hh_del = &(del_node->hh);
		if (del_node == ELMT_FROM_HH(head->hh.tbl, head->hh.tbl->tail))
		{
			head->hh.tbl->tail = (UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + head->hh.tbl->hho);
		}
		if (del_node->hh.prev)
		{
			((UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + head->hh.tbl->hho))->next = del_node->hh.next;
		}
		else
		{
			DECLTYPE_ASSIGN(head, del_node->hh.next);
		}
		if (_hd_hh_del->next)
		{
			((UT_hash_handle*) ((ptrdiff_t) _hd_hh_del->next + head->hh.tbl->hho))->prev = _hd_hh_del->prev;
		}
		HASH_TO_BKT(_hd_hh_del->hashv, head->hh.tbl->num_buckets, bucket);
		HASH_DEL_IN_BKT(hh, head->hh.tbl->buckets[bucket], _hd_hh_del);
		head->hh.tbl->num_items--;
	}
	return SW_OK;
}

void* swHashMap_find(swHashMap_node** root, char *key, uint16_t key_len)
{
	swHashMap_node *ret = swHashMap_find_node(*root, key, key_len);
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

int swHashMap_update(swHashMap_node** root, char *key, uint16_t key_len, void *data)
{
	swHashMap_node *node = swHashMap_find_node(*root, key, key_len);
	if (node == NULL)
	{
		return SW_ERR;
	}
	node->data = data;
	return SW_OK;
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

int swHashMap_del(swHashMap_node** root, char *key, uint16_t key_len)
{
	swHashMap_node *node = swHashMap_find_node(*root, key, key_len);;
	if (node == NULL)
	{
		return SW_ERR;
	}
	swHashMap_delete_node(*root, node);
	sw_free(node->key_str);
	sw_free(node);
	return SW_OK;
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
	sw_free(ret);
}

SWINLINE void* swHashMap_foreach(swHashMap_node** root, char **key, void **data, swHashMap_node *head)
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

void swHashMap_destory(swHashMap_node** root)
{
	swHashMap_node *find, *tmp = NULL;
	HASH_ITER(hh, *root, find, tmp)
	{
		swHashMap_delete_node(*root, find);
		sw_free(find);
	}
}
