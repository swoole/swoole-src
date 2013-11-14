#ifndef __SW_HASHMAP_H
#define __SW_HASHMAP_H

#include "hashtable.h"

#define SW_HASHMAP_KEY_LEN  128

typedef struct swHashMap_node
{
	int key_int;
	char *key_str;
	void *data;
	UT_hash_handle hh;
} swHashMap_node;

typedef struct _swHashMap
{
	swHashMap_node *root;

} swHashMap;

void swHashMap_free(swHashMap* hm);
void swHashMap_add(swHashMap* hm, char *key, void *data);
void swHashMap_add_int(swHashMap* hm, int key, void *data);
void* swHashMap_find(swHashMap* hm, char *key);
void* swHashMap_find_int(swHashMap* hm, int key);
void swHashMap_update_int(swHashMap* hm, int key, void *data);
void swHashMap_update(swHashMap* hm, char *key, void *data);
void swHashMap_del(swHashMap* hm, char *key);
void swHashMap_del_int(swHashMap* hm, int key);

#endif
