#ifndef __SW_HASHMAP_H
#define __SW_HASHMAP_H

#include "hashtable.h"

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

#endif
