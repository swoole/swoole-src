#ifndef __SW_HASHMAP_H
#define __SW_HASHMAP_H

typedef struct swHashMap_node* swHashMap;

void swHashMap_free(swHashMap *hm);
int swHashMap_add(swHashMap *hm, char *key, uint16_t key_len, void *data);
void swHashMap_add_int(swHashMap *hm, uint64_t key, void *data);
void* swHashMap_find(swHashMap *hm, char *key, uint16_t key_len);
void* swHashMap_find_int(swHashMap *hm, uint64_t key);
void swHashMap_update_int(swHashMap *hm, uint64_t key, void *data);
int swHashMap_update(swHashMap *hm, char *key, uint16_t key_len, void *data);
int swHashMap_del(swHashMap *hm, char *key, uint16_t key_len);
void swHashMap_del_int(swHashMap *hm, uint64_t key);
SWINLINE void* swHashMap_foreach(swHashMap* root, char **key, void **data, swHashMap head);
void* swHashMap_foreach_int(swHashMap* root, uint64_t *key, void **data, swHashMap head);
void swHashMap_destory(swHashMap* root);

#endif
