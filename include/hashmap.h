#ifndef __SW_HASHMAP_H
#define __SW_HASHMAP_H

typedef void swHashMap_dtor(void *data);

typedef struct
{
    struct swHashMap_node *root;
    struct swHashMap_node *iterator;
    swHashMap_dtor *dtor;
} swHashMap;

swHashMap* swHashMap_new(uint32_t bucket_num, swHashMap_dtor *dtor);
void swHashMap_free(swHashMap *hmap);

int swHashMap_add(swHashMap *hmap, char *key, uint16_t key_len, void *data);
void swHashMap_add_int(swHashMap *hmap, uint64_t key, void *data);
void* swHashMap_find(swHashMap *hmap, char *key, uint16_t key_len);
void* swHashMap_find_int(swHashMap *hmap, uint64_t key);
void swHashMap_update_int(swHashMap *hmap, uint64_t key, void *data);
int swHashMap_update(swHashMap *hmap, char *key, uint16_t key_len, void *data);
int swHashMap_del(swHashMap *hmap, char *key, uint16_t key_len);
void swHashMap_del_int(swHashMap *hmap, uint64_t key);
void* swHashMap_each(swHashMap* hmap, char **key);
void* swHashMap_each_int(swHashMap* hmap, uint64_t *key);
#define swHashMap_each_reset(hmap)    (hmap->iterator = NULL)

#endif
