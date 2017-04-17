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

#ifndef __SW_HASHMAP_H
#define __SW_HASHMAP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*swHashMap_dtor)(void *data);

typedef struct
{
    struct swHashMap_node *root;
    struct swHashMap_node *iterator;
    swHashMap_dtor dtor;
} swHashMap;

swHashMap* swHashMap_new(uint32_t bucket_num, swHashMap_dtor dtor);
void swHashMap_free(swHashMap *hmap);

int swHashMap_add(swHashMap *hmap, char *key, uint16_t key_len, void *data);
void swHashMap_add_int(swHashMap *hmap, uint64_t key, void *data);
void* swHashMap_find(swHashMap *hmap, char *key, uint16_t key_len);
void* swHashMap_find_int(swHashMap *hmap, uint64_t key);
void swHashMap_update_int(swHashMap *hmap, uint64_t key, void *data);
int swHashMap_update(swHashMap *hmap, char *key, uint16_t key_len, void *data);
int swHashMap_del(swHashMap *hmap, char *key, uint16_t key_len);
int swHashMap_del_int(swHashMap *hmap, uint64_t key);
int swHashMap_move(swHashMap *hmap, char *old_key, uint16_t old_key_len, char *new_key, uint16_t new_key_len);
int swHashMap_move_int(swHashMap *hmap, uint64_t old_key, uint64_t new_key);
void* swHashMap_each(swHashMap* hmap, char **key);
void* swHashMap_each_int(swHashMap* hmap, uint64_t *key);
#define swHashMap_each_reset(hmap)    (hmap->iterator = NULL)

#ifdef __cplusplus
}
#endif

#endif
