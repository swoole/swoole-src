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
#include "uthash.h"
#include "hash.h"

typedef struct swHashMap_node
{
    uint64_t key_int;
    char *key_str;
    void *data;
    UT_hash_handle hh;
} swHashMap_node;

static int swHashMap_node_delete(swHashMap_node *root, swHashMap_node *del_node);

static sw_inline void swHashMap_node_dtor(swHashMap *hmap, swHashMap_node *node)
{
    if (hmap->dtor)
    {
        hmap->dtor(node->data);
    }
}

static sw_inline void swHashMap_node_free(swHashMap *hmap, swHashMap_node *node)
{
    swHashMap_node_dtor(hmap, node);
    sw_free(node->key_str);
    sw_free(node);
}

static sw_inline int swHashMap_node_add(swHashMap_node *root, swHashMap_node *add)
{
    unsigned _ha_bkt;
    add->hh.next = NULL;
    add->hh.key = add->key_str;
    add->hh.keylen = add->key_int;

    root->hh.tbl->tail->next = add;
    add->hh.prev = ELMT_FROM_HH(root->hh.tbl, root->hh.tbl->tail);
    root->hh.tbl->tail = &(add->hh);

    root->hh.tbl->num_items++;
    add->hh.tbl = root->hh.tbl;
    add->hh.hashv = swoole_hash_jenkins(add->key_str, add->key_int);
    _ha_bkt = add->hh.hashv & (root->hh.tbl->num_buckets - 1);

    HASH_ADD_TO_BKT(root->hh.tbl->buckets[_ha_bkt], &add->hh);

    return SW_OK;
}

static sw_inline swHashMap_node* swHashMap_node_each(swHashMap* hmap)
{
    swHashMap_node *iterator = hmap->iterator;
    swHashMap_node *tmp;

    if (hmap->root->hh.tbl->num_items == 0)
    {
        return NULL;
    }
    if (iterator == NULL)
    {
        iterator = hmap->root;
    }
    tmp = iterator->hh.next;
    if (tmp)
    {
        hmap->iterator = tmp;
        return tmp;
    }
    else
    {
        hmap->iterator = NULL;
        return NULL;
    }
}

swHashMap* swHashMap_new(uint32_t bucket_num, swHashMap_dtor dtor)
{
    swHashMap *hmap = sw_malloc(sizeof(swHashMap));
    if (!hmap)
    {
        swWarn("malloc[1] failed.");
        return NULL;
    }
    swHashMap_node *root = sw_malloc(sizeof(swHashMap_node));
    if (!root)
    {
        swWarn("malloc[2] failed.");
        sw_free(hmap);
        return NULL;
    }

    bzero(hmap, sizeof(swHashMap));
    hmap->root = root;

    bzero(root, sizeof(swHashMap_node));

    root->hh.tbl = (UT_hash_table*) sw_malloc(sizeof(UT_hash_table));
    if (!(root->hh.tbl))
    {
        swWarn("malloc for table failed.");
        sw_free(hmap);
        return NULL;
    }

    memset(root->hh.tbl, 0, sizeof(UT_hash_table));
    root->hh.tbl->tail = &(root->hh);
    root->hh.tbl->num_buckets = SW_HASHMAP_INIT_BUCKET_N;
    root->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;
    root->hh.tbl->hho = (char*) (&root->hh) - (char*) root;
    root->hh.tbl->buckets = (UT_hash_bucket*) sw_malloc(SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
    if (!root->hh.tbl->buckets)
    {
        swWarn("malloc for buckets failed.");
        sw_free(hmap);
        return NULL;
    }
    memset(root->hh.tbl->buckets, 0, SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
    root->hh.tbl->signature = HASH_SIGNATURE;

    hmap->dtor = dtor;

    return hmap;
}

int swHashMap_add(swHashMap* hmap, char *key, uint16_t key_len, void *data)
{
    swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
    if (node == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    bzero(node, sizeof(swHashMap_node));
    swHashMap_node *root = hmap->root;
    node->key_str = strndup(key, key_len);
    node->key_int = key_len;
    node->data = data;
    return swHashMap_node_add(root, node);
}

void swHashMap_add_int(swHashMap *hmap, uint64_t key, void *data)
{
    swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
    swHashMap_node *root = hmap->root;
    if (node == NULL)
    {
        swWarn("malloc failed");
        return;
    }
    node->key_int = key;
    node->data = data;
    node->key_str = NULL;
    HASH_ADD_INT(root, key_int, node);
}

static sw_inline swHashMap_node *swHashMap_node_find(swHashMap_node *root, char *key_str, uint16_t key_len)
{
    swHashMap_node *out;
    unsigned bucket, hash;
    out = NULL;
    if (root)
    {
        hash = swoole_hash_jenkins(key_str, key_len);
        bucket = hash & (root->hh.tbl->num_buckets - 1);
        HASH_FIND_IN_BKT(root->hh.tbl, hh, (root)->hh.tbl->buckets[bucket], key_str, key_len, out);
    }
    return out;
}

static int swHashMap_node_delete(swHashMap_node *root, swHashMap_node *del_node)
{
    unsigned bucket;
    struct UT_hash_handle *_hd_hh_del;

    if ((del_node->hh.prev == NULL) && (del_node->hh.next == NULL))
    {
        sw_free(root->hh.tbl->buckets);
        sw_free(root->hh.tbl);
    }
    else
    {
        _hd_hh_del = &(del_node->hh);
        if (del_node == ELMT_FROM_HH(root->hh.tbl, root->hh.tbl->tail))
        {
            root->hh.tbl->tail = (UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + root->hh.tbl->hho);
        }
        if (del_node->hh.prev)
        {
            ((UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + root->hh.tbl->hho))->next = del_node->hh.next;
        }
        else
        {
            DECLTYPE_ASSIGN(root, del_node->hh.next);
        }
        if (_hd_hh_del->next)
        {
            ((UT_hash_handle*) ((ptrdiff_t) _hd_hh_del->next + root->hh.tbl->hho))->prev = _hd_hh_del->prev;
        }
        HASH_TO_BKT(_hd_hh_del->hashv, root->hh.tbl->num_buckets, bucket);
        HASH_DEL_IN_BKT(hh, root->hh.tbl->buckets[bucket], _hd_hh_del);
        root->hh.tbl->num_items--;
    }
    return SW_OK;
}

void* swHashMap_find(swHashMap* hmap, char *key, uint16_t key_len)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *ret = swHashMap_node_find(root, key, key_len);
    if (ret == NULL)
    {
        return NULL;
    }
    return ret->data;
}

void* swHashMap_find_int(swHashMap* hmap, uint64_t key)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;
    HASH_FIND_INT(root, &key, ret);
    if (ret == NULL)
    {
        return NULL;
    }
    return ret->data;
}

int swHashMap_update(swHashMap* hmap, char *key, uint16_t key_len, void *data)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *node = swHashMap_node_find(root, key, key_len);
    if (node == NULL)
    {
        return SW_ERR;
    }
    swHashMap_node_dtor(hmap, node);
    node->data = data;
    return SW_OK;
}

void swHashMap_update_int(swHashMap* hmap, uint64_t key, void *data)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;
    HASH_FIND_INT(root, &key, ret);
    if (ret == NULL)
    {
        return;
    }
    swHashMap_node_dtor(hmap, ret);
    ret->data = data;
}

int swHashMap_del(swHashMap* hmap, char *key, uint16_t key_len)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *node = swHashMap_node_find(root, key, key_len);
    if (node == NULL)
    {
        return SW_ERR;
    }
    swHashMap_node_delete(root, node);
    swHashMap_node_free(hmap, node);
    return SW_OK;
}

int swHashMap_del_int(swHashMap *hmap, uint64_t key)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;

    HASH_FIND_INT(root, &key, ret);
    if (ret == NULL)
    {
        return SW_ERR;
    }
    HASH_DEL(root, ret);
    swHashMap_node_free(hmap, ret);
    return SW_OK;
}

int swHashMap_move(swHashMap *hmap, char *old_key, uint16_t old_key_len, char *new_key, uint16_t new_key_len)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *node = swHashMap_node_find(root, old_key, old_key_len);
    if (node == NULL)
    {
        return SW_ERR;
    }
    swHashMap_node_delete(root, node);
    sw_strdup_free(node->key_str);
    node->key_str = strndup(new_key, new_key_len);
    node->key_int = new_key_len;
    return swHashMap_node_add(root, node);
}

int swHashMap_move_int(swHashMap *hmap, uint64_t old_key, uint64_t new_key)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;

    HASH_FIND_INT(root, &old_key, ret);
    if (ret == NULL)
    {
        return SW_ERR;
    }
    HASH_DEL(root, ret);

    ret->key_int = new_key;
    HASH_ADD_INT(root, key_int, ret);

    return SW_OK;
}

void* swHashMap_each(swHashMap* hmap, char **key)
{
    swHashMap_node *node = swHashMap_node_each(hmap);
    if (node)
    {
        *key = node->key_str;
        return node->data;
    }
    else
    {
        return NULL;
    }
}

void* swHashMap_each_int(swHashMap* hmap, uint64_t *key)
{
    swHashMap_node *node = swHashMap_node_each(hmap);
    if (node)
    {
        *key = node->key_int;
        return node->data;
    }
    else
    {
        return NULL;
    }
}

void swHashMap_free(swHashMap* hmap)
{
    swHashMap_node *find, *tmp = NULL;
    swHashMap_node *root = hmap->root;
    HASH_ITER(hh, root, find, tmp)
    {
        if (find == root) continue;
        swHashMap_node_delete(root, find);
        swHashMap_node_free(hmap, find);
    }

    sw_free(hmap->root->hh.tbl->buckets);
    sw_free(hmap->root->hh.tbl);
    sw_free(hmap->root);

    sw_free(hmap);
}

/* {{{  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 *
 *  First, the polynomial itself and its table of feedback terms.  The
 *  polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *
 *  Note that we take it "backwards" and put the highest-order term in
 *  the lowest-order bit.  The X^32 term is "implied"; the LSB is the
 *  X^31 term, etc.  The X^0 term (usually shown as "+1") results in
 *  the MSB being 1
 *
 *  Note that the usual hardware shift register implementation, which
 *  is what we're using (we're merely optimizing it by doing eight-bit
 *  chunks at a time) shifts bits into the lowest-order term.  In our
 *  implementation, that means shifting towards the right.  Why do we
 *  do it this way?  Because the calculated CRC must be transmitted in
 *  order from highest-order term to lowest-order term.  UARTs transmit
 *  characters in order from LSB to MSB.  By storing the CRC this way
 *  we hand it to the UART in the order low-byte to high-byte; the UART
 *  sends each low-bit to hight-bit; and the result is transmission bit
 *  by bit from highest- to lowest-order term without requiring any bit
 *  shuffling on our part.  Reception works similarly
 *
 *  The feedback terms table consists of 256, 32-bit entries.  Notes
 *
 *      The table can be generated at runtime if desired; code to do so
 *      is shown later.  It might not be obvious, but the feedback
 *      terms simply represent the results of eight shift/xor opera
 *      tions for all combinations of data and CRC register values
 *
 *      The values must be right-shifted by eight bits by the "updcrc
 *      logic; the shift must be unsigned (bring in zeroes).  On some
 *      hardware you could probably optimize the shift in assembler by
 *      using byte-swap instructions
 *      polynomial $edb88320
 *
 *
 * CRC32 code derived from work by Gary S. Brown.
 */

static unsigned int crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

static inline uint32_t crc32(char *buf, unsigned int size)
{
    const char *p;
    register int crc = 0;

    p = buf;
    while (size--)
    {
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ ~0U;
}

uint32_t swoole_crc32(char *data, uint32_t size)
{
    if (size < CRC_STRING_MAXLEN)
    {
        return crc32(data, size);
    }
    else
    {
        int i = 0;
        char crc_contents[CRC_STRING_MAXLEN];
        int head = CRC_STRING_MAXLEN >> 2;
        int tail = CRC_STRING_MAXLEN >> 4;
        int body = CRC_STRING_MAXLEN - head - tail;
        char *p = data + head;
        char *q = crc_contents + head;
        int step = (size - tail - head) / body;

        memcpy(crc_contents, data, head);
        for (; i < body; i++, q++, p += step)
        {
            *q = *p;
        }
        memcpy(q, p, tail);
        return crc32(crc_contents, CRC_STRING_MAXLEN);
    }
}
