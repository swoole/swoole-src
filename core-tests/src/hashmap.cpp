#include "tests.h"

#include <map>
#include <unordered_map>

typedef struct
{
    int fd;
    int key;
} swFdInfo;

bool type_eof()
{
    char eof[] = SW_DATA_EOF;
    printf("SW_DATA_STREAM_EOF = %s\n", eof);
    return 0;
}

TEST(hashmap, string)
{
    swHashMap *hm = swHashMap_new(16, NULL);
    swHashMap_add(hm, (char *) SW_STRL("hello"), (void *) 199);
    swHashMap_add(hm, (char *) SW_STRL("swoole22"), (void *) 8877);
    swHashMap_add(hm, (char *) SW_STRL("hello2"), (void *) 200);
    swHashMap_add(hm, (char *) SW_STRL("willdel"), (void *) 888);
    swHashMap_add(hm, (char *) SW_STRL("willupadte"), (void *) 9999);
    swHashMap_add(hm, (char *) SW_STRL("hello3"), (void *) 78978);

    swHashMap_del(hm, (char *) SW_STRL("willdel"));
    swHashMap_update(hm, (char *) SW_STRL("willupadte"), (void *) (9999 * 5555));

    int ret1 = (int) (long) swHashMap_find(hm, (char *) SW_STRL("hello"));
    ASSERT_GT(ret1, 0);

    int ret2 = (int) (long) swHashMap_find(hm, (char *) SW_STRL("hello2"));
    ASSERT_GT(ret2, 0);

    int ret3 = (int) (long) swHashMap_find(hm, (char *) SW_STRL("notfound"));
    ASSERT_EQ(ret3, 0);

    char *key;
    int data;

    while (1)
    {
        data = (int) (long) swHashMap_each(hm, &key);
        if (!data)
        {
            break;
        }
    }
    swHashMap_free(hm);
}

#define  BUFSIZE 128
#define  MAP_SIZE  32
char data[BUFSIZE];

TEST(hashmap, integer)
{
    swHashMap *ht = swHashMap_new(16, free);
    swFdInfo *pkt, *tmp;
    int i;
    swFdInfo *lists[MAP_SIZE];

    for (i = 0; i < MAP_SIZE; i++)
    {
        pkt = (swFdInfo *) malloc(sizeof(swFdInfo));
        pkt->key = i;
        pkt->fd = i * 37;
        swHashMap_add_int(ht, pkt->fd, pkt);
        lists[i] = pkt;
    }

    tmp = (swFdInfo *) swHashMap_find_int(ht, 37 * 8);
    ASSERT_NE((void* )tmp, nullptr);

    tmp = (swFdInfo *) swHashMap_find_int(ht, 37 * 3);
    ASSERT_NE((void* )tmp, nullptr);

    tmp = (swFdInfo *) swHashMap_find_int(ht, 36 * 3);
    ASSERT_EQ((void* )tmp, nullptr);

    for (i = 0; i < 10; i++)
    {
        free(lists[i]);
    }
}
