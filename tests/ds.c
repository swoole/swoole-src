#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "uthash.h"
#include <netinet/tcp.h>
#include "tests.h"

typedef struct _swHashTable_FdInfo
{
	int fd;
	int key;
	UT_hash_handle hh;
} swHashTable_FdInfo;

swUnitTest(type_test1)
{
	char eof[] = SW_DATA_EOF;
	printf("SW_DATA_STREAM_EOF = %s\n", eof);
	return 0;
}

swUnitTest(hashmap_test1)
{
	swHashMap hm = NULL;

	swWarn("add");
	swHashMap_add(&hm, "hello", 199);
	swHashMap_add(&hm, "swoole22", 8877);
	swHashMap_add(&hm, "hello2", 200);
	swHashMap_add(&hm, "willdel", 888);
	swHashMap_add(&hm, "hello3", 78978);

	swWarn("del");
	swHashMap_del(&hm, "willdel");
//	int ret = swHashMap_find(&hm, "hello");
//	printf("ret=%d\n", ret);
//
//	int ret2 = swHashMap_find(&hm, "hello2");
//	printf("ret2=%d\n", ret2);

	void *tmp = NULL;
	char *key;
	int data;

	while(1)
	{
		tmp = swHashMap_foreach(&hm, &key, &data, tmp);
		printf("key=%s|value=%d\n", key, data);
		if(tmp == NULL) break;
	}
	return 0;
}

#define BUFSIZE 128
char data[BUFSIZE];

static void err_exit(const char *msg)
{
	printf("%s:%s\n", msg, strerror(errno));
	exit(-1);
}

swUnitTest(chan_test)
{
	if (object->argc != 3)
	{
		printf("usage: ipc_benchmark rw_num worker_num\n");
		return 0;
	}
	pid_t pid;
	int num = atoi(object->argv[1]);
	int worker_num = atoi(object->argv[2]);
	int ret;

	char item[BUFSIZE];
	swChannel *chan = swChannel_create(1024 * 80, 1000, SW_CHAN_NOTIFY | SW_CHAN_LOCK | SW_CHAN_SHM);
	if (chan == NULL)
	{
		err_exit("msgget");
	}

	int i;
	for (i = 0; i < worker_num; i++)
	{
		if ((pid = fork()) < 0)
		{
			err_exit("fork");
		}
		else if (pid > 0)
		{
			continue;
		}
		else
		{
			int recvn = 0;
//			double t1 = microtime();
			while (1)
			{
				swChannel_wait(chan);
				ret = swChannel_pop(chan, item, BUFSIZE);
				if (ret < 0)
					continue;
				recvn++;
				printf("Worke[%d] recv[%d]=%s\n", i, recvn, item);
			}
			printf("Worker[%d] Finish: recv=%d\n", i, recvn);
			exit(0);
		}
	}

	main_loop: sleep(1);
//	memset(item, 'c', BUFSIZE - 1);
//	item[BUFSIZE - 1] = 0;
	int sendn = 0;
	while (num >= 0)
	{
		sprintf(item, "%d--||||||||||||nnnnnnnnnnn", sendn);
		swChannel_push(chan, item, BUFSIZE);
		swChannel_notify(chan);
		sendn++;
		printf("Master send[%d]\n", sendn);
		num--;
	}
	if (ret < 0)
	{
		err_exit("parent msgsnd");
	}
	printf("Send finish|num=%d|sendn=%d\n", num, sendn);
	int status;
	for (i = 0; i < worker_num; i++)
	{
		wait(&status);
	}
	return 0;
}

/**
 * HashTable Test
 */
swUnitTest(ds_test2)
{
	swHashTable_FdInfo *ht = NULL;
	swHashTable_FdInfo *pkt, *tmp;
	int i;

	for (i = 0; i < 10; i++)
	{
		pkt = (swHashTable_FdInfo *) malloc(sizeof(swHashTable_FdInfo));
		pkt->key = i;
		pkt->fd = i * 34;
		HASH_ADD_INT(ht, key, pkt);
	}
	i = 7;
	HASH_FIND_INT(ht, &i, tmp);
	if (tmp != NULL)
	{

		printf("The key(%d) exists in hash. Fd = %d\n", i, tmp->fd);
	}
	return 0;
}
