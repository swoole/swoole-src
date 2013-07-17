/*
 * UnitTest.c
 *
 *  Created on: 2013-4-26
 *      Author: htf
 */

#include "swoole.h"
#include "tests.h"
#include "hashtable.h"

typedef struct _swHashTable_FdInfo
{
	swUnitTest_Func func;
	int run_times;
	char *key;
	UT_hash_handle hh;
} swHashTable_unitTst;

static swHashTable_unitTst *unitTest_ht;

void _swUnitTest_setup(swUnitTest_Func func, char *func_name, int run_times)
{
	swHashTable_unitTst *u;
	u = (swHashTable_unitTst *) malloc(sizeof(swHashTable_unitTst));
	u->key = func_name;
	u->func = func;
	u->run_times = run_times;
	HASH_ADD_STR(unitTest_ht, key, u);
}

int swUnitTest_run(swUnitTest *object)
{
	int max_len = 128;
	int argc = object->argc;
	char **argv = object->argv;
	int ret;

	swUnitTest_Func func;
	swHashTable_unitTst *tmp;
	int i = 0;

	if (argc < 2)
	{
		printf("Please enter %s unitTest_name\n", argv[0]);
		for (tmp = unitTest_ht; tmp != NULL; tmp = tmp->hh.next)
		{
			printf("%d.\t%s\n", i++, tmp->key);
		}
		return 0;
	}

	for (tmp = unitTest_ht; tmp != NULL; tmp = tmp->hh.next)
	{
		if (strncmp(argv[1], tmp->key, max_len) == 0)
		{
			func = tmp->func;
			printf("running\n");
			ret = func(object);

		}
	}
	return ret;
}

void p_str(void *str)
{
	printf("Str: %s|len=%ld\n", (char *) str, strlen((char *) str));
}
