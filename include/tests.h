/*
 * tests.h
 *
 *  Created on: 2013-4-22
 *      Author: htf
 */

#ifndef SW_TESTS_H_
#define SW_TESTS_H_

#define swUnitTest(x) int swUnitTest_##x(swUnitTest *object)
#define swUnitTest_steup(x,n,t) _swUnitTest_setup(swUnitTest_##x, #x, n, t)

typedef struct _swUnitTest
{
	int argc;
	char **argv;
} swUnitTest;
typedef int (*swUnitTest_Func)(swUnitTest *object);

void _swUnitTest_setup(swUnitTest_Func func, char *func_name, int run_times, char *comment);
int swUnitTest_run(swUnitTest *object);

swUnitTest(mem_test1);
swUnitTest(mem_test2);
swUnitTest(mem_test3);
swUnitTest(mem_test4);

swUnitTest(client_test);
swUnitTest(server_test);

swUnitTest(hashmap_test1);
swUnitTest(ds_test2);
swUnitTest(ds_test1);

swUnitTest(chan_test);

swUnitTest(u1_test2);
swUnitTest(u1_test1);
swUnitTest(u1_test3);

swUnitTest(http_test2);

swUnitTest(type_test1);

swUnitTest(aio_test);
swUnitTest(aio_test2);

swUnitTest(rbtree_test);
void p_str(void *str);

swUnitTest(pool_thread);

#endif /* SW_TESTS_H_ */
