#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "memory.h"
#include "tests.h"

int main(int argc, char **argv)
{
	swoole_init();
	swUnitTest test;
	test.argc = argc;
	test.argv = argv;

	swUnitTest_steup(mem_test1, 1, "alloc shared memory");
	swUnitTest_steup(mem_test2, 1, "tests for fixed memory pool");
	swUnitTest_steup(mem_test3, 1, "tests for global memory pool");
	swUnitTest_steup(mem_test4, 1, "tests for ring buffer memory pool");

	swUnitTest_steup(server_test, 1, "socket server test");
	swUnitTest_steup(client_test, 1, "socket client test");
    swUnitTest_steup(dnslookup_test, 1, "dns lookup test");

	swUnitTest_steup(chan_test, 1, "channel test");

	swUnitTest_steup(ds_test2, 1, "user data struct test");
	swUnitTest_steup(hashmap_test1, 1, "hashmap data struct test");

	swUnitTest_steup(u1_test1, 1, "user1 test");
	swUnitTest_steup(u1_test2, 1, "user2 test");
	swUnitTest_steup(u1_test3, 1, "user3 test");

	swUnitTest_steup(aio_test, 1, "linux native aio test");
	swUnitTest_steup(aio_test2, 1, "thread pool aio test");

	swUnitTest_steup(rbtree_test, 1, "rbtree data struct test");
	//swUnitTest_steup(pool_thread, 1);

	swUnitTest_steup(type_test1, 1, "type test");

	//swUnitTest_steup(ws_test1, 1, "websocket decode test");

	//swUnitTest_steup(http_test1, 1, "http get test");
	//swUnitTest_steup(http_test2, 1, "http post test");


	swUnitTest_steup(heap_test1, 1, "heap test");

	swUnitTest_steup(ringbuffer_test1, 1, "ringbuffer test");
	return swUnitTest_run(&test);
}
