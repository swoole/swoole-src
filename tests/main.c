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

	swUnitTest_steup(mem_test1, 1);
	swUnitTest_steup(mem_test2, 1);
	swUnitTest_steup(mem_test3, 1);

	swUnitTest_steup(server_test, 1);
	swUnitTest_steup(client_test, 1);

	swUnitTest_steup(chan_test, 1);

	swUnitTest_steup(ds_test2, 1);
	swUnitTest_steup(hashmap_test1, 1);

	swUnitTest_steup(u1_test1, 1);
	swUnitTest_steup(u1_test2, 1);

	swUnitTest_steup(aio_test, 1);

	//swUnitTest_steup(pool_thread, 1);

	swUnitTest_steup(type_test1, 1);
	return swUnitTest_run(&test);
}
