#include "tests.h"
#include "swoole.h"
#include "linux_aio.h"

#define BUF_SIZE 1024

swUnitTest(aio_test)
{
	swReactor reactor;
	char *test_file = "aio_test_file";
	int fd = open(test_file, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0)
	{
		perror("open");
		return 3;
	}
	char *buf;
	if (posix_memalign(&buf, 512, BUF_SIZE)) {
		perror("posix_memalign");
		return 5;
	}

//	if (read(fd, buf, buf_size) > 0)
//	{
//		printf("file content: %s\n", buf);
//	}
//	else
//	{
//		perror("read");
//		return 4;
//	}

	if (swReactorEpoll_create(&reactor, 128) < 0)
	{
		return 1;
	}
	swoole_aio_init(&reactor, 0);

	//ftruncate(fd, BUF_SIZE);
	memset(buf, 'A', BUF_SIZE - 1);
	buf[BUF_SIZE - 1] = 0;

	swoole_aio_write(fd, buf, BUF_SIZE, 0);
	reactor.wait(&reactor, NULL);
	swoole_aio_destroy();
	close(fd);

	printf("buf: %s\n", buf);
	return 0;
}
