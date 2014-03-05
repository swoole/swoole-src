/**
 * aio for freebsd
 */
#include "swoole.h"
#include <aio.h>

int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset)
{
	struct aiocb aiocb;

	memset(&aiocb, 0, sizeof(struct aiocb));
	aiocb.aio_fildes = fd;
	aiocb.aio_buf = outbuf;
	aiocb.aio_nbytes = size;
	aiocb.aio_lio_opcode = LIO_WRITE;


}

