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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/


#include "swoole.h"
#include "tests.h"

#define READ_THREAD_N       4
#define WRITE_N             1000000
#define PRINT_SERNUM_N      10000

static swMemoryPool *pool = NULL;
static swPipe sock;

typedef struct
{
    uint32_t size;
    uint32_t serial_num;
    void* ptr;
} pkg;

void thread_read(int i);

swUnitTest(ringbuffer_test1)
{
    int i;
    pthread_t pids[READ_THREAD_N];

    pool = swRingBuffer_new(1024 * 1024 * 4, 0);
    if (!pool)
    {
        return 1;
    }

    if (swPipeUnsock_create(&sock, 1, SOCK_STREAM) < 0)
    {
        return 2;
    }

    for (i = 0; i < READ_THREAD_N; i++)
    {
        pthread_create(&pids[i], NULL, ( void *(*) (void *)) thread_read, (void *) i);
    }
    sleep(1);

    uint32_t size, yield_count = 0;
    void *ptr;
    pkg send_pkg;

    srand((unsigned int) time(NULL));

    for (i = 0; i < WRITE_N; i++)
    {
        size = 10000 + rand() % 90000;
        //printf("alloc size=%d\n", size);

        yield_count = 0;
        do
        {
            ptr = pool->alloc(pool, size);
            if (ptr)
            {
                break;
            }
            else
            {
                yield_count ++;
                usleep(100);
            }
        } while(yield_count < 100);

        if (!ptr)
        {
            break;
        }

        send_pkg.ptr = ptr;
        send_pkg.size = size;
        send_pkg.serial_num = rand();

        memcpy(ptr, &size, sizeof(size));
        memcpy(ptr + size - 4, &(send_pkg.serial_num), sizeof(send_pkg.serial_num));

//        if (i % PRINT_SERNUM_N == 0)
//        {
//            printf("send.serial_num=%d\n", send_pkg.serial_num);
//        }

        if (sock.write(&sock, &send_pkg, sizeof(send_pkg)) < 0)
        {
            printf("write() failed. Error: %s\n", strerror(errno));
        }
        //sleep(1);
    }
    printf("alloc count = %d\n", i);
    return 0;
}

void thread_read(int i)
{
    pkg recv_pkg;
    int tmp;
    int ret;
    int recv_count = 0;
    int j = 0;

    while (1)
    {
        ret = sock.read(&sock, &recv_pkg, sizeof(recv_pkg));
        if (ret < 0)
        {
            printf("read() failed. Error: %s\n", strerror(errno));
            break;
        }
        memcpy(&tmp, recv_pkg.ptr, sizeof(tmp));
        if (tmp != recv_pkg.size)
        {
            printf("Thread#%d: data[1] error, recv_count=%d, length1=%d, length2=%d\n", i, recv_count, recv_pkg.size, tmp);
            break;
        }
        memcpy(&tmp, recv_pkg.ptr + recv_pkg.size - 4, sizeof(tmp));
        if (tmp != recv_pkg.serial_num)
        {
            printf("Thread#%d: data[2] error, recv_count=%d, num1=%d, num2=%d\n", i, recv_count, recv_pkg.serial_num, tmp);
            break;
        }
//        if (j % PRINT_SERNUM_N == 0)
//        {
//            printf("recv.serial_num=%d\n", tmp);
//        }
        j++;
        //printf("Thread#%d: ptr=%p,size=%d\n", i, recv_pkg.ptr, recv_pkg.size);
        pool->free(pool, recv_pkg.ptr);
        recv_count ++;
    }
}

