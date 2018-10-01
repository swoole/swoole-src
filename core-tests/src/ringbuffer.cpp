#include "tests.h"

#include <thread>

#define READ_THREAD_N       4
#define WRITE_N             100000
#define PRINT_SERNUM_N      1000

static swMemoryPool *pool = NULL;

typedef struct
{
    uint32_t size;
    uint32_t serial_num;
    void* ptr;
} pkg;

typedef struct
{
    std::thread *thread;
    swPipe pipe;
} ThreadObject;

static void thread_read(int i);
static void thread_write(void);
static ThreadObject threads[READ_THREAD_N];

TEST(ringbuffer, thread)
{
    int i;
    pool = swRingBuffer_new(1024 * 1024 * 4, 1);
    ASSERT_NE(pool, nullptr);

    for (i = 0; i < READ_THREAD_N; i++)
    {
        int ret = swPipeUnsock_create(&threads[i].pipe, 1, SOCK_DGRAM);
        ASSERT_EQ(ret, 0);
        threads[i].thread = new std::thread(thread_read, i);
    }

    sleep(1);
    srand((unsigned int) time(NULL));
    thread_write();

    for (i = 0; i < READ_THREAD_N; i++)
    {
        threads[i].thread->join();
        threads[i].pipe.close(&threads[i].pipe);
        delete threads[i].thread;
    }
}

static void thread_write(void)
{
    uint32_t size, yield_count = 0, yield_total_count = 0;
    void *ptr;
    pkg send_pkg;
    bzero(&send_pkg, sizeof(send_pkg));

    int i;
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
                yield_count++;
                yield_total_count++;
                usleep(10);
            }
        } while (yield_count < 100);

        if (!ptr)
        {
            printf("alloc failed. break\n");
            break;
        }

        send_pkg.ptr = ptr;
        send_pkg.size = size;
        send_pkg.serial_num = rand();

        //保存长度值
        memcpy(ptr, &size, sizeof(size));
        //在指针末尾保存一个串号
        memcpy((char*) ptr + size - 4, &(send_pkg.serial_num), sizeof(send_pkg.serial_num));

#ifdef PRINT_SERNUM_OPEN
        if (i % PRINT_SERNUM_N == 0)
        {
            printf("send. send_count=%d, serial_num=%d\n", i, send_pkg.serial_num);
        }
#endif
        if (threads[i % READ_THREAD_N].pipe.write(&threads[i % READ_THREAD_N].pipe, &send_pkg, sizeof(send_pkg)) < 0)
        {
            printf("write() failed. Error: %s\n", strerror(errno));
        }
        if (i % 100 == 0)
        {
            usleep(10);
        }
        //sleep(1);
    }
    printf("alloc count = %d, yield_total_count = %d\n", i, yield_total_count);
}

static void thread_read(int i)
{
    pkg recv_pkg;
    uint32_t tmp;
    int ret;
    uint32_t recv_count = 0;
    int j = 0;
    swPipe *sock = &threads[i].pipe;
    int task_n = WRITE_N / READ_THREAD_N;

    for (j = 0; j < task_n; j++)
    {
        ret = sock->read(sock, &recv_pkg, sizeof(recv_pkg));
        if (ret < 0)
        {
            printf("read() failed. Error: %s\n", strerror(errno));
            break;
        }
        memcpy(&tmp, recv_pkg.ptr, sizeof(tmp));
        if (tmp != recv_pkg.size)
        {
            printf("Thread#%d: size error, recv_count=%d, length1=%d, length2=%d\n", i, recv_count, recv_pkg.size, tmp);
            continue;
        }

        memcpy(&tmp, (char*) recv_pkg.ptr + recv_pkg.size - 4, sizeof(tmp));
        if (tmp != recv_pkg.serial_num)
        {
            printf("Thread#%d: serial_num error, recv_count=%d, num1=%d, num2=%d\n", i, recv_count, recv_pkg.serial_num,
                    tmp);
            continue;
        }

#ifdef PRINT_SERNUM_OPEN
        if (j % PRINT_SERNUM_N == 0)
        {
            printf("recv. recv_count=%d, serial_num=%d\n", recv_count, tmp);
        }
#endif
        //printf("Thread#%d: ptr=%p,size=%d\n", i, recv_pkg.ptr, recv_pkg.size);
        pool->free(pool, recv_pkg.ptr);
        recv_count++;
    }
    printf("worker #%d finish, recv_count=%d\n", i, recv_count);
}
