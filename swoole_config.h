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
#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#define SW_MAX_FDTYPE              32   //32 kinds of event
#define SW_ERROR_MSG_SIZE          512
#define SW_MAX_WORKER_GROUP        2

#define SW_USE_RINGBUFFER

#define SW_GLOBAL_MEMORY_PAGESIZE  (1024*1024*2) //全局内存的分页

#define SW_MAX_THREAD_NCPU         4 // n * cpu_num
#define SW_MAX_WORKER_NCPU         1000 // n * cpu_num
#define SW_MAX_REQUEST             5000          //最大请求包数
#define SW_UNSOCK_BUFSIZE          (8*1024*1024)  //UDP socket的buffer区大小

//#define SW_CONNECTION_LIST_EXPAND  (4096*2)  //动态扩容的数量

//#define SW_DEBUG                  //debug
#define SW_LOG_NO_SRCINFO          //no source info
#define SW_LOG_TRACE_OPEN          0  //1: open all trace log, 0: close all trace log, >1: open some[traceId=n] trace log
//#define SW_BUFFER_SIZE            65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_CLIENT_BUFFER_SIZE      65535

#ifdef SW_USE_RINGBUFFER
#define SW_BUFFER_SIZE             65535
#else
#define SW_BUFFER_SIZE             (8192-sizeof(struct _swDataHead)) //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#endif

#define SW_SENDFILE_TRUNK          65535
#define SW_SENDFILE_MAXLEN         4194304

#define SW_HASHMAP_KEY_MAXLEN      256
#define SW_HASHMAP_INIT_BUCKET_N   32  //hashmap初始化时创建32大小的桶

#define SW_DATA_EOF                "\r\n\r\n"
#define SW_DATA_EOF_MAXLEN         8

#define SW_HEARTBEAT_PING_LEN      8
#define SW_HEARTBEAT_PONG_LEN      8

#define SW_MAINREACTOR_TIMEO       1    //main reactor
#define SW_MAINREACTOR_USE_UNSOCK  1    //主线程使用unsock
#define SW_REACTOR_WRITER_TIMEO    3    //writer线程的reactor
#define SW_TASKWAIT_TIMEOUT        0.5

#ifdef HAVE_EVENTFD
#define HAVE_LINUX_AIO
#endif

#define SW_AIO_THREAD_POOL
#define SW_AIO_THREAD_NUM          2
#define SW_AIO_MAX_FILESIZE        4194304
#define SW_AIO_EVENT_NUM           128
//#define SW_AIO_THREAD_USE_CHANNEL
//#define SW_THREADPOOL_USE_CHANNEL
#define SW_THREADPOOL_QUEUE_LEN    100
#define SW_IP_MAX_LENGTH           32



#define SW_USE_WRITER_THREAD       0    //使用单独的发送线程

#define SW_WORKER_SENDTO_COUNT     32    //写回客户端失败尝试次数
#define SW_WORKER_SENDTO_YIELD     10   //yield after sendto
#define SW_WORKER_READ_COUNT       10
#define SW_WORKER_WAIT_PIPE
#define SW_WORKER_WAIT_TIMEOUT     1000

//#define SW_WORKER_SEND_CHUNK

#define SW_MAINREACTOR_USE_POLL         //main thread to use select or poll

#define SW_REACTOR_TIMEO_SEC       3
#define SW_REACTOR_TIMEO_USEC      0
#define SW_REACTOR_SCHEDULE        2    //连接分配模式: 1轮询分配, 2按FD取摸固定分配, 3根据连接数进行调度
#define SW_REACTOR_MAXEVENTS       4096
//#define SW_REACTOR_SYNC_SEND            //direct send
#define SW_SCHEDULE_INTERVAL       32   //平均调度的间隔次数,减少运算量

#define SW_QUEUE_SIZE              100   //缩减版的RingQueue,用在线程模式下

#define SW_WRITER_TIMEOUT          3

#define SW_RINGQUEUE_USE           0              //使用RingQueue代替系统消息队列，此特性正在测试中，启用此特性会用内存队列来替代IPC通信，会减少系统调用、内存申请和复制，提高性能
#define SW_RINGQUEUE_LEN           100            //RingQueue队列长度
#define SW_RINGQUEUE_MEMSIZE       (1024*1024*4)  //内存区大小,默认分配4M的内存

//#define SW_USE_RINGQUEUE_TS           1     //使用线程安全版本的RingQueue
#define SW_RINGBUFFER_COLLECT_N         100   //collect max_count
#define SW_RINGBUFFER_FREE_N_MAX        4    //when free_n > MAX, execute collect
#define SW_RINGBUFFER_WARNING           100
/**
 * ringbuffer memory pool size
 */
#define SW_REACTOR_RINGBUFFER_SIZE       (1024*1024*4)
#define SW_BUFFER_OUTPUT_SIZE            (1024*1024*2)
#define SW_BUFFER_INPUT_SIZE             (1024*1024*2)

#define SW_MEMORY_POOL_SLAB_PAGE         10     //内存池的页数

#define SW_USE_FIXED_BUFFER

#define SW_ACCEPT_AGAIN            1     //是否循环accept，可以一次性处理完全部的listen队列，用于大量并发连接的场景
#define SW_ACCEPT_MAX_COUNT        64    //一次循环的最大accept次数

#define SW_CLOSE_AGAIN             1
#define SW_CLOSE_QLEN              1024
//#define SW_USE_EPOLLET
#define SW_USE_EVENTFD                   //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持

#define SW_AIO_MAX_EVENTS                128

#define SW_TASK_TMP_FILE                 "/tmp/swoole/task.XXXXXX"
#define SW_FILE_CHUNK_SIZE               65536

#define SW_TABLE_CONFLICT_PROPORTION     0.2 //20%

#define SW_SSL_BUFSIZE  16384

#define SW_SPINLOCK_LOOP_N               1024

#define SW_STRING_BUFFER_MAXLEN          (1024*1024*128)
#define SW_STRING_BUFFER_DEFAULT         128

#if defined(HAVE_SIGNALFD) && SW_WORKER_IPC_MODE != 1
#undef HAVE_SIGNALFD
#endif

#if defined(HAVE_TIMERFD) && SW_WORKER_IPC_MODE != 1
#undef HAVE_TIMERFD
#endif

#endif /* SWOOLE_CONFIG_H_ */
