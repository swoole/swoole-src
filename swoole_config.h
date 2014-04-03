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

#define SW_GLOBAL_MEMORY_PAGESIZE  (1024*1024*2) //全局内存的分页

#define SW_MAX_THREAD_NCPU         4 // n * cpu_num
#define SW_MAX_WORKER_NCPU         100 // n * cpu_num
#define SW_MAX_FDS                 (1024*10)      //最大tcp连接数
#define SW_MAX_REQUEST             10000          //最大请求包数
#define SW_UNSOCK_BUFSIZE          (4*1024*1024)  //UDP socket的buffer区大小

//#define SW_CONNECTION_LIST_EXPAND  (4096*2)  //动态扩容的数量

//#define SW_DEBUG                  //启用调试模式，请注释掉此行代码 这里用--enable-swoole-debug开启调试模式
#define SW_LOG_NO_SRCINFO          //不需要源代码信息
//#define SW_BUFFER_SIZE            65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_CLIENT_BUFFER_SIZE      65535
#define SW_BUFFER_SIZE             (8192-sizeof(struct _swDataHead)) //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
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
#define SW_REACTOR_DIRECT_SEND          //首先尝试直接发送,如果发生EAGAIN错误,再添加EPOLLOUT事件监听
#define SW_TASKWAIT_TIMEOUT        0.5

//#define SW_AIO_LINUX_NATIVE
//#define SW_AIO_GCC
#define SW_AIO_THREAD_POOL
#define SW_AIO_THREAD_NUM          2
//#define SW_AIO_THREAD_USE_CHANNEL
//#define SW_THREADPOOL_USE_CHANNEL
#define SW_THREADPOOL_QUEUE_LEN    100
#define SW_IP_MAX_LENGTH           32
#define SW_AIO_MAX_FILESIZE        4194304
#define SW_AIO_EVENT_NUM           128

#ifndef SW_WORKER_IPC_MODE
#define SW_WORKER_IPC_MODE         1    //1:unix socket,2:IPC Message Queue
#endif
#define SW_USE_WRITER_THREAD       0    //使用单独的发送线程

#define SW_WORKER_SENDTO_COUNT     2    //写回客户端失败尝试次数
#define SW_WORKER_SENDTO_YIELD     10   //yield after sendto

#define SW_MAINREACTOR_USE_POLL         //main thread to use select or poll

#define SW_REACTOR_TIMEO_SEC       3
#define SW_REACTOR_TIMEO_USEC      0
#define SW_REACTOR_SCHEDULE        3    //连接分配模式: 1轮询分配, 2按FD取摸固定分配, 3根据连接数进行调度
#define SW_REACTOR_MAXEVENTS       4096
#define SW_SCHEDULE_INTERVAL       32   //平均调度的间隔次数,减少运算量

#define SW_QUEUE_SIZE              100   //缩减版的RingQueue,用在线程模式下

#define SW_RINGQUEUE_USE           0             //使用RingQueue代替系统消息队列，此特性正在测试中，启用此特性会用内存队列来替代IPC通信，会减少系统调用、内存申请和复制，提高性能
#define SW_RINGQUEUE_LEN           100           //RingQueue队列长度
#define SW_RINGQUEUE_MEMSIZE       (1024*1024*4) //内存区大小,默认分配4M的内存

//#define SW_USE_RINGQUEUE_TS       1     //使用线程安全版本的RingQueue
#define SW_MEMORY_POOL_SLAB_PAGE   10     //内存池的页数

#define SW_USE_FIXED_BUFFER

#define SW_ACCEPT_AGAIN            1     //是否循环accept，可以一次性处理完全部的listen队列，用于大量并发连接的场景
#define SW_ACCEPT_MAX_COUNT        64    //一次循环的最大accept次数

#define SW_CLOSE_AGAIN             1
#define SW_CLOSE_QLEN              1024
//#define SW_USE_EPOLLET
#define SW_USE_EVENTFD                   //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持

#define SW_AIO_MAX_EVENTS          128

#endif /* SWOOLE_CONFIG_H_ */
