/*
 * swoole_config.h
 *
 *  Created on: 2012-11-13
 *      Author: tianfenghan
 */
#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#define SWOOLE_VERSION             "1.6.6"

#define SW_GLOBAL_MEMORY_PAGESIZE  (4096*2) //全局内存的分页

#define SW_MAX_FDS                 (1024*10) //最大tcp连接数
#define SW_MAX_REQUEST             10000     //最大请求包数
#define SW_UDP_SOCK_BUFSIZE        (4*1024*1024) //UDP socket的buffer区大小

//#define SW_CONNECTION_LIST_EXPAND  (4096*2)  //动态扩容的数量

//#define SW_DEBUG                  //启用调试模式，请注释掉此行代码 这里用--enable-swoole-debug开启调试模式
#define SW_LOG_NO_SRCINFO          //不需要源代码信息
//#define SW_BUFFER_SIZE            65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_BUFFER_SIZE             8192 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_MAX_TRUNK_NUM           10  //每个请求最大允许创建的trunk数，可得出每个请求的内存分配量为 SW_BUFFER_SIZE * SW_MAX_TRUNK_NUM

#define SW_DATA_EOF                "\r\n\r\n"
#define SW_DATA_EOF_MAXLEN         8
//#define SW_USE_CONN_BUFFER         1 //使用ConnBuffer还是DataBuffer,DataBuffer是分trunk的，ConnBuffer是固定的

#define SW_MAINREACTOR_TIMEO       3    //主线程reactor
#define SW_MAINREACTOR_USE_UNSOCK  1    //主线程使用unsock
#define SW_REACTOR_WRITER_TIMEO    3    //writer线程的reactor

#ifndef SW_WORKER_IPC_MODE
#define SW_WORKER_IPC_MODE         1    //1:unix socket,2:IPC Message Queue
#endif

#define SW_WORKER_SENDTO_COUNT     2    //写回客户端失败尝试次数

#define SW_MAINREACTOR_USE_POLL        //主线程，使用poll还是select

#define SW_REACTOR_TIMEO_SEC       3
#define SW_REACTOR_TIMEO_USEC      0
#define SW_REACTOR_DISPATCH        2    //连接分配模式，1平均分配，2按FD取摸固定分配

#define SW_WORKER_UNSOCK_BUFSIZE   (1024 * 1024 * 2)

#define SW_QUEUE_SIZE              100  //缩减版的RingQueue,用在线程模式下

#define SW_RINGQUEUE_USE           0             //使用RingQueue代替系统消息队列，此特性正在测试中，启用此特性会用内存队列来替代IPC通信，会减少系统调用、内存申请和复制，提高性能
#define SW_RINGQUEUE_LEN           100           //RingQueue队列长度
#define SW_RINGQUEUE_MEMSIZE       (1024*1024*4) //内存区大小,默认分配4M的内存

//#define SW_USE_RINGQUEUE_TS       1     //使用线程安全版本的RingQueue
#define SW_MEMORY_POOL_SLAB_PAGE   10     //内存池的页数

#define SW_USE_FIXED_BUFFER

#define SW_ACCEPT_AGAIN            1     //是否循环accept，可以一次性处理完全部的listen队列，用于大量并发连接的场景
#define SW_CLOSE_AGAIN             1
#define SW_CLOSE_QLEN              128
//#define SW_USE_EPOLLET
#define SW_USE_EVENTFD                   //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持

#endif /* SWOOLE_CONFIG_H_ */
