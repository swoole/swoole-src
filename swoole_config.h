/*
 * swoole_config.h
 *
 *  Created on: 2012-11-13
 *      Author: tianfenghan
 */
#include <sys/syscall.h>

#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#define SW_MAX_FDS                 (1024*10) //最大tcp连接数
#define SW_MAX_REQUEST             10000     //最大请求包数
//#define SW_DEBUG                  //启用调试模式，请注释掉此行代码 这里用--enable-swoole-debug开启调试模式
//#define SW_BUFFER_SIZE            65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_BUFFER_SIZE             8192 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_MAX_TRUNK_NUM           10  //每个请求最大允许创建的trunk数，可得出每个请求的内存分配量为 SW_BUFFER_SIZE * SW_MAX_TRUNK_NUM

#define SW_DATA_EOF                "\r\n\r\n"
#define SW_DATA_EOF_MAXLEN         8

#define SW_QUEUE_SIZE              100  //RingBuffer队列长度
#define SW_MAINREACTOR_TIMEO       3    //主线程，reactor
//#define SW_MAINREACTOR_USE_POLL         //主线程，使用poll还是select

#define SW_REACTOR_TIMEO_SEC       3
#define SW_REACTOR_TIMEO_USEC      0
#define SW_REACTOR_DISPATCH        2   //连接分配模式，1平均分配，2按FD取摸固定分配

#define SW_WORKER_MSGQUEUE_KEY     0x27000900

//#define SW_USE_RINGQUEUE_TS       1   //使用线程安全版本的RingQueue
//#define SW_USE_SHM_CHAN            1    //使用共享内存队列，此特性正在测试中，启用此特性会用内存队列来替代IPC通信，会减少系统调用、内存申请和复制，提高性能
#define SW_CHAN_PUSH_TRY_COUNT     100
#define SW_CHAN_BUFFER_SIZE        1024*1024*2 //2M缓存区
#define SW_CHAN_ELEM_SIZE          16
#define SW_CHAN_DEBUG              0
//#define SW_CHAN_USE_MMAP           0  //使用mmap还是sysv shm
#define SW_CHAN_SYSV_KEY           0x27000800

#define SW_USE_FIXED_BUFFER

#ifdef __NR_accept4
#define SW_USE_ACCEPT4                   //是否使用accept4，可以节省一次setnonblock的系统调用
#endif

#define SW_ACCEPT_AGAIN            1     //是否循环accept，可以一次性处理完全部的listen队列，用于大量并发连接的场景
#define SW_USE_EVENTFD                   //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持
#endif /* SWOOLE_CONFIG_H_ */
