/*
 * swoole_config.h
 *
 *  Created on: 2012-11-13
 *      Author: tianfenghan
 */

#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

//#define SW_DEBUG                 //启用调试模式，请注释掉此行代码 这里用--enable-swoole-debug开启调试模式
#define SW_BUFFER_SIZE           65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)

#define SW_QUEUE_SIZE            100  //RingBuffer队列长度
#define SW_MAINREACTOR_TIMEO     3    //main reactor
#define SW_MAINREACTOR_USE_POLL       //主进程使用poll还是select

#define SW_REACTOR_TIMEO_SEC     3
#define SW_REACTOR_TIMEO_USEC    0

//#define SW_USE_RINGQUEUE_TS      1

#define SW_USE_FIXED_BUFFER
#define SW_USE_ACCEPT4    //是否使用accept4，可以节省一次setnonblock的系统调用         1
#define SW_USE_EVENTFD      //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持
#endif /* SWOOLE_CONFIG_H_ */
