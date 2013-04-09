/*
 * swoole_config.h
 *
 *  Created on: 2012-11-13
 *      Author: htf
 */

#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#define SW_DEBUG               //启用调试模式
#define SW_BUFFER_SIZE         65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)

#define SW_QUEUE_SIZE          100 //RingBuffer队列长度
#define SW_MAINREACTOR_TIMEO   3  //main reactor

#define SW_USE_FIXED_BUFFER

#endif /* SWOOLE_CONFIG_H_ */
