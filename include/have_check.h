/*
 * have_check.h
 *
 *  Created on: 2013-6-28
 *      Author: htf
 */

#ifndef HAVE_CHECK_H_
#define HAVE_CHECK_H_

#warning "have checking"

#ifdef HAVE_EPOLL
#warning "HAVE_EPOLL"
#endif

#ifdef HAVE_EVENTFD
#warning "HAVE_EVENTFD"
#endif

#ifdef HAVE_TIMERFD
#warning "HAVE_TIMERFD"
#endif

#endif /* HAVE_CHECK_H_ */
