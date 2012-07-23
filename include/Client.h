/*
 * Client.h
 *
 *  Created on: 2012-7-22
 *      Author: htf
 */

#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#define SW_CLIENT_TCP       1
#define SW_CLIENT_TCP6      2  //ipv6
#define SW_CLIENT_UDP       3
#define SW_CLIENT_UDP6      4  //ipv6


typedef struct _swClient
{
	int sock;
	int id;
	int type;
} swClient;


#endif /* SW_CLIENT_H_ */
