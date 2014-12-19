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


#ifndef _WEBSOCKET_SHA1_H__
#define _WEBSOCKET_SHA1_H__

/* Define this if your machine is LITTLE_ENDIAN, otherwise #undef it: */
#ifdef WORDS_BIGENDIAN
# undef		LITTLE_ENDIAN
#else
# ifndef LITTLE_ENDIAN
#  define	LITTLE_ENDIAN
# endif
#endif

/* Make sure you define these types for your architecture: */
typedef unsigned int sha1_quadbyte;	/* 4 byte type */
typedef unsigned char sha1_byte;	/* single byte type */

/*
 * Be sure to get the above definitions right.  For instance, on my
 * x86 based FreeBSD box, I define LITTLE_ENDIAN and use the type
 * "unsigned long" for the quadbyte.  On FreeBSD on the Alpha, however,
 * while I still use LITTLE_ENDIAN, I must define the quadbyte type
 * as "unsigned int" instead.
 */

#define SHA1_BLOCK_LENGTH	64
#define SHA1_DIGEST_LENGTH	20

/* The SHA1 structure: */
typedef struct _SHA_CTX {
  sha1_quadbyte	state[5];
  sha1_quadbyte	count[2];
  sha1_byte	buffer[SHA1_BLOCK_LENGTH];
} SHA_CTX;

#ifndef NOPROTO
void swSha1_init(SHA_CTX *context);
void swSha1_update(SHA_CTX *context, sha1_byte *data, unsigned int len);
void swSha1_final(sha1_byte digest[SHA1_DIGEST_LENGTH],
        SHA_CTX* context);
#else
void swSha1_init();
void swSha1_update();
void swSha1_final();
#endif

#endif

