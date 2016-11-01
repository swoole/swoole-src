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

#ifndef SW_HASH_H_
#define SW_HASH_H_

#include <stdint.h>

#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

/**
 * jenkins
 */
static inline uint64_t swoole_hash_jenkins(char *key, uint32_t keylen)
{
    uint64_t hashv;

    unsigned i, j, k;
    hashv = 0xfeedbeef;
    i = j = 0x9e3779b9;
    k = (unsigned) (keylen);

    while (k >= 12)
    {
        i += (key[0] + ((unsigned) key[1] << 8) + ((unsigned) key[2] << 16)
                + ((unsigned) key[3] << 24));
        j += (key[4] + ((unsigned) key[5] << 8) + ((unsigned) key[6] << 16)
                + ((unsigned) key[7] << 24));
        hashv += (key[8] + ((unsigned) key[9] << 8) + ((unsigned) key[10] << 16)
                + ((unsigned) key[11] << 24));

        HASH_JEN_MIX(i, j, hashv);

        key += 12;
        k -= 12;
    }
    hashv += keylen;
    switch (k)
    {
    case 11:
        hashv += ((unsigned) key[10] << 24);
        /* no break */
    case 10:
        hashv += ((unsigned) key[9] << 16);
        /* no break */
    case 9:
        hashv += ((unsigned) key[8] << 8);
        /* no break */
    case 8:
        j += ((unsigned) key[7] << 24);
        /* no break */
    case 7:
        j += ((unsigned) key[6] << 16);
        /* no break */
    case 6:
        j += ((unsigned) key[5] << 8);
        /* no break */
    case 5:
        j += key[4];
        /* no break */
    case 4:
        i += ((unsigned) key[3] << 24);
        /* no break */
    case 3:
        i += ((unsigned) key[2] << 16);
        /* no break */
    case 2:
        i += ((unsigned) key[1] << 8);
        /* no break */
    case 1:
        i += key[0];
    }
    HASH_JEN_MIX(i, j, hashv);
    return hashv;
}

/**
 * MurmurHash2(Austin Appleby)
 */
static inline uint32_t swoole_hash_austin(char *key, unsigned int keylen)
{
    unsigned int h, k;
    h = 0 ^ keylen;

    while (keylen >= 4)
    {
        k  = key[0];
        k |= key[1] << 8;
        k |= key[2] << 16;
        k |= key[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        key += 4;
        keylen -= 4;
    }

    switch (keylen)
    {
    case 3:
        h ^= key[2] << 16;
        /* no break */
    case 2:
        h ^= key[1] << 8;
        /* no break */
    case 1:
        h ^= key[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

/* {{{ DJBX33A (Daniel J. Bernstein, Times 33 with Addition)
 *
 * This is Daniel J. Bernstein's popular `times 33' hash function as
 * posted by him years ago on comp->lang.c. It basically uses a function
 * like ``hash(i) = hash(i-1) * 33 + str[i]''. This is one of the best
 * known hash functions for strings. Because it is both computed very
 * fast and distributes very well.
 *
 * The magic of number 33, i.e. why it works better than many other
 * constants, prime or not, has never been adequately explained by
 * anyone. So I try an explanation: if one experimentally tests all
 * multipliers between 1 and 256 (as RSE did now) one detects that even
 * numbers are not useable at all. The remaining 128 odd numbers
 * (except for the number 1) work more or less all equally well. They
 * all distribute in an acceptable way and this way fill a hash table
 * with an average percent of approx. 86%.
 *
 * If one compares the Chi^2 values of the variants, the number 33 not
 * even has the best value. But the number 33 and a few other equally
 * good numbers like 17, 31, 63, 127 and 129 have nevertheless a great
 * advantage to the remaining numbers in the large set of possible
 * multipliers: their multiply operation can be replaced by a faster
 * operation based on just one shift plus either a single addition
 * or subtraction operation. And because a hash function has to both
 * distribute good _and_ has to be very fast to compute, those few
 * numbers should be preferred and seems to be the reason why Daniel J.
 * Bernstein also preferred it.
 *
 *                  -- Ralf S. Engelschall <rse@engelschall.com>
 */
static inline uint64_t swoole_hash_php(char *key, uint32_t len)
{
    register ulong_t hash = 5381;
    /* variant with the hash unrolled eight times */
    for (; len >= 8; len -= 8)
    {
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
    }

    switch (len)
    {
        case 7: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 6: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 5: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 4: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 3: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 2: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 1: hash = ((hash << 5) + hash) + *key++; break;
        case 0: break;
        default: break;
    }
    return hash;
}

#define CRC_STRING_MAXLEN      256

uint32_t swoole_crc32(char *data, uint32_t size);

#endif /* SW_HASH_H_ */
