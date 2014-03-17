/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */
#ifndef __zc_xplatform_h
#define __zc_xplatform_h

#include <limits.h>

#define ZLOG_INT32_LEN   sizeof("-2147483648") - 1
#define ZLOG_INT64_LEN   sizeof("-9223372036854775808") - 1

#if ((__GNU__ == 2) && (__GNUC_MINOR__ < 8))
#define ZLOG_MAX_UINT32_VALUE  (uint32_t) 0xffffffffLL
#else
#define ZLOG_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#endif

#define ZLOG_MAX_INT32_VALUE   (uint32_t) 0x7fffffff

#define MAXLEN_PATH 1024
#define MAXLEN_CFG_LINE (MAXLEN_PATH * 4)

#define FILE_NEWLINE "\n"
#define FILE_NEWLINE_LEN 1

#include <string.h>
#include <strings.h>

#define STRCMP(_a_,_C_,_b_) ( strcmp(_a_,_b_) _C_ 0 )
#define STRNCMP(_a_,_C_,_b_,_n_) ( strncmp(_a_,_b_,_n_) _C_ 0 )
#define STRICMP(_a_,_C_,_b_) ( strcasecmp(_a_,_b_) _C_ 0 )
#define STRNICMP(_a_,_C_,_b_,_n_) ( strncasecmp(_a_,_b_,_n_) _C_ 0 )


#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif

/* Define zlog_fstat to fstat or fstat64() */
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
#define zlog_fstat fstat64
#define zlog_stat stat64
#else
#define zlog_fstat fstat
#define zlog_stat stat
#endif

/* Define zlog_fsync to fdatasync() in Linux and fsync() for all the rest */
#ifdef __linux__
#define zlog_fsync fdatasync
#else
#define zlog_fsync fsync
#endif



#endif
