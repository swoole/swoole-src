/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include "fmacros.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "spec.h"
#include "level_list.h"
#include "zc_defs.h"


#define ZLOG_DEFAULT_TIME_FMT "%F %T"
#define	ZLOG_HEX_HEAD  \
	"\n             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF"

/*******************************************************************************/
void zlog_spec_profile(zlog_spec_t * a_spec, int flag)
{
	zc_assert(a_spec,);
	zc_profile(flag, "----spec[%p][%.*s][%s|%d][%s,%ld,%ld][%s]----",
		a_spec,
		a_spec->len, a_spec->str,
		a_spec->time_fmt,
		a_spec->time_cache_index,
		a_spec->print_fmt, (long)a_spec->max_width, (long)a_spec->min_width,
		a_spec->mdc_key);
	return;
}

/*******************************************************************************/
/* implementation of write function */

static int zlog_spec_write_time(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	zlog_time_cache_t * a_cache = a_thread->event->time_caches + a_spec->time_cache_index;
	time_t now_sec = a_thread->event->time_stamp.tv_sec;
	struct tm *time_local = &(a_thread->event->time_local);

	/* the event meet the 1st time_spec in his life cycle */
	if (!now_sec) {
		gettimeofday(&(a_thread->event->time_stamp), NULL);
		now_sec = a_thread->event->time_stamp.tv_sec;
	}

	/* When this event's last cached time_local is not now */
	if (a_thread->event->time_local_sec != now_sec) {
		localtime_r(&(now_sec), time_local);
		a_thread->event->time_local_sec = now_sec;
	}

	/* When this spec's last cache time string is not now */
	if (a_cache->sec != now_sec) {
		a_cache->len = strftime(a_cache->str, sizeof(a_cache->str), a_spec->time_fmt, time_local);
		a_cache->sec = now_sec;
	}

	return zlog_buf_append(a_buf, a_cache->str, a_cache->len);
}

#if 0
static int zlog_spec_write_time_D(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (!a_thread->event->time_stamp.tv_sec) {
		gettimeofday(&(a_thread->event->time_stamp), NULL);
	}

	/* 
	 * It is modified when time slips one second.
	 * So it is a strong cache, as Default time format is always %F %T.
	 * That's why I said %D is faster than %d()
	 */
	if (a_thread->event->time_stamp.tv_sec != a_thread->event->time_last_D) {

		a_thread->event->time_last_D = a_thread->event->time_stamp.tv_sec;
		localtime_r(&(a_thread->event->time_stamp.tv_sec),
			    &(a_thread->event->time_local));

		strftime(a_thread->event->time_cache_D,
			sizeof(a_thread->event->time_cache_D),
			ZLOG_DEFAULT_TIME_FMT, &(a_thread->event->time_local) );
	}
	return zlog_buf_append(a_buf, a_thread->event->time_cache_D, sizeof(a_thread->event->time_cache_D) - 1);
}
#endif

static int zlog_spec_write_ms(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (!a_thread->event->time_stamp.tv_sec) {
		gettimeofday(&(a_thread->event->time_stamp), NULL);
	}
	return zlog_buf_printf_dec32(a_buf, (a_thread->event->time_stamp.tv_usec / 1000), 3);
}

static int zlog_spec_write_us(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (!a_thread->event->time_stamp.tv_sec) {
		gettimeofday(&(a_thread->event->time_stamp), NULL);
	}
	return zlog_buf_printf_dec32(a_buf, a_thread->event->time_stamp.tv_usec, 6);
}

static int zlog_spec_write_mdc(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	zlog_mdc_kv_t *a_mdc_kv;

	a_mdc_kv = zlog_mdc_get_kv(a_thread->mdc, a_spec->mdc_key);
	if (!a_mdc_kv) {
		zc_error("zlog_mdc_get_kv key[%s] fail", a_spec->mdc_key);
		return 0;
	}

	return zlog_buf_append(a_buf, a_mdc_kv->value, a_mdc_kv->value_len);
}

static int zlog_spec_write_str(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	return zlog_buf_append(a_buf, a_spec->str, a_spec->len);
}

static int zlog_spec_write_category(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	return zlog_buf_append(a_buf, a_thread->event->category_name, a_thread->event->category_name_len);
}

static int zlog_spec_write_srcfile(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (!a_thread->event->file) {
		return zlog_buf_append(a_buf, "(file=null)", sizeof("(file=null)") - 1);
	} else {
		return zlog_buf_append(a_buf, a_thread->event->file, a_thread->event->file_len);
	}
}

static int zlog_spec_write_srcfile_neat(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	char *p;

	if ((p = strrchr(a_thread->event->file, '/')) != NULL) {
		return zlog_buf_append(a_buf, p + 1,
			(char*)a_thread->event->file + a_thread->event->file_len - p - 1);
	} else {
		if (!a_thread->event->file) {
			return zlog_buf_append(a_buf, "(file=null)", sizeof("(file=null)") - 1);
		} else {
			return zlog_buf_append(a_buf, a_thread->event->file, a_thread->event->file_len);
		}
	}
}

static int zlog_spec_write_srcline(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{

	return zlog_buf_printf_dec64(a_buf, a_thread->event->line, 0);
}

static int zlog_spec_write_srcfunc(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (!a_thread->event->file) {
		return zlog_buf_append(a_buf, "(func=null)", sizeof("(func=null)") - 1);
	} else {
		return zlog_buf_append(a_buf, a_thread->event->func, a_thread->event->func_len);
	}
}


static int zlog_spec_write_hostname(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	return zlog_buf_append(a_buf, a_thread->event->host_name, a_thread->event->host_name_len);
}

static int zlog_spec_write_newline(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	return zlog_buf_append(a_buf, FILE_NEWLINE, FILE_NEWLINE_LEN);
}

static int zlog_spec_write_percent(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	return zlog_buf_append(a_buf, "%", 1);
}

static int zlog_spec_write_pid(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	/* 1st in event lifecycle */
	if (!a_thread->event->pid) {
		a_thread->event->pid = getpid();

		/* compare with previous event */
		if (a_thread->event->pid != a_thread->event->last_pid) {
			a_thread->event->last_pid = a_thread->event->pid;
			a_thread->event->pid_str_len
				= sprintf(a_thread->event->pid_str, "%u", a_thread->event->pid);
		}
	}

	return zlog_buf_append(a_buf, a_thread->event->pid_str, a_thread->event->pid_str_len);
}

static int zlog_spec_write_tid_hex(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{

	/* don't need to get tid again, as tmap_new_thread fetch it already */
	/* and fork not change tid */
	return zlog_buf_append(a_buf, a_thread->event->tid_hex_str, a_thread->event->tid_hex_str_len);
}

static int zlog_spec_write_tid_long(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{

	/* don't need to get tid again, as tmap_new_thread fetch it already */
	/* and fork not change tid */
	return zlog_buf_append(a_buf, a_thread->event->tid_str, a_thread->event->tid_str_len);
}

static int zlog_spec_write_level_lowercase(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	zlog_level_t *a_level;

	a_level = zlog_level_list_get(zlog_env_conf->levels, a_thread->event->level);
	return zlog_buf_append(a_buf, a_level->str_lowercase, a_level->str_len);
}

static int zlog_spec_write_level_uppercase(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	zlog_level_t *a_level;

	a_level = zlog_level_list_get(zlog_env_conf->levels, a_thread->event->level);
	return zlog_buf_append(a_buf, a_level->str_uppercase, a_level->str_len);
}

static int zlog_spec_write_usrmsg(zlog_spec_t * a_spec, zlog_thread_t * a_thread, zlog_buf_t * a_buf)
{
	if (a_thread->event->generate_cmd == ZLOG_FMT) {
		if (a_thread->event->str_format) {
			return zlog_buf_vprintf(a_buf,
				      a_thread->event->str_format,
				      a_thread->event->str_args);
		} else {
			return zlog_buf_append(a_buf, "format=(null)", sizeof("format=(null)")-1);
		}
	} else if (a_thread->event->generate_cmd == ZLOG_HEX) {
		int rc;
		long line_offset;
		long byte_offset;

		/* thread buf start == null or len <= 0 */
		if (a_thread->event->hex_buf == NULL) {
			rc = zlog_buf_append(a_buf, "buf=(null)", sizeof("buf=(null)")-1);
			goto zlog_hex_exit;
		}

		rc = zlog_buf_append(a_buf, ZLOG_HEX_HEAD, sizeof(ZLOG_HEX_HEAD)-1);
		if (rc) {
			goto zlog_hex_exit;
		}

		line_offset = 0;
		byte_offset = 0;

		while (1) {
			unsigned char c;

			rc = zlog_buf_append(a_buf, "\n", 1);
			if (rc)  goto zlog_hex_exit;

			rc = zlog_buf_printf_dec64(a_buf, line_offset + 1, 10);
			if (rc)  goto zlog_hex_exit;
			rc = zlog_buf_append(a_buf, "   ", 3);
			if (rc)  goto zlog_hex_exit;

			for (byte_offset = 0; byte_offset < 16; byte_offset++) {
				if (line_offset * 16 + byte_offset < a_thread->event->hex_buf_len) {
					c = *((unsigned char *)a_thread->event->hex_buf
						+ line_offset * 16 + byte_offset);
					rc = zlog_buf_printf_hex(a_buf, c, 2);
					if (rc) goto zlog_hex_exit;
					rc = zlog_buf_append(a_buf, " ", 1);
					if (rc) goto zlog_hex_exit;
				} else {
					rc = zlog_buf_append(a_buf, "   ", 3);
					if (rc)  goto zlog_hex_exit;
				}
			}

			rc = zlog_buf_append(a_buf, "  ", 2);
			if (rc) goto zlog_hex_exit;

			for (byte_offset = 0; byte_offset < 16; byte_offset++) {
				if (line_offset * 16 + byte_offset < a_thread->event->hex_buf_len) {
					c = *((unsigned char *)a_thread->event->hex_buf
						+ line_offset * 16 + byte_offset);
					if (c >= 32 && c <= 126) {
						rc = zlog_buf_append(a_buf,(char*)&c, 1);
						if (rc)  goto zlog_hex_exit;
					} else {
						rc = zlog_buf_append(a_buf, ".", 1);
						if (rc)  goto zlog_hex_exit;
					}
				} else {
					rc = zlog_buf_append(a_buf, " ", 1);
					if (rc)  goto zlog_hex_exit;
				}
			}

			if (line_offset * 16 + byte_offset >= a_thread->event->hex_buf_len) {
				break;
			}

			line_offset++;
		}

	      zlog_hex_exit:
		if (rc < 0) {
			zc_error("write hex msg fail");
			return -1;
		} else if (rc > 0) {
			zc_error("write hex msg, buf is full");
			return 1;
		}

		return 0;
	}

	return 0;
}

/*******************************************************************************/
/* implementation of gen function */

static int zlog_spec_gen_msg_direct(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	/* no need to reprint %1.2d here */
	return a_spec->write_buf(a_spec, a_thread, a_thread->msg_buf);
}

static int zlog_spec_gen_msg_reformat(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	int rc;

	zlog_buf_restart(a_thread->pre_msg_buf);

	rc = a_spec->write_buf(a_spec, a_thread, a_thread->pre_msg_buf);
	if (rc < 0) {
		zc_error("a_spec->gen_buf fail");
		return -1;
	} else if (rc > 0) {
		/* buf is full, try printf */
	}

	return zlog_buf_adjust_append(a_thread->msg_buf,
		zlog_buf_str(a_thread->pre_msg_buf), zlog_buf_len(a_thread->pre_msg_buf),
		a_spec->left_adjust, a_spec->min_width, a_spec->max_width);
}

/*******************************************************************************/
static int zlog_spec_gen_path_direct(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	/* no need to reprint %1.2d here */
	return a_spec->write_buf(a_spec, a_thread, a_thread->path_buf);
}

static int zlog_spec_gen_path_reformat(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	int rc;

	zlog_buf_restart(a_thread->pre_path_buf);

	rc = a_spec->write_buf(a_spec, a_thread, a_thread->pre_path_buf);
	if (rc < 0) {
		zc_error("a_spec->gen_buf fail");
		return -1;
	} else if (rc > 0) {
		/* buf is full, try printf */
	}

	return zlog_buf_adjust_append(a_thread->path_buf,
		zlog_buf_str(a_thread->pre_path_buf), zlog_buf_len(a_thread->pre_path_buf),
		a_spec->left_adjust, a_spec->min_width, a_spec->max_width);
}

/*******************************************************************************/
static int zlog_spec_gen_archive_path_direct(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	/* no need to reprint %1.2d here */
	return a_spec->write_buf(a_spec, a_thread, a_thread->archive_path_buf);
}

static int zlog_spec_gen_archive_path_reformat(zlog_spec_t * a_spec, zlog_thread_t * a_thread)
{
	int rc;

	zlog_buf_restart(a_thread->pre_path_buf);

	rc = a_spec->write_buf(a_spec, a_thread, a_thread->pre_path_buf);
	if (rc < 0) {
		zc_error("a_spec->gen_buf fail");
		return -1;
	} else if (rc > 0) {
		/* buf is full, try printf */
	}

	return zlog_buf_adjust_append(a_thread->archive_path_buf,
		zlog_buf_str(a_thread->pre_path_buf), zlog_buf_len(a_thread->pre_path_buf),
		a_spec->left_adjust, a_spec->min_width, a_spec->max_width);
}

/*******************************************************************************/
static int zlog_spec_parse_print_fmt(zlog_spec_t * a_spec)
{
	/* -12.35 12 .35 */
	char *p, *q;
	long i, j;

	p = a_spec->print_fmt;
	if (*p == '-') {
		a_spec->left_adjust = 1;
		p++; 
	} else {
		a_spec->left_adjust = 0;
	}

	i = j = 0;
	sscanf(p, "%ld.", &i);
	q = strchr(p, '.');
	if (q) sscanf(q, ".%ld", &j);

	a_spec->min_width = (size_t) i;
	a_spec->max_width = (size_t) j;
	return 0;
}

/*******************************************************************************/
void zlog_spec_del(zlog_spec_t * a_spec)
{
	zc_assert(a_spec,);
	free(a_spec);
	zc_debug("zlog_spec_del[%p]", a_spec);
}

/* a spec may consist of
 * a const string: /home/bb
 * a string begin with %: %12.35d(%F %X,%l)
 */
zlog_spec_t *zlog_spec_new(char *pattern_start, char **pattern_next, int *time_cache_count)
{
	char *p;
	int nscan = 0;
	int nread = 0;
	zlog_spec_t *a_spec;

	zc_assert(pattern_start, NULL);
	zc_assert(pattern_next, NULL);

	a_spec = calloc(1, sizeof(zlog_spec_t));
	if (!a_spec) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	a_spec->str = p = pattern_start;

	switch (*p) {
	case '%':
		/* a string begin with %: %12.35d(%F %X) */

		/* process width and precision char in %-12.35P */
		nread = 0;
		nscan = sscanf(p, "%%%[.0-9-]%n", a_spec->print_fmt, &nread);
		if (nscan == 1) {
			a_spec->gen_msg = zlog_spec_gen_msg_reformat;
			a_spec->gen_path = zlog_spec_gen_path_reformat;
			a_spec->gen_archive_path = zlog_spec_gen_archive_path_reformat;
			if (zlog_spec_parse_print_fmt(a_spec)) {
				zc_error("zlog_spec_parse_print_fmt fail");
				goto err;
			}
		} else {
			nread = 1; /* skip the % char */
			a_spec->gen_msg = zlog_spec_gen_msg_direct;
			a_spec->gen_path = zlog_spec_gen_path_direct;
			a_spec->gen_archive_path = zlog_spec_gen_archive_path_direct;
		}

		p += nread;

		if (*p == 'd') {
			if (*(p+1) != '(') {
				/* without '(' , use default */
				strcpy(a_spec->time_fmt, ZLOG_DEFAULT_TIME_FMT);
				p++;
			} else if (STRNCMP(p, ==, "d()", 3)) {
				/* with () but without detail time format,
				 * keep a_spec->time_fmt=="" */
				strcpy(a_spec->time_fmt, ZLOG_DEFAULT_TIME_FMT);
				p += 3;
			} else {
				nread = 0;
				nscan = sscanf(p, "d(%[^)])%n", a_spec->time_fmt, &nread);
				if (nscan != 1) {
					nread = 0;
				}
				p += nread;
				if (*(p - 1) != ')') {
					zc_error("in string[%s] can't find match \')\'", a_spec->str);
					goto err;
				}
			}

			a_spec->time_cache_index = *time_cache_count;
			(*time_cache_count)++;
			a_spec->write_buf = zlog_spec_write_time;

			*pattern_next = p;
			a_spec->len = p - a_spec->str;
			break;
		}

		if (*p == 'M') {
			nread = 0;
			nscan = sscanf(p, "M(%[^)])%n", a_spec->mdc_key, &nread);
			if (nscan != 1) {
				nread = 0;
				if (STRNCMP(p, ==, "M()", 3)) {
					nread = 3;
				}
			}
			p += nread;
			if (*(p - 1) != ')') {
				zc_error("in string[%s] can't find match \')\'", a_spec->str);
				goto err;
			}

			*pattern_next = p;
			a_spec->len = p - a_spec->str;
			a_spec->write_buf = zlog_spec_write_mdc;
			break;
		}

		if (STRNCMP(p, ==, "ms", 2)) {
			p += 2;
			*pattern_next = p;
			a_spec->len = p - a_spec->str;
			a_spec->write_buf = zlog_spec_write_ms;
			break;
		} else if (STRNCMP(p, ==, "us", 2)) {
			p += 2;
			*pattern_next = p;
			a_spec->len = p - a_spec->str;
			a_spec->write_buf = zlog_spec_write_us;
			break;
		}

		*pattern_next = p + 1;
		a_spec->len = p - a_spec->str + 1;

		switch (*p) {
		case 'c':
			a_spec->write_buf = zlog_spec_write_category;
			break;
		case 'D':
			strcpy(a_spec->time_fmt, ZLOG_DEFAULT_TIME_FMT);
			a_spec->time_cache_index = *time_cache_count;
			(*time_cache_count)++;
			a_spec->write_buf = zlog_spec_write_time;
			break;
		case 'F':
			a_spec->write_buf = zlog_spec_write_srcfile;
			break;
		case 'f':
			a_spec->write_buf = zlog_spec_write_srcfile_neat;
			break;
		case 'H':
			a_spec->write_buf = zlog_spec_write_hostname;
			break;
		case 'L':
			a_spec->write_buf = zlog_spec_write_srcline;
			break;
		case 'm':
			a_spec->write_buf = zlog_spec_write_usrmsg;
			break;
		case 'n':
			a_spec->write_buf = zlog_spec_write_newline;
			break;
		case 'p':
			a_spec->write_buf = zlog_spec_write_pid;
			break;
		case 'U':
			a_spec->write_buf = zlog_spec_write_srcfunc;
			break;
		case 'v':
			a_spec->write_buf = zlog_spec_write_level_lowercase;
			break;
		case 'V':
			a_spec->write_buf = zlog_spec_write_level_uppercase;
			break;
		case 't':
			a_spec->write_buf = zlog_spec_write_tid_hex;
			break;
		case 'T':
			a_spec->write_buf = zlog_spec_write_tid_long;
			break;
		case '%':
			a_spec->write_buf = zlog_spec_write_percent;
			break;
		default:
			zc_error("str[%s] in wrong format, p[%c]", a_spec->str, *p);
			goto err;
		}
		break;
	default:
		/* a const string: /home/bb */
		*pattern_next = strchr(p, '%');
		if (*pattern_next) {
			a_spec->len = *pattern_next - p;
		} else {
			a_spec->len = strlen(p);
			*pattern_next = p + a_spec->len;
		}
		a_spec->write_buf = zlog_spec_write_str;
		a_spec->gen_msg = zlog_spec_gen_msg_direct;
		a_spec->gen_path = zlog_spec_gen_path_direct;
		a_spec->gen_archive_path = zlog_spec_gen_archive_path_direct;
	}

	zlog_spec_profile(a_spec, ZC_DEBUG);
	return a_spec;
err:
	zlog_spec_del(a_spec);
	return NULL;
}

