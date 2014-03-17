/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include "fmacros.h"

#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "rule.h"
#include "format.h"
#include "buf.h"
#include "thread.h"
#include "level_list.h"
#include "rotater.h"
#include "spec.h"
#include "conf.h"

#include "zc_defs.h"


void zlog_rule_profile(zlog_rule_t * a_rule, int flag)
{
	int i;
	zlog_spec_t *a_spec;

	zc_assert(a_rule,);
	zc_profile(flag, "---rule:[%p][%s%c%d]-[%d,%d][%s,%p,%d:%ld*%d~%s][%d][%d][%s:%s:%p];[%p]---",
		a_rule,

		a_rule->category,
		a_rule->compare_char,
		a_rule->level,

		a_rule->file_perms,
		a_rule->file_open_flags,

		a_rule->file_path,
		a_rule->dynamic_specs,
		a_rule->static_fd,

		a_rule->archive_max_size,
		a_rule->archive_max_count,
		a_rule->archive_path,

		a_rule->pipe_fd,

		a_rule->syslog_facility,

		a_rule->record_name,
		a_rule->record_path,
		a_rule->record_func,
		a_rule->format);

	if (a_rule->dynamic_specs) {
		zc_arraylist_foreach(a_rule->dynamic_specs, i, a_spec) {
			zlog_spec_profile(a_spec, flag);
		}
	}
	return;
}

/*******************************************************************************/

static int zlog_rule_output_static_file_single(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	struct stat stb;
	int do_file_reload = 0;
	int redo_inode_stat = 0;

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	/* check if the output file was changed by an external tool by comparing the inode to our saved off one */
	if (stat(a_rule->file_path, &stb)) {
		if (errno != ENOENT) {
			zc_error("stat fail on [%s], errno[%d]", a_rule->file_path, errno);
			return -1;
		} else {
			do_file_reload = 1;
			redo_inode_stat = 1; /* we'll have to restat the newly created file to get the inode info */
		}
	} else {
		do_file_reload = (stb.st_ino != a_rule->static_ino || stb.st_dev != a_rule->static_dev);
	}

	if (do_file_reload) {
		close(a_rule->static_fd);
		a_rule->static_fd = open(a_rule->file_path,
			O_WRONLY | O_APPEND | O_CREAT | a_rule->file_open_flags,
			a_rule->file_perms);
		if (a_rule->static_fd < 0) {
			zc_error("open file[%s] fail, errno[%d]", a_rule->file_path, errno);
			return -1;
		}

		/* save off the new dev/inode info from the stat call we already did */
		if (redo_inode_stat) {
			if (stat(a_rule->file_path, &stb)) {
				zc_error("stat fail on new file[%s], errno[%d]", a_rule->file_path, errno);
				return -1;
			}
		}
		a_rule->static_dev = stb.st_dev;
		a_rule->static_ino = stb.st_ino;
	}

	if (write(a_rule->static_fd,
			zlog_buf_str(a_thread->msg_buf),
			zlog_buf_len(a_thread->msg_buf)) < 0) {
		zc_error("write fail, errno[%d]", errno);
		return -1;
	}

	/* not so thread safe here, as multiple thread may ++fsync_count at the same time */
	if (a_rule->fsync_period && ++a_rule->fsync_count >= a_rule->fsync_period) {
		a_rule->fsync_count = 0;
		if (fsync(a_rule->static_fd)) {
			zc_error("fsync[%d] fail, errno[%d]", a_rule->static_fd, errno);
		}
	}

	return 0;
}

static char * zlog_rule_gen_archive_path(zlog_rule_t *a_rule, zlog_thread_t *a_thread)
{
	int i;
	zlog_spec_t *a_spec;

	if (!a_rule->archive_specs) return a_rule->archive_path;

	zlog_buf_restart(a_thread->archive_path_buf);

	zc_arraylist_foreach(a_rule->archive_specs, i, a_spec) {
		if (zlog_spec_gen_archive_path(a_spec, a_thread)) {
			zc_error("zlog_spec_gen_path fail");
			return NULL;
		}
	}

	zlog_buf_seal(a_thread->archive_path_buf);
	return zlog_buf_str(a_thread->archive_path_buf);
}

static int zlog_rule_output_static_file_rotate(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	size_t len;
	struct zlog_stat info;
	int fd;

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	fd = open(a_rule->file_path, 
		a_rule->file_open_flags | O_WRONLY | O_APPEND | O_CREAT, a_rule->file_perms);
	if (fd < 0) {
		zc_error("open file[%s] fail, errno[%d]", a_rule->file_path, errno);
		return -1;
	}

	len = zlog_buf_len(a_thread->msg_buf);
	if (write(fd, zlog_buf_str(a_thread->msg_buf), len) < 0) {
		zc_error("write fail, errno[%d]", errno);
		close(fd);
		return -1;
	}

	if (a_rule->fsync_period && ++a_rule->fsync_count >= a_rule->fsync_period) {
		a_rule->fsync_count = 0;
		if (fsync(fd)) zc_error("fsync[%d] fail, errno[%d]", fd, errno);
	}

	if (close(fd) < 0) {
		zc_error("close fail, maybe cause by write, errno[%d]", errno);
		return -1;
	}

	if (a_rule->fsync_period && ++a_rule->fsync_count >= a_rule->fsync_period) {
		a_rule->fsync_count = 0;
		if (fsync(a_rule->static_fd)) {
			zc_error("fsync[%d] fail, errno[%d]", a_rule->static_fd, errno);
		}
	}

	if (len > a_rule->archive_max_size) {
		zc_debug("one msg's len[%ld] > archive_max_size[%ld], no rotate",
			 (long)len, (long)a_rule->archive_max_size);
		return 0;
	}

	if (stat(a_rule->file_path, &info)) {
		zc_warn("stat [%s] fail, errno[%d], maybe in rotating", a_rule->file_path, errno);
		return 0;
	}

	/* file not so big, return */
	if (info.st_size + len < a_rule->archive_max_size) return 0;

	if (zlog_rotater_rotate(zlog_env_conf->rotater, 
		a_rule->file_path, len,
		zlog_rule_gen_archive_path(a_rule, a_thread),
		a_rule->archive_max_size, a_rule->archive_max_count)
		) {
		zc_error("zlog_rotater_rotate fail");
		return -1;
	} /* success or no rotation do nothing */

	return 0;
}

/* return path	success
 * return NULL	fail
 */
#define zlog_rule_gen_path(a_rule, a_thread) do {    \
	int i;    \
	zlog_spec_t *a_spec;    \
    \
	zlog_buf_restart(a_thread->path_buf);    \
    \
	zc_arraylist_foreach(a_rule->dynamic_specs, i, a_spec) {    \
		if (zlog_spec_gen_path(a_spec, a_thread)) {    \
			zc_error("zlog_spec_gen_path fail");    \
			return -1;    \
		}    \
	}    \
    \
	zlog_buf_seal(a_thread->path_buf);    \
} while(0)


static int zlog_rule_output_dynamic_file_single(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	int fd;

	zlog_rule_gen_path(a_rule, a_thread);

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_output fail");
		return -1;
	}

	fd = open(zlog_buf_str(a_thread->path_buf),
		a_rule->file_open_flags | O_WRONLY | O_APPEND | O_CREAT, a_rule->file_perms);
	if (fd < 0) {
		zc_error("open file[%s] fail, errno[%d]", zlog_buf_str(a_thread->path_buf), errno);
		return -1;
	}

	if (write(fd, zlog_buf_str(a_thread->msg_buf), zlog_buf_len(a_thread->msg_buf)) < 0) {
		zc_error("write fail, errno[%d]", errno);
		close(fd);
		return -1;
	}

	if (a_rule->fsync_period && ++a_rule->fsync_count >= a_rule->fsync_period) {
		a_rule->fsync_count = 0;
		if (fsync(fd)) zc_error("fsync[%d] fail, errno[%d]", fd, errno);
	}

	if (close(fd) < 0) {
		zc_error("close fail, maybe cause by write, errno[%d]", errno);
		return -1;
	}

	return 0;
}

static int zlog_rule_output_dynamic_file_rotate(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	int fd;
	char *path;
	size_t len;
	struct zlog_stat info;

	zlog_rule_gen_path(a_rule, a_thread);

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_output fail");
		return -1;
	}

	path = zlog_buf_str(a_thread->path_buf);
	fd = open(path, a_rule->file_open_flags | O_WRONLY | O_APPEND | O_CREAT, a_rule->file_perms);
	if (fd < 0) {
		zc_error("open file[%s] fail, errno[%d]", zlog_buf_str(a_thread->path_buf), errno);
		return -1;
	}

	len = zlog_buf_len(a_thread->msg_buf);
	if (write(fd, zlog_buf_str(a_thread->msg_buf), len) < 0) {
		zc_error("write fail, errno[%d]", errno);
		close(fd);
		return -1;
	}

	if (a_rule->fsync_period && ++a_rule->fsync_count >= a_rule->fsync_period) {
		a_rule->fsync_count = 0;
		if (fsync(fd)) zc_error("fsync[%d] fail, errno[%d]", fd, errno);
	}

	if (close(fd) < 0) {
		zc_error("write fail, maybe cause by write, errno[%d]", errno);
		return -1;
	}

	if (len > a_rule->archive_max_size) {
		zc_debug("one msg's len[%ld] > archive_max_size[%ld], no rotate",
			 (long)len, (long) a_rule->archive_max_size);
		return 0;
	}

	if (stat(path, &info)) {
		zc_warn("stat [%s] fail, errno[%d], maybe in rotating", path, errno);
		return 0;
	}

	/* file not so big, return */
	if (info.st_size + len < a_rule->archive_max_size) return 0;

	if (zlog_rotater_rotate(zlog_env_conf->rotater, 
		path, len,
		zlog_rule_gen_archive_path(a_rule, a_thread),
		a_rule->archive_max_size, a_rule->archive_max_count)
		) {
		zc_error("zlog_rotater_rotate fail");
		return -1;
	} /* success or no rotation do nothing */

	return 0;
}

static int zlog_rule_output_pipe(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	if (write(a_rule->pipe_fd,
			zlog_buf_str(a_thread->msg_buf),
			zlog_buf_len(a_thread->msg_buf)) < 0) {
		zc_error("write fail, errno[%d]", errno);
		return -1;
	}

	return 0;
}

static int zlog_rule_output_syslog(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	zlog_level_t *a_level;

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	/*
	msg = a_thread->msg_buf->start;
	msg_len = a_thread->msg_buf->end - a_thread->msg_buf->start;
	 */

	a_level = zlog_level_list_get(zlog_env_conf->levels, a_thread->event->level);
	zlog_buf_seal(a_thread->msg_buf);
	syslog(a_rule->syslog_facility | a_level->syslog_level,
		"%s",  zlog_buf_str(a_thread->msg_buf));
	return 0;
}

static int zlog_rule_output_static_record(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	zlog_msg_t msg;

	if (!a_rule->record_func) {
		zc_error("user defined record funcion for [%s] not set, no output",
			a_rule->record_name);
		return -1;
	}

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}
	zlog_buf_seal(a_thread->msg_buf);

	msg.buf = zlog_buf_str(a_thread->msg_buf);
	msg.len = zlog_buf_len(a_thread->msg_buf);
	msg.path = a_rule->record_path;

	if (a_rule->record_func(&msg)) {
		zc_error("a_rule->record fail");
		return -1;
	}
	return 0;
}

static int zlog_rule_output_dynamic_record(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	zlog_msg_t msg;

	if (!a_rule->record_func) {
		zc_error("user defined record funcion for [%s] not set, no output",
			a_rule->record_name);
		return -1;
	}

	zlog_rule_gen_path(a_rule, a_thread);

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}
	zlog_buf_seal(a_thread->msg_buf);

	msg.buf = zlog_buf_str(a_thread->msg_buf);
	msg.len = zlog_buf_len(a_thread->msg_buf);
	msg.path = zlog_buf_str(a_thread->path_buf);

	if (a_rule->record_func(&msg)) {
		zc_error("a_rule->record fail");
		return -1;
	}
	return 0;
}

static int zlog_rule_output_stdout(zlog_rule_t * a_rule,
				   zlog_thread_t * a_thread)
{

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	if (write(STDOUT_FILENO,
		zlog_buf_str(a_thread->msg_buf), zlog_buf_len(a_thread->msg_buf)) < 0) {
		zc_error("write fail, errno[%d]", errno);
		return -1;
	}

	return 0;
}

static int zlog_rule_output_stderr(zlog_rule_t * a_rule,
				   zlog_thread_t * a_thread)
{

	if (zlog_format_gen_msg(a_rule->format, a_thread)) {
		zc_error("zlog_format_gen_msg fail");
		return -1;
	}

	if (write(STDERR_FILENO,
		zlog_buf_str(a_thread->msg_buf), zlog_buf_len(a_thread->msg_buf)) < 0) {
		zc_error("write fail, errno[%d]", errno);
		return -1;
	}

	return 0;
}
/*******************************************************************************/
static int syslog_facility_atoi(char *facility)
{
	/* guess no unix system will choose -187
	 * as its syslog facility, so it is a safe return value
	 */
	zc_assert(facility, -187);

	if (STRICMP(facility, ==, "LOG_LOCAL0")) return LOG_LOCAL0;
	if (STRICMP(facility, ==, "LOG_LOCAL1")) return LOG_LOCAL1;
	if (STRICMP(facility, ==, "LOG_LOCAL2")) return LOG_LOCAL2;
	if (STRICMP(facility, ==, "LOG_LOCAL3")) return LOG_LOCAL3;
	if (STRICMP(facility, ==, "LOG_LOCAL4")) return LOG_LOCAL4;
	if (STRICMP(facility, ==, "LOG_LOCAL5")) return LOG_LOCAL5;
	if (STRICMP(facility, ==, "LOG_LOCAL6")) return LOG_LOCAL6;
	if (STRICMP(facility, ==, "LOG_LOCAL7")) return LOG_LOCAL7;
	if (STRICMP(facility, ==, "LOG_USER")) return LOG_USER;
	if (STRICMP(facility, ==, "LOG_AUTHPRIV")) return LOG_AUTHPRIV;
	if (STRICMP(facility, ==, "LOG_CRON")) return LOG_CRON;
	if (STRICMP(facility, ==, "LOG_DAEMON")) return LOG_DAEMON;
	if (STRICMP(facility, ==, "LOG_FTP")) return LOG_FTP;
	if (STRICMP(facility, ==, "LOG_KERN")) return LOG_KERN;
	if (STRICMP(facility, ==, "LOG_LPR")) return LOG_LPR;
	if (STRICMP(facility, ==, "LOG_MAIL")) return LOG_MAIL;
	if (STRICMP(facility, ==, "LOG_NEWS")) return LOG_NEWS;
	if (STRICMP(facility, ==, "LOG_SYSLOG")) return LOG_SYSLOG;
		return LOG_AUTHPRIV;

	zc_error("wrong syslog facility[%s], must in LOG_LOCAL[0-7] or LOG_USER", facility);
	return -187;
}

static int zlog_rule_parse_path(char *path_start, /* start with a " */
		char *path_str, size_t path_size, zc_arraylist_t **path_specs,
		int *time_cache_count)
{
	char *p, *q;
	size_t len;
	zlog_spec_t *a_spec;
	zc_arraylist_t *specs;

	p = path_start + 1;

	q = strrchr(p, '"');
	if (!q) {
		zc_error("matching \" not found in conf line[%s]", path_start);
		return -1;
	}
	len = q - p;
	if (len > path_size - 1) {
		zc_error("file_path too long %ld > %ld", len, path_size - 1);
		return -1;
	}
	memcpy(path_str, p, len);

	/* replace any environment variables like %E(HOME) */
	if (zc_str_replace_env(path_str, path_size)) {
		zc_error("zc_str_replace_env fail");
		return -1;
	}

	if (strchr(path_str, '%') == NULL) {
		/* static, no need create specs */
		return 0;
	}

	specs = zc_arraylist_new((zc_arraylist_del_fn)zlog_spec_del);
	if (!path_specs) {
		zc_error("zc_arraylist_new fail");
		return -1;
	}

	for (p = path_str; *p != '\0'; p = q) {
		a_spec = zlog_spec_new(p, &q, time_cache_count);
		if (!a_spec) {
			zc_error("zlog_spec_new fail");
			goto err;
		}

		if (zc_arraylist_add(specs, a_spec)) {
			zc_error("zc_arraylist_add fail");
			goto err;
		}
	}

	*path_specs = specs;
	return 0;
err:
	if (specs) zc_arraylist_del(specs);
	if (a_spec) zlog_spec_del(a_spec);
	return -1;
}

zlog_rule_t *zlog_rule_new(char *line,
		zc_arraylist_t *levels,
		zlog_format_t * default_format,
		zc_arraylist_t * formats,
		unsigned int file_perms,
		size_t fsync_period,
		int * time_cache_count)
{
	int rc = 0;
	int nscan = 0;
	int nread = 0;
	zlog_rule_t *a_rule;

	char selector[MAXLEN_CFG_LINE + 1];
	char category[MAXLEN_CFG_LINE + 1];
	char level[MAXLEN_CFG_LINE + 1];

	char *action;
	char output[MAXLEN_CFG_LINE + 1];
	char format_name[MAXLEN_CFG_LINE + 1];
	char file_path[MAXLEN_CFG_LINE + 1];
	char archive_max_size[MAXLEN_CFG_LINE + 1];
	char *file_limit;

	char *p;
	char *q;
	size_t len;

	zc_assert(line, NULL);
	zc_assert(default_format, NULL);
	zc_assert(formats, NULL);

	a_rule = calloc(1, sizeof(zlog_rule_t));
	if (!a_rule) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	a_rule->file_perms = file_perms;
	a_rule->fsync_period = fsync_period;

	/* line         [f.INFO "%H/log/aa.log", 20MB * 12; MyTemplate]
	 * selector     [f.INFO]
	 * *action      ["%H/log/aa.log", 20MB * 12; MyTemplate]
	 */
	memset(&selector, 0x00, sizeof(selector));
	nscan = sscanf(line, "%s %n", selector, &nread);
	if (nscan != 1) {
		zc_error("sscanf [%s] fail, selector", line);
		goto err;
	}
	action = line + nread;

	/*
	 * selector     [f.INFO]
	 * category     [f]
	 * level        [.INFO]
	 */
	memset(category, 0x00, sizeof(category));
	memset(level, 0x00, sizeof(level));
	nscan = sscanf(selector, " %[^.].%s", category, level);
	if (nscan != 2) {
		zc_error("sscanf [%s] fail, category or level is null",
			 selector);
		goto err;
	}


	/* check and set category */
	for (p = category; *p != '\0'; p++) {
		if ((!isalnum(*p)) && (*p != '_') && (*p != '*') && (*p != '!')) {
			zc_error("category name[%s] character is not in [a-Z][0-9][_!*]",
				 category);
			goto err;
		}
	}

	/* as one line can't be longer than MAXLEN_CFG_LINE, same as category */
	strcpy(a_rule->category, category);

	/* check and set level */
	switch (level[0]) {
	case '=':
		/* aa.=debug */
		a_rule->compare_char = '=';
		p = level + 1;
		break;
	case '!':
		/* aa.!debug */
		a_rule->compare_char = '!';
		p = level + 1;
		break;
	case '*':
		/* aa.* */
		a_rule->compare_char = '*';
		p = level;
		break;
	default:
		/* aa.debug */
		a_rule->compare_char = '.';
		p = level;
		break;
	}

	a_rule->level = zlog_level_list_atoi(levels, p);

	/* level_bit is a bitmap represents which level can be output 
	 * 32bytes, [0-255] levels, see level.c
	 * which bit field is 1 means allow output and 0 not
	 */
	switch (a_rule->compare_char) {
	case '=':
		memset(a_rule->level_bitmap, 0x00, sizeof(a_rule->level_bitmap));
		a_rule->level_bitmap[a_rule->level / 8] |= (1 << (7 - a_rule->level % 8));
		break;
	case '!':
		memset(a_rule->level_bitmap, 0xFF, sizeof(a_rule->level_bitmap));
		a_rule->level_bitmap[a_rule->level / 8] &= ~(1 << (7 - a_rule->level % 8));
		break;
	case '*':
		memset(a_rule->level_bitmap, 0xFF, sizeof(a_rule->level_bitmap));
		break;
	case '.':
		memset(a_rule->level_bitmap, 0x00, sizeof(a_rule->level_bitmap));
		a_rule->level_bitmap[a_rule->level / 8] |= ~(0xFF << (8 - a_rule->level % 8));
		memset(a_rule->level_bitmap + a_rule->level / 8 + 1, 0xFF,
				sizeof(a_rule->level_bitmap) -  a_rule->level / 8 - 1);
		break;
	}

	/* action               ["%H/log/aa.log", 20MB * 12 ; MyTemplate]
	 * output               ["%H/log/aa.log", 20MB * 12]
	 * format               [MyTemplate]
	 */
	memset(output, 0x00, sizeof(output));
	memset(format_name, 0x00, sizeof(format_name));
	nscan = sscanf(action, " %[^;];%s", output, format_name);
	if (nscan < 1) {
		zc_error("sscanf [%s] fail", action);
		goto err;
	}

	/* check and get format */
	if (STRCMP(format_name, ==, "")) {
		zc_debug("no format specified, use default");
		a_rule->format = default_format;
	} else {
		int i;
		int find_flag = 0;
		zlog_format_t *a_format;

		zc_arraylist_foreach(formats, i, a_format) {
			if (zlog_format_has_name(a_format, format_name)) {
				a_rule->format = a_format;
				find_flag = 1;
				break;
			}
		}
		if (!find_flag) {
			zc_error("in conf file can't find format[%s], pls check",
			     format_name);
			goto err;
		}
	}

	/* output               [-"%E(HOME)/log/aa.log" , 20MB*12]  [>syslog , LOG_LOCAL0 ]
	 * file_path            [-"%E(HOME)/log/aa.log" ]           [>syslog ]
	 * *file_limit          [20MB * 12 ~ "aa.#i.log" ]          [LOG_LOCAL0]
	 */
	memset(file_path, 0x00, sizeof(file_path));
	nscan = sscanf(output, " %[^,],", file_path);
	if (nscan < 1) {
		zc_error("sscanf [%s] fail", action);
		goto err;
	}

	file_limit = strchr(output, ',');
	if (file_limit) {
		file_limit++; /* skip the , */
		while( isspace(*file_limit) ) {
			file_limit++;
		}
	}

	p = NULL;
	switch (file_path[0]) {
	case '-' :
		/* sync file each time write log */
		if (file_path[1] != '"') {
			zc_error(" - must set before a file output");
			goto err;
		}

		/* no need to fsync, as file is opened by O_SYNC, write immediately */
		a_rule->fsync_period = 0;

		p = file_path + 1;
		a_rule->file_open_flags = O_SYNC;
		/* fall through */
	case '"' :
		if (!p) p = file_path;

		rc = zlog_rule_parse_path(p, a_rule->file_path, sizeof(a_rule->file_path),
				&(a_rule->dynamic_specs), time_cache_count);
		if (rc) {
			zc_error("zlog_rule_parse_path fail");
			goto err;
		}

		if (file_limit) {
			memset(archive_max_size, 0x00, sizeof(archive_max_size));
			nscan = sscanf(file_limit, " %[0-9MmKkBb] * %d ~",
					archive_max_size, &(a_rule->archive_max_count));
			if (nscan) {
				a_rule->archive_max_size = zc_parse_byte_size(archive_max_size);
			}
			p = strchr(file_limit, '"');
			if (p) { /* archive file path exist */
				rc = zlog_rule_parse_path(p,
					a_rule->archive_path, sizeof(a_rule->file_path),
					&(a_rule->archive_specs), time_cache_count);
				if (rc) {
					zc_error("zlog_rule_parse_path fail");
					goto err;
				}

				p = strchr(a_rule->archive_path, '#');
				if ( (p == NULL) && (
						(strchr(p, 'r') == NULL) || (strchr(p, 's') == NULL)
					)
				   ) {
					zc_error("archive_path must contain #r or #s");
					goto err;
				}
			}
		}

		/* try to figure out if the log file path is dynamic or static */
		if (a_rule->dynamic_specs) {
			if (a_rule->archive_max_size <= 0) {
				a_rule->output = zlog_rule_output_dynamic_file_single;
			} else {
				a_rule->output = zlog_rule_output_dynamic_file_rotate;
			}
		} else {
			struct stat stb;

			if (a_rule->archive_max_size <= 0) {
				a_rule->output = zlog_rule_output_static_file_single;
			} else {
				/* as rotate, so need to reopen everytime */
				a_rule->output = zlog_rule_output_static_file_rotate;
			}

			a_rule->static_fd = open(a_rule->file_path,
				O_WRONLY | O_APPEND | O_CREAT | a_rule->file_open_flags,
				a_rule->file_perms);
			if (a_rule->static_fd < 0) {
				zc_error("open file[%s] fail, errno[%d]", a_rule->file_path, errno);
				goto err;
			}

			/* save off the inode information for checking for a changed file later on */
			if (fstat(a_rule->static_fd, &stb)) {
				zc_error("stat [%s] fail, errno[%d], failing to open static_fd", a_rule->file_path, errno);
				goto err;
			}
			a_rule->static_dev = stb.st_dev;
			a_rule->static_ino = stb.st_ino;
		}
		break;
	case '|' :
		a_rule->pipe_fp = popen(output + 1, "w");
		if (!a_rule->pipe_fp) {
			zc_error("popen fail, errno[%d]", errno);
			goto err;
		}
		a_rule->pipe_fd = fileno(a_rule->pipe_fp);
		if (a_rule->pipe_fd < 0 ) {
			zc_error("fileno fail, errno[%d]", errno);
			goto err;
		}
		a_rule->output = zlog_rule_output_pipe;
		break;
	case '>' :
		if (STRNCMP(file_path + 1, ==, "syslog", 6)) {
			a_rule->syslog_facility = syslog_facility_atoi(file_limit);
			if (a_rule->syslog_facility == -187) {
				zc_error("-187 get");
				goto err;
			}
			a_rule->output = zlog_rule_output_syslog;
			openlog(NULL, LOG_NDELAY | LOG_NOWAIT | LOG_PID, LOG_USER);
		} else if (STRNCMP(file_path + 1, ==, "stdout", 6)) {
			a_rule->output = zlog_rule_output_stdout;
		} else if (STRNCMP(file_path + 1, ==, "stderr", 6)) {
			a_rule->output = zlog_rule_output_stderr;
		} else {
			zc_error
			    ("[%s]the string after is not syslog, stdout or stderr", output);
			goto err;
		}
		break;
	case '$' :
		sscanf(file_path + 1, "%s", a_rule->record_name);
			
		if (file_limit) {  /* record path exists */
			p = strchr(file_limit, '"');
			if (!p) {
				zc_error("record_path not start with \", [%s]", file_limit);
				goto err;
			}
			p++; /* skip 1st " */

			q = strrchr(p, '"');
			if (!q) {
				zc_error("matching \" not found in conf line[%s]", p);
				goto err;
			}
			len = q - p;
			if (len > sizeof(a_rule->record_path) - 1) {
				zc_error("record_path too long %ld > %ld", len, sizeof(a_rule->record_path) - 1);
				goto err;
			}
			memcpy(a_rule->record_path, p, len);
		}

		/* replace any environment variables like %E(HOME) */
		rc = zc_str_replace_env(a_rule->record_path, sizeof(a_rule->record_path));
		if (rc) {
			zc_error("zc_str_replace_env fail");
			goto err;
		}

		/* try to figure out if the log file path is dynamic or static */
		if (strchr(a_rule->record_path, '%') == NULL) {
			a_rule->output = zlog_rule_output_static_record;
		} else {
			zlog_spec_t *a_spec;

			a_rule->output = zlog_rule_output_dynamic_record;

			a_rule->dynamic_specs = zc_arraylist_new((zc_arraylist_del_fn)zlog_spec_del);
			if (!(a_rule->dynamic_specs)) {
				zc_error("zc_arraylist_new fail");
				goto err;
			}
			for (p = a_rule->record_path; *p != '\0'; p = q) {
				a_spec = zlog_spec_new(p, &q, time_cache_count);
				if (!a_spec) {
					zc_error("zlog_spec_new fail");
					goto err;
				}

				rc = zc_arraylist_add(a_rule->dynamic_specs, a_spec);
				if (rc) {
					zlog_spec_del(a_spec);
					zc_error("zc_arraylist_add fail");
					goto err;
				}
			}
		}
		break;
	default :
		zc_error("the 1st char[%c] of file_path[%s] is wrong",
		       file_path[0], file_path);
		goto err;
	}

	//zlog_rule_profile(a_rule, ZC_DEBUG);
	return a_rule;
err:
	zlog_rule_del(a_rule);
	return NULL;
}

void zlog_rule_del(zlog_rule_t * a_rule)
{
	zc_assert(a_rule,);
	if (a_rule->dynamic_specs) {
		zc_arraylist_del(a_rule->dynamic_specs);
		a_rule->dynamic_specs = NULL;
	}
	if (a_rule->static_fd) {
		if (close(a_rule->static_fd)) {
			zc_error("close fail, maybe cause by write, errno[%d]", errno);
		}
	}
	if (a_rule->pipe_fp) {
		if (pclose(a_rule->pipe_fp) == -1) {
			zc_error("pclose fail, errno[%d]", errno);
		}
	}
	if (a_rule->archive_specs) {
		zc_arraylist_del(a_rule->archive_specs);
		a_rule->archive_specs = NULL;
	}
	free(a_rule);
	zc_debug("zlog_rule_del[%p]", a_rule);
	return;
}

/*******************************************************************************/
int zlog_rule_output(zlog_rule_t * a_rule, zlog_thread_t * a_thread)
{
	switch (a_rule->compare_char) {
	case '*' :
		return a_rule->output(a_rule, a_thread);
		break;
	case '.' :
		if (a_thread->event->level >= a_rule->level) {
			return a_rule->output(a_rule, a_thread);
		} else {
			return 0;
		}
		break;
	case '=' :
		if (a_thread->event->level == a_rule->level) {
			return a_rule->output(a_rule, a_thread);
		} else {
			return 0;
		}
		break;
	case '!' :
		if (a_thread->event->level != a_rule->level) {
			return a_rule->output(a_rule, a_thread);
		} else {
			return 0;
		}
		break;
	}

	return 0;
}

/*******************************************************************************/
int zlog_rule_is_wastebin(zlog_rule_t * a_rule)
{
	zc_assert(a_rule, -1);
	
	if (STRCMP(a_rule->category, ==, "!")) {
		return 1;
	}

	return 0;
}

/*******************************************************************************/
int zlog_rule_match_category(zlog_rule_t * a_rule, char *category)
{
	zc_assert(a_rule, -1);
	zc_assert(category, -1);

	if (STRCMP(a_rule->category, ==, "*")) {
		/* '*' match anything, so go on */
		return 1;
	} else if (STRCMP(a_rule->category, ==, category)) {
		/* accurate compare */
		return 1;
	} else {
		/* aa_ match aa_xx & aa, but not match aa1_xx */
		size_t len;
		len = strlen(a_rule->category);

		if (a_rule->category[len - 1] == '_') {
			if (strlen(category) == len - 1) {
				len--;
			}

			if (STRNCMP(a_rule->category, ==, category, len)) {
				return 1;
			}
		}
	}

	return 0;
}

/*******************************************************************************/

int zlog_rule_set_record(zlog_rule_t * a_rule, zc_hashtable_t *records)
{
	zlog_record_t *a_record;

	if (a_rule->output != zlog_rule_output_static_record 
	&&  a_rule->output != zlog_rule_output_dynamic_record) {
		return 0; /* fliter, may go through not record rule */
	}

	a_record = zc_hashtable_get(records, a_rule->record_name);
	if (a_record) {
		a_rule->record_func = a_record->output;
	}
	return 0;
}
