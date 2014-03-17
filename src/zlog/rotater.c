/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "zc_defs.h"
#include "rotater.h"

#define ROLLING  1     /* aa.02->aa.03, aa.01->aa.02, aa->aa.01 */
#define SEQUENCE 2     /* aa->aa.03 */

typedef struct {
	int index;
	char path[MAXLEN_PATH + 1];
} zlog_file_t;

void zlog_rotater_profile(zlog_rotater_t * a_rotater, int flag)
{
	zc_assert(a_rotater,);
	zc_profile(flag, "--rotater[%p][%p,%s,%d][%s,%s,%s,%ld,%ld,%d,%d,%d]--",
		a_rotater,

		&(a_rotater->lock_mutex),
		a_rotater->lock_file,
		a_rotater->lock_fd,

		a_rotater->base_path,
		a_rotater->archive_path,
		a_rotater->glob_path,
		(long)a_rotater->num_start_len,
		(long)a_rotater->num_end_len,
		a_rotater->num_width,
		a_rotater->mv_type,
		a_rotater->max_count
		);
	if (a_rotater->files) {
		int i;
		zlog_file_t *a_file;
		zc_arraylist_foreach(a_rotater->files, i, a_file) {
			zc_profile(flag, "[%s,%d]->", a_file->path, a_file->index);
		}
	}
	return;
}

/*******************************************************************************/
void zlog_rotater_del(zlog_rotater_t *a_rotater)
{
	zc_assert(a_rotater,);

	if (a_rotater->lock_fd) {
		if (close(a_rotater->lock_fd)) {
			zc_error("close fail, errno[%d]", errno);
		}
	}

	if (pthread_mutex_destroy(&(a_rotater->lock_mutex))) {
		zc_error("pthread_mutex_destroy fail, errno[%d]", errno);
	}

	free(a_rotater);
	zc_debug("zlog_rotater_del[%p]", a_rotater);
	return;
}

zlog_rotater_t *zlog_rotater_new(char *lock_file)
{
	int fd = 0;
	zlog_rotater_t *a_rotater;

	zc_assert(lock_file, NULL);

	a_rotater = calloc(1, sizeof(zlog_rotater_t));
	if (!a_rotater) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	if (pthread_mutex_init(&(a_rotater->lock_mutex), NULL)) {
		zc_error("pthread_mutex_init fail, errno[%d]", errno);
		free(a_rotater);
		return NULL;
	}

	/* depends on umask of the user here
	 * if user A create /tmp/zlog.lock 0600
	 * user B is unable to read /tmp/zlog.lock
	 * B has to choose another lock file except /tmp/zlog.lock
	 */
	fd = open(lock_file, O_RDWR | O_CREAT,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		zc_error("open file[%s] fail, errno[%d]", lock_file, errno);
		goto err;
	}

	a_rotater->lock_fd = fd;
	a_rotater->lock_file = lock_file;

	//zlog_rotater_profile(a_rotater, ZC_DEBUG);
	return a_rotater;
err:
	zlog_rotater_del(a_rotater);
	return NULL;
}

/*******************************************************************************/

static void zlog_file_del(zlog_file_t * a_file)
{
	zc_debug("del onefile[%p]", a_file);
	zc_debug("a_file->path[%s]", a_file->path);
	free(a_file);
}

static zlog_file_t *zlog_file_check_new(zlog_rotater_t * a_rotater, const char *path)
{
	int nwrite;
	int nread;
	zlog_file_t *a_file;

	/* base_path will not be in list */
	if (STRCMP(a_rotater->base_path, ==, path)) {
		return NULL;
	}

	/* omit dirs */
	if ((path)[strlen(path) - 1] == '/') {
		return NULL;
	}

	a_file = calloc(1, sizeof(zlog_file_t));
	if (!a_file) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	nwrite = snprintf(a_file->path, sizeof(a_file->path), "%s", path);
	if (nwrite < 0 || nwrite >= sizeof(a_file->path)) {
		zc_error("snprintf fail or overflow, nwrite=[%d], errno[%d]", nwrite, errno);
		goto err;
	}

	nread = 0;
	sscanf(a_file->path + a_rotater->num_start_len, "%d%n", &(a_file->index), &(nread));

	if (a_rotater->num_width != 0) {
		if (nread < a_rotater->num_width) {
			zc_warn("aa.1.log is not expect, need aa.01.log");
			goto err;
		}
	} /* else all file is ok */

	return a_file;
err:
	free(a_file);
	return NULL;
}


static int zlog_file_cmp(zlog_file_t * a_file_1, zlog_file_t * a_file_2)
{
	return (a_file_1->index > a_file_2->index);
}

static int zlog_rotater_add_archive_files(zlog_rotater_t * a_rotater)
{
	int rc = 0;
	glob_t glob_buf;
	size_t pathc;
	char **pathv;
	zlog_file_t *a_file;

	a_rotater->files = zc_arraylist_new((zc_arraylist_del_fn)zlog_file_del);
	if (!a_rotater->files) {
		zc_error("zc_arraylist_new fail");
		return -1;
	}

	/* scan file which is aa.*.log and aa */
	rc = glob(a_rotater->glob_path, GLOB_ERR | GLOB_MARK | GLOB_NOSORT, NULL, &glob_buf);
	if (rc == GLOB_NOMATCH) {
		goto exit;
	} else if (rc) {
		zc_error("glob err, rc=[%d], errno[%d]", rc, errno);
		return -1;
	}

	pathv = glob_buf.gl_pathv;
	pathc = glob_buf.gl_pathc;

	/* check and find match aa.[0-9]*.log, depend on num_width */
	for (; pathc-- > 0; pathv++) {
		a_file = zlog_file_check_new(a_rotater, *pathv);
		if (!a_file) {
			zc_warn("not the expect pattern file");
			continue;
		}

		/* file in list aa.00, aa.01, aa.02... */
		rc = zc_arraylist_sortadd(a_rotater->files,
					(zc_arraylist_cmp_fn)zlog_file_cmp, a_file);
		if (rc) {
			zc_error("zc_arraylist_sortadd fail");
			goto err;
		}
	}

exit:
	globfree(&glob_buf);
	return 0;
err:
	globfree(&glob_buf);
	return -1;
}

static int zlog_rotater_seq_files(zlog_rotater_t * a_rotater)
{
	int rc = 0;
	int nwrite = 0;
	int i, j;
	zlog_file_t *a_file;
	char new_path[MAXLEN_PATH + 1];

	zc_arraylist_foreach(a_rotater->files, i, a_file) {
		if (a_rotater->max_count > 0 
			&& i < zc_arraylist_len(a_rotater->files) - a_rotater->max_count) {
			/* unlink aa.0 aa.1 .. aa.(n-c) */
			rc = unlink(a_file->path);
			if (rc) {
				zc_error("unlink[%s] fail, errno[%d]",a_file->path , errno);
				return -1;
			}
			continue;
		}
	}

	if (zc_arraylist_len(a_rotater->files) > 0) { /* list is not empty */
		a_file = zc_arraylist_get(a_rotater->files, zc_arraylist_len(a_rotater->files)-1);
		if (!a_file) {
			zc_error("zc_arraylist_get fail");
			return -1;
		}

		j = zc_max(zc_arraylist_len(a_rotater->files)-1, a_file->index) + 1;
	} else {
		j = 0;
	}

	/* do the base_path mv  */
	memset(new_path, 0x00, sizeof(new_path));
	nwrite = snprintf(new_path, sizeof(new_path), "%.*s%0*d%s",
		(int) a_rotater->num_start_len, a_rotater->glob_path, 
		a_rotater->num_width, j,
		a_rotater->glob_path + a_rotater->num_end_len);
	if (nwrite < 0 || nwrite >= sizeof(new_path)) {
		zc_error("nwirte[%d], overflow or errno[%d]", nwrite, errno);
		return -1;
	}

	if (rename(a_rotater->base_path, new_path)) {
		zc_error("rename[%s]->[%s] fail, errno[%d]", a_rotater->base_path, new_path, errno);
		return -1;
	}

	return 0;
}


static int zlog_rotater_roll_files(zlog_rotater_t * a_rotater)
{
	int i;
	int rc = 0;
	int nwrite;
	char new_path[MAXLEN_PATH + 1];
	zlog_file_t *a_file;

	/* now in the list, aa.0 aa.1 aa.2 aa.02... */
	for (i = zc_arraylist_len(a_rotater->files) - 1; i > -1; i--) {
		a_file = zc_arraylist_get(a_rotater->files, i);
		if (!a_file) {
			zc_error("zc_arraylist_get fail");
			return -1;
		}

		if (a_rotater->max_count > 0 && i >= a_rotater->max_count - 1) {
			/* remove file.3 >= 3*/
			rc = unlink(a_file->path);
			if (rc) {
				zc_error("unlink[%s] fail, errno[%d]",a_file->path , errno);
				return -1;
			}
			continue;
		}

		/* begin rename aa.01.log -> aa.02.log , using i, as index in list maybe repeat */
		memset(new_path, 0x00, sizeof(new_path));
		nwrite = snprintf(new_path, sizeof(new_path), "%.*s%0*d%s",
			(int) a_rotater->num_start_len, a_rotater->glob_path, 
			a_rotater->num_width, i + 1,
			a_rotater->glob_path + a_rotater->num_end_len);
		if (nwrite < 0 || nwrite >= sizeof(new_path)) {
			zc_error("nwirte[%d], overflow or errno[%d]", nwrite, errno);
			return -1;
		}

		if (rename(a_file->path, new_path)) {
			zc_error("rename[%s]->[%s] fail, errno[%d]", a_file->path, new_path, errno);
			return -1;
		}
	}

	/* do the base_path mv  */
	memset(new_path, 0x00, sizeof(new_path));
	nwrite = snprintf(new_path, sizeof(new_path), "%.*s%0*d%s",
		(int) a_rotater->num_start_len, a_rotater->glob_path, 
		a_rotater->num_width, 0,
		a_rotater->glob_path + a_rotater->num_end_len);
	if (nwrite < 0 || nwrite >= sizeof(new_path)) {
		zc_error("nwirte[%d], overflow or errno[%d]", nwrite, errno);
		return -1;
	}

	if (rename(a_rotater->base_path, new_path)) {
		zc_error("rename[%s]->[%s] fail, errno[%d]", a_rotater->base_path, new_path, errno);
		return -1;
	}

	return 0;
}


static int zlog_rotater_parse_archive_path(zlog_rotater_t * a_rotater)
{
	int nwrite;
	int nread;
	char *p;
	size_t len;

	/* no archive path is set */
	if (a_rotater->archive_path[0] == '\0') {
		nwrite = snprintf(a_rotater->glob_path, sizeof(a_rotater->glob_path),
					"%s.*", a_rotater->base_path);
		if (nwrite < 0 || nwrite > sizeof(a_rotater->glob_path)) {
			zc_error("nwirte[%d], overflow or errno[%d]", nwrite, errno);
			return -1;
		}

		a_rotater->mv_type = ROLLING;
		a_rotater->num_width = 0;
		a_rotater->num_start_len = strlen(a_rotater->base_path) + 1;
		a_rotater->num_end_len = strlen(a_rotater->base_path) + 2;
		return 0;
	} else {

		/* find the 1st # */
		p = strchr(a_rotater->archive_path, '#');
		if (!p) {
			zc_error("no # in archive_path[%s]", a_rotater->archive_path);
			return -1;
		}

		nread = 0;
		sscanf(p, "#%d%n", &(a_rotater->num_width), &nread);
		if (nread == 0) nread = 1;
		if (*(p+nread) == 'r') {
			a_rotater->mv_type = ROLLING;
		} else if (*(p+nread) == 's') {
			a_rotater->mv_type = SEQUENCE;
		} else {
			zc_error("#r or #s not found");
			return -1;
		}

		/* copy and substitue #i to * in glob_path*/
		len = p - a_rotater->archive_path;
		if (len > sizeof(a_rotater->glob_path) - 1) {
			zc_error("sizeof glob_path not enough,len[%ld]", (long) len);
			return -1;
		}
		memcpy(a_rotater->glob_path, a_rotater->archive_path, len);

		nwrite = snprintf(a_rotater->glob_path + len, sizeof(a_rotater->glob_path) - len,
				"*%s", p + nread + 1);
		if (nwrite < 0 || nwrite > sizeof(a_rotater->glob_path) - len) {
			zc_error("nwirte[%d], overflow or errno[%d]", nwrite, errno);
			return -1;
		}

		a_rotater->num_start_len = len;
		a_rotater->num_end_len = len + 1;
	}
	
	return 0;
}

static void zlog_rotater_clean(zlog_rotater_t *a_rotater)
{
	a_rotater->base_path = NULL;
	a_rotater->archive_path = NULL;
	a_rotater->max_count = 0;
	a_rotater->mv_type = 0;
	a_rotater->num_width = 0;
	a_rotater->num_start_len = 0;
	a_rotater->num_end_len = 0;
	memset(a_rotater->glob_path, 0x00, sizeof(a_rotater->glob_path));

	if (a_rotater->files) zc_arraylist_del(a_rotater->files);
	a_rotater->files = NULL;
}

static int zlog_rotater_lsmv(zlog_rotater_t *a_rotater, 
		char *base_path, char *archive_path, int archive_max_count)
{
	int rc = 0;

	a_rotater->base_path = base_path;
	a_rotater->archive_path = archive_path;
	a_rotater->max_count = archive_max_count;
	rc = zlog_rotater_parse_archive_path(a_rotater);
	if (rc) {
		zc_error("zlog_rotater_parse_archive_path fail");
		goto err;
	}

	rc = zlog_rotater_add_archive_files(a_rotater);
	if (rc) {
		zc_error("zlog_rotater_add_archive_files fail");
		goto err;
	}

	if (a_rotater->mv_type == ROLLING) {
		rc = zlog_rotater_roll_files(a_rotater);
		if (rc) {
			zc_error("zlog_rotater_roll_files fail");
			goto err;
		}
	} else if (a_rotater->mv_type == SEQUENCE) {
		rc = zlog_rotater_seq_files(a_rotater);
		if (rc) {
			zc_error("zlog_rotater_seq_files fail");
			goto err;
		}
	}

	zlog_rotater_clean(a_rotater);
	return 0;
err:
	zlog_rotater_clean(a_rotater);
	return -1;
}
/*******************************************************************************/

static int zlog_rotater_trylock(zlog_rotater_t *a_rotater)
{
	int rc;
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	rc = pthread_mutex_trylock(&(a_rotater->lock_mutex));
	if (rc == EBUSY) {
		zc_warn("pthread_mutex_trylock fail, as lock_mutex is locked by other threads");
		return -1;
	} else if (rc != 0) {
		zc_error("pthread_mutex_trylock fail, rc[%d]", rc);
		return -1;
	}

	if (fcntl(a_rotater->lock_fd, F_SETLK, &fl)) {
		if (errno == EAGAIN || errno == EACCES) {
			/* lock by other process, that's right, go on */
			/* EAGAIN on linux */
			/* EACCES on AIX */
			zc_warn("fcntl lock fail, as file is lock by other process");
		} else {
			zc_error("lock fd[%d] fail, errno[%d]", a_rotater->lock_fd, errno);
		}
		if (pthread_mutex_unlock(&(a_rotater->lock_mutex))) {
			zc_error("pthread_mutex_unlock fail, errno[%d]", errno);
		}
		return -1;
	}

	return 0;
}

static int zlog_rotater_unlock(zlog_rotater_t *a_rotater)
{
	int rc = 0;
	struct flock fl;

	fl.l_type = F_UNLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	if (fcntl(a_rotater->lock_fd, F_SETLK, &fl)) {
		rc = -1;
		zc_error("unlock fd[%s] fail, errno[%d]", a_rotater->lock_fd, errno);
	}

	if (pthread_mutex_unlock(&(a_rotater->lock_mutex))) {
		rc = -1;
		zc_error("pthread_mutext_unlock fail, errno[%d]", errno);
	}

	return rc;
}

int zlog_rotater_rotate(zlog_rotater_t *a_rotater,
		char *base_path, size_t msg_len,
		char *archive_path, long archive_max_size, int archive_max_count)
{
	int rc = 0;
	struct zlog_stat info;

	zc_assert(base_path, -1);

	if (zlog_rotater_trylock(a_rotater)) {
		zc_warn("zlog_rotater_trylock fail, maybe lock by other process or threads");
		return 0;
	}

	if (stat(base_path, &info)) {
		rc = -1;
		zc_error("stat [%s] fail, errno[%d]", base_path, errno);
		goto exit;
	}

	if (info.st_size + msg_len <= archive_max_size) {
		/* file not so big,
		 * may alread rotate by oth process or thread,
		 * return */
		rc = 0;
		goto exit;
	}

	/* begin list and move files */
	rc = zlog_rotater_lsmv(a_rotater, base_path, archive_path, archive_max_count);
	if (rc) {
		zc_error("zlog_rotater_lsmv [%s] fail, return", base_path);
		rc = -1;
	} /* else if (rc == 0) */

	//zc_debug("zlog_rotater_file_ls_mv success");

exit:
	/* unlock file */
	if (zlog_rotater_unlock(a_rotater)) {
		zc_error("zlog_rotater_unlock fail");
	}

	return rc;
}

/*******************************************************************************/
