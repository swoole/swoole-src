/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2017 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Wez Furlong <wez@thebrainroom.com>                          |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#include "php.h"
#include "php_globals.h"
#include "php_network.h"
#include "php_open_temporary_file.h"
#include "ext/standard/file.h"
#include "ext/standard/flock_compat.h"
#include "ext/standard/php_filestat.h"
#include <stddef.h>
#include <fcntl.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include "SAPI.h"

#include "thirdparty/php/streams/php_streams_int.h"
#ifdef PHP_WIN32
# include "win32/winutil.h"
# include "win32/time.h"
# include "win32/ioutil.h"
# include "win32/readdir.h"
#endif

#include "file_hook.h"

#if !defined(WINDOWS) && !defined(NETWARE)
extern int php_get_uid_by_name(const char *name, uid_t *uid);
extern int php_get_gid_by_name(const char *name, gid_t *gid);
#endif

#if defined(PHP_WIN32)
# define PLAIN_WRAP_BUF_SIZE(st) (((st) > UINT_MAX) ? UINT_MAX : (unsigned int)(st))
#else
# define PLAIN_WRAP_BUF_SIZE(st) (st)
#endif

#if PHP_VERSION_ID < 70400
static size_t php_stdiop_write(php_stream *stream, const char *buf, size_t count);
static size_t php_stdiop_read(php_stream *stream, char *buf, size_t count);
#else
static ssize_t php_stdiop_write(php_stream *stream, const char *buf, size_t count);
static ssize_t php_stdiop_read(php_stream *stream, char *buf, size_t count);
#endif
static int sw_php_stdiop_close(php_stream *stream, int close_handle);
static int php_stdiop_stat(php_stream *stream, php_stream_statbuf *ssb);
static int php_stdiop_flush(php_stream *stream);
static int php_stdiop_seek(php_stream *stream, zend_off_t offset, int whence, zend_off_t *newoffset);
static int php_stdiop_set_option(php_stream *stream, int option, int value, void *ptrparam);
static int php_stdiop_cast(php_stream *stream, int castas, void **ret);

static void php_stream_mode_sanitize_fdopen_fopencookie(php_stream *stream, char *result);
static php_stream *_sw_php_stream_fopen_from_fd_int(int fd, const char *mode, const char *persistent_id STREAMS_DC);
static php_stream *_sw_php_stream_fopen_from_fd(int fd, const char *mode, const char *persistent_id STREAMS_DC);

static int sw_php_stream_parse_fopen_modes(const char *mode, int *open_flags)
{
    int flags;

    switch (mode[0])
    {
    case 'r':
        flags = 0;
        break;
    case 'w':
        flags = O_TRUNC | O_CREAT;
        break;
    case 'a':
        flags = O_CREAT | O_APPEND;
        break;
    case 'x':
        flags = O_CREAT | O_EXCL;
        break;
    case 'c':
        flags = O_CREAT;
        break;
    default:
        /* unknown mode */
        return FAILURE;
    }

    if (strchr(mode, '+'))
    {
        flags |= O_RDWR;
    }
    else if (flags)
    {
        flags |= O_WRONLY;
    }
    else
    {
        flags |= O_RDONLY;
    }

#if defined(O_CLOEXEC)
    if (strchr(mode, 'e'))
    {
        flags |= O_CLOEXEC;
    }
#endif

#if defined(O_NONBLOCK)
    if (strchr(mode, 'n'))
    {
        flags |= O_NONBLOCK;
    }
#endif

#if defined(_O_TEXT) && defined(O_BINARY)
    if (strchr(mode, 't'))
    {
        flags |= _O_TEXT;
    }
    else
    {
        flags |= O_BINARY;
    }
#endif

    *open_flags = flags;
    return SUCCESS;
}

#define stream_fopen_from_fd_rel(fd, mode, persistent_id)    _sw_php_stream_fopen_from_fd((fd), (mode), (persistent_id) STREAMS_REL_CC)
#define sw_php_stream_fopen_from_fd_int(fd, mode, persistent_id)   _sw_php_stream_fopen_from_fd_int((fd), (mode), (persistent_id) STREAMS_CC)
#define sw_php_stream_fopen_from_fd_int_rel(fd, mode, persistent_id)    _sw_php_stream_fopen_from_fd_int((fd), (mode), (persistent_id) STREAMS_REL_CC)

/* {{{ ------- STDIO stream implementation -------*/

typedef struct {
	FILE *file;
	int fd;					/* underlying file descriptor */
	unsigned is_process_pipe:1;	/* use pclose instead of fclose */
	unsigned is_pipe:1;			/* don't try and seek */
	unsigned cached_fstat:1;	/* sb is valid */
	unsigned is_pipe_blocking:1; /* allow blocking read() on pipes, currently Windows only */
	unsigned _reserved:28;

	int lock_flag;			/* stores the lock state */
	zend_string *temp_name;	/* if non-null, this is the path to a temporary file that
							 * is to be deleted when the stream is closed */
#if HAVE_FLUSHIO
	char last_op;
#endif

#if HAVE_MMAP
	char *last_mapped_addr;
	size_t last_mapped_len;
#endif
#ifdef PHP_WIN32
	char *last_mapped_addr;
	HANDLE file_mapping;
#endif

	zend_stat_t sb;
} php_stdio_stream_data;

#define PHP_STDIOP_GET_FD(anfd, data)	anfd = (data)->file ? fileno((data)->file) : (data)->fd

static php_stream_ops sw_php_stream_stdio_ops = {
    php_stdiop_write,
    php_stdiop_read,
    sw_php_stdiop_close,
    php_stdiop_flush,
    "STDIO/coroutine",
    php_stdiop_seek,
    php_stdiop_cast,
    php_stdiop_stat,
    php_stdiop_set_option
};

static int do_fstat(php_stdio_stream_data *d, int force)
{
	if (!d->cached_fstat || force) {
		int fd;
		int r;

		PHP_STDIOP_GET_FD(fd, d);
		r = fstat(fd, &d->sb);
		d->cached_fstat = r == 0;

		return r;
	}
	return 0;
}

static php_stream *_sw_php_stream_fopen_from_fd_int(int fd, const char *mode, const char *persistent_id STREAMS_DC)
{
    php_stdio_stream_data *self = (php_stdio_stream_data *) pemalloc_rel_orig(sizeof(*self), persistent_id);
    memset(self, 0, sizeof(*self));
    self->file = NULL;
    self->is_pipe = 0;
    self->lock_flag = LOCK_UN;
    self->is_process_pipe = 0;
    self->temp_name = NULL;
    self->fd = fd;
    return php_stream_alloc_rel(&sw_php_stream_stdio_ops, self, persistent_id, mode);
}

#if PHP_VERSION_ID < 70400
static size_t php_stdiop_write(php_stream *stream, const char *buf, size_t count)
#else
static ssize_t php_stdiop_write(php_stream *stream, const char *buf, size_t count)
#endif
{
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;

    assert(data != NULL);

    if (data->fd >= 0)
    {
        int bytes_written = write(data->fd, buf, count);
#if PHP_VERSION_ID < 70400
        if (bytes_written < 0)
        {
            return 0;
        }
        return (size_t) bytes_written;
#else
        return bytes_written;
#endif
    }
    else
    {
        return fwrite(buf, 1, count, data->file);
    }
}

#if PHP_VERSION_ID < 70400
static size_t php_stdiop_read(php_stream *stream, char *buf, size_t count)
#else
static ssize_t php_stdiop_read(php_stream *stream, char *buf, size_t count)
#endif
{
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;
    size_t ret;

    assert(data != NULL);

    if (data->fd >= 0)
    {
        ret = read(data->fd, buf, PLAIN_WRAP_BUF_SIZE(count));

        if (ret == (size_t) -1 && errno == EINTR)
        {
            /* Read was interrupted, retry once,
             If read still fails, giveup with feof==0
             so script can retry if desired */
            ret = read(data->fd, buf, PLAIN_WRAP_BUF_SIZE(count));
        }

        stream->eof = (ret == 0 || (ret == (size_t) -1 && errno != EWOULDBLOCK && errno != EINTR && errno != EBADF));
    }
    else
    {
        ret = fread(buf, 1, count, data->file);
        stream->eof = feof(data->file);
    }
    return ret;
}

static int sw_php_stdiop_close(php_stream *stream, int close_handle)
{
    int ret;
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;

    assert(data != NULL);

    if (data->last_mapped_addr)
    {
        munmap(data->last_mapped_addr, data->last_mapped_len);
        data->last_mapped_addr = NULL;
    }

    if (close_handle)
    {
        if (data->file)
        {
            if (data->is_process_pipe)
            {
                errno = 0;
                ret = pclose(data->file);

#if HAVE_SYS_WAIT_H
                if (WIFEXITED(ret))
                {
                    ret = WEXITSTATUS(ret);
                }
#endif
            }
            else
            {
                ret = fclose(data->file);
                data->file = NULL;
            }
        }
        else if (data->fd != -1)
        {
            if ((data->lock_flag & LOCK_EX) || (data->lock_flag & LOCK_SH))
            {
                swoole_coroutine_flock_ex(stream->orig_path, data->fd, LOCK_UN);
            }
            ret = close(data->fd);
            data->fd = -1;
        }
        else
        {
            return 0; /* everything should be closed already -> success */
        }
        if (data->temp_name)
        {
            unlink(ZSTR_VAL(data->temp_name));
            /* temporary streams are never persistent */
            zend_string_release(data->temp_name);
            data->temp_name = NULL;
        }
    }
    else
    {
        ret = 0;
        data->file = NULL;
        data->fd = -1;
    }

    pefree(data, stream->is_persistent);

    return ret;
}

static int php_stdiop_flush(php_stream *stream)
{
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;

    assert(data != NULL);

    /*
     * stdio buffers data in user land. By calling fflush(3), this
     * data is send to the kernel using write(2). fsync'ing is
     * something completely different.
     */
    if (data->file)
    {
        return fflush(data->file);
    }
    return 0;
}

static int php_stdiop_seek(php_stream *stream, zend_off_t offset, int whence, zend_off_t *newoffset)
{
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;
    int ret;

    assert(data != NULL);

    if (data->is_pipe)
    {
        php_error_docref(NULL, E_WARNING, "cannot seek on a pipe");
        return -1;
    }

    if (data->fd >= 0)
    {
        zend_off_t result;

        result = lseek(data->fd, offset, whence);
        if (result == (zend_off_t) -1)
            return -1;

        *newoffset = result;
        return 0;

    }
    else
    {
        ret = zend_fseek(data->file, offset, whence);
        *newoffset = zend_ftell(data->file);
        return ret;
    }
}

static int php_stdiop_cast(php_stream *stream, int castas, void **ret)
{
    php_socket_t fd;
    php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;

    assert(data != NULL);

    /* as soon as someone touches the stdio layer, buffering may ensue,
     * so we need to stop using the fd directly in that case */

    switch (castas)
    {
    case PHP_STREAM_AS_STDIO:
        if (ret)
        {
            if (data->file == NULL)
            {
                /* we were opened as a plain file descriptor, so we
                 * need fdopen now */
                char fixed_mode[5];
                php_stream_mode_sanitize_fdopen_fopencookie(stream, fixed_mode);
                data->file = fdopen(data->fd, fixed_mode);
                if (data->file == NULL)
                {
                    return FAILURE;
                }
            }

            *(FILE**) ret = data->file;
            data->fd = SOCK_ERR;
        }
        return SUCCESS;

    case PHP_STREAM_AS_FD_FOR_SELECT:
        PHP_STDIOP_GET_FD(fd, data);
        if (SOCK_ERR == fd)
        {
            return FAILURE;
        }
        if (ret)
        {
            *(php_socket_t *) ret = fd;
        }
        return SUCCESS;

    case PHP_STREAM_AS_FD:
        PHP_STDIOP_GET_FD(fd, data);

        if (SOCK_ERR == fd)
        {
            return FAILURE;
        }
        if (data->file)
        {
            fflush(data->file);
        }
        if (ret)
        {
            *(php_socket_t *) ret = fd;
        }
        return SUCCESS;
    default:
        return FAILURE;
    }
}

static int php_stdiop_stat(php_stream *stream, php_stream_statbuf *ssb)
{
	int ret;
	php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;

	assert(data != NULL);
	if((ret = do_fstat(data, 1)) == 0) {
		memcpy(&ssb->sb, &data->sb, sizeof(ssb->sb));
	}

	return ret;
}

static int php_stdiop_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
	php_stdio_stream_data *data = (php_stdio_stream_data*) stream->abstract;
	size_t size;
	int fd;
#ifdef O_NONBLOCK
	/* FIXME: make this work for win32 */
	int flags;
	int oldval;
#endif

	PHP_STDIOP_GET_FD(fd, data);

	switch(option) {
		case PHP_STREAM_OPTION_BLOCKING:
			if (fd == -1)
				return -1;
#ifdef O_NONBLOCK
			flags = fcntl(fd, F_GETFL, 0);
			oldval = (flags & O_NONBLOCK) ? 0 : 1;
			if (value)
				flags &= ~O_NONBLOCK;
			else
				flags |= O_NONBLOCK;

			if (-1 == fcntl(fd, F_SETFL, flags))
				return -1;
			return oldval;
#else
			return -1; /* not yet implemented */
#endif

		case PHP_STREAM_OPTION_WRITE_BUFFER:

			if (data->file == NULL) {
				return -1;
			}

			if (ptrparam)
				size = *(size_t *)ptrparam;
			else
				size = BUFSIZ;

			switch(value) {
				case PHP_STREAM_BUFFER_NONE:
					return setvbuf(data->file, NULL, _IONBF, 0);

				case PHP_STREAM_BUFFER_LINE:
					return setvbuf(data->file, NULL, _IOLBF, size);

				case PHP_STREAM_BUFFER_FULL:
					return setvbuf(data->file, NULL, _IOFBF, size);

				default:
					return -1;
			}
			break;

		case PHP_STREAM_OPTION_LOCKING:
			if (fd == -1) {
				return -1;
			}

			if ((zend_uintptr_t) ptrparam == PHP_STREAM_LOCK_SUPPORTED) {
				return 0;
			}

			if (!swoole_coroutine_flock_ex(stream->orig_path, fd, value)) {
				data->lock_flag = value;
				return 0;
			} else {
				return -1;
			}
			break;

		case PHP_STREAM_OPTION_MMAP_API:
#if HAVE_MMAP
			{
				php_stream_mmap_range *range = (php_stream_mmap_range*)ptrparam;
				int prot, flags;

				switch (value) {
					case PHP_STREAM_MMAP_SUPPORTED:
						return fd == -1 ? PHP_STREAM_OPTION_RETURN_ERR : PHP_STREAM_OPTION_RETURN_OK;

					case PHP_STREAM_MMAP_MAP_RANGE:
						if(do_fstat(data, 1) != 0) {
							return PHP_STREAM_OPTION_RETURN_ERR;
						}
						if (range->length == 0 && range->offset > 0 && range->offset < (size_t)data->sb.st_size) {
							range->length = data->sb.st_size - range->offset;
						}
						if (range->length == 0 || range->length > (size_t)data->sb.st_size) {
							range->length = data->sb.st_size;
						}
						if (range->offset >= (size_t)data->sb.st_size) {
							range->offset = data->sb.st_size;
							range->length = 0;
						}
						switch (range->mode) {
							case PHP_STREAM_MAP_MODE_READONLY:
								prot = PROT_READ;
								flags = MAP_PRIVATE;
								break;
							case PHP_STREAM_MAP_MODE_READWRITE:
								prot = PROT_READ | PROT_WRITE;
								flags = MAP_PRIVATE;
								break;
							case PHP_STREAM_MAP_MODE_SHARED_READONLY:
								prot = PROT_READ;
								flags = MAP_SHARED;
								break;
							case PHP_STREAM_MAP_MODE_SHARED_READWRITE:
								prot = PROT_READ | PROT_WRITE;
								flags = MAP_SHARED;
								break;
							default:
								return PHP_STREAM_OPTION_RETURN_ERR;
						}
						range->mapped = (char*)mmap(NULL, range->length, prot, flags, fd, range->offset);
						if (range->mapped == (char*)MAP_FAILED) {
							range->mapped = NULL;
							return PHP_STREAM_OPTION_RETURN_ERR;
						}
						/* remember the mapping */
						data->last_mapped_addr = range->mapped;
						data->last_mapped_len = range->length;
						return PHP_STREAM_OPTION_RETURN_OK;

					case PHP_STREAM_MMAP_UNMAP:
						if (data->last_mapped_addr) {
							munmap(data->last_mapped_addr, data->last_mapped_len);
							data->last_mapped_addr = NULL;

							return PHP_STREAM_OPTION_RETURN_OK;
						}
						return PHP_STREAM_OPTION_RETURN_ERR;
				}
			}
#elif defined(PHP_WIN32)
			{
				php_stream_mmap_range *range = (php_stream_mmap_range*)ptrparam;
				HANDLE hfile = (HANDLE)_get_osfhandle(fd);
				DWORD prot, acc, loffs = 0, delta = 0;

				switch (value) {
					case PHP_STREAM_MMAP_SUPPORTED:
						return hfile == INVALID_HANDLE_VALUE ? PHP_STREAM_OPTION_RETURN_ERR : PHP_STREAM_OPTION_RETURN_OK;

					case PHP_STREAM_MMAP_MAP_RANGE:
						switch (range->mode) {
							case PHP_STREAM_MAP_MODE_READONLY:
								prot = PAGE_READONLY;
								acc = FILE_MAP_READ;
								break;
							case PHP_STREAM_MAP_MODE_READWRITE:
								prot = PAGE_READWRITE;
								acc = FILE_MAP_READ | FILE_MAP_WRITE;
								break;
							case PHP_STREAM_MAP_MODE_SHARED_READONLY:
								prot = PAGE_READONLY;
								acc = FILE_MAP_READ;
								/* TODO: we should assign a name for the mapping */
								break;
							case PHP_STREAM_MAP_MODE_SHARED_READWRITE:
								prot = PAGE_READWRITE;
								acc = FILE_MAP_READ | FILE_MAP_WRITE;
								/* TODO: we should assign a name for the mapping */
								break;
							default:
								return PHP_STREAM_OPTION_RETURN_ERR;
						}

						/* create a mapping capable of viewing the whole file (this costs no real resources) */
						data->file_mapping = CreateFileMapping(hfile, NULL, prot, 0, 0, NULL);

						if (data->file_mapping == NULL) {
							return PHP_STREAM_OPTION_RETURN_ERR;
						}

						size = GetFileSize(hfile, NULL);
						if (range->length == 0 && range->offset > 0 && range->offset < size) {
							range->length = size - range->offset;
						}
						if (range->length == 0 || range->length > size) {
							range->length = size;
						}
						if (range->offset >= size) {
							range->offset = size;
							range->length = 0;
						}

						/* figure out how big a chunk to map to be able to view the part that we need */
						if (range->offset != 0) {
							SYSTEM_INFO info;
							DWORD gran;

							GetSystemInfo(&info);
							gran = info.dwAllocationGranularity;
							loffs = ((DWORD)range->offset / gran) * gran;
							delta = (DWORD)range->offset - loffs;
						}

						data->last_mapped_addr = MapViewOfFile(data->file_mapping, acc, 0, loffs, range->length + delta);

						if (data->last_mapped_addr) {
							/* give them back the address of the start offset they requested */
							range->mapped = data->last_mapped_addr + delta;
							return PHP_STREAM_OPTION_RETURN_OK;
						}

						CloseHandle(data->file_mapping);
						data->file_mapping = NULL;

						return PHP_STREAM_OPTION_RETURN_ERR;

					case PHP_STREAM_MMAP_UNMAP:
						if (data->last_mapped_addr) {
							UnmapViewOfFile(data->last_mapped_addr);
							data->last_mapped_addr = NULL;
							CloseHandle(data->file_mapping);
							data->file_mapping = NULL;
							return PHP_STREAM_OPTION_RETURN_OK;
						}
						return PHP_STREAM_OPTION_RETURN_ERR;

					default:
						return PHP_STREAM_OPTION_RETURN_ERR;
				}
			}

#endif
			return PHP_STREAM_OPTION_RETURN_NOTIMPL;

		case PHP_STREAM_OPTION_TRUNCATE_API:
			switch (value) {
				case PHP_STREAM_TRUNCATE_SUPPORTED:
					return fd == -1 ? PHP_STREAM_OPTION_RETURN_ERR : PHP_STREAM_OPTION_RETURN_OK;

				case PHP_STREAM_TRUNCATE_SET_SIZE: {
					ptrdiff_t new_size = *(ptrdiff_t*)ptrparam;
					if (new_size < 0) {
						return PHP_STREAM_OPTION_RETURN_ERR;
					}
					return ftruncate(fd, new_size) == 0 ? PHP_STREAM_OPTION_RETURN_OK : PHP_STREAM_OPTION_RETURN_ERR;
				}
			}

#ifdef PHP_WIN32
		case PHP_STREAM_OPTION_PIPE_BLOCKING:
			data->is_pipe_blocking = value;
			return PHP_STREAM_OPTION_RETURN_OK;
#endif
		case PHP_STREAM_OPTION_META_DATA_API:
			if (fd == -1)
				return -1;
#ifdef O_NONBLOCK
			flags = fcntl(fd, F_GETFL, 0);

			add_assoc_bool((zval*)ptrparam, "timed_out", 0);
			add_assoc_bool((zval*)ptrparam, "blocked", (flags & O_NONBLOCK)? 0 : 1);
			add_assoc_bool((zval*)ptrparam, "eof", stream->eof);

			return PHP_STREAM_OPTION_RETURN_OK;
#endif
			return -1;
		default:
			return PHP_STREAM_OPTION_RETURN_NOTIMPL;
	}
}
/* }}} */

/* {{{ plain files opendir/readdir implementation */
#if PHP_VERSION_ID < 70400
static size_t php_plain_files_dirstream_read(php_stream *stream, char *buf, size_t count)
#else
static ssize_t php_plain_files_dirstream_read(php_stream *stream, char *buf, size_t count)
#endif
{
    DIR *dir = (DIR*) stream->abstract;
    struct dirent *result;
    php_stream_dirent *ent = (php_stream_dirent*) buf;

	/* avoid problems if someone mis-uses the stream */
	if (count != sizeof(php_stream_dirent)) {
	    return 0;
	}

	if ((result = readdir(dir))) {
		PHP_STRLCPY(ent->d_name, result->d_name, sizeof(ent->d_name), strlen(result->d_name));
		return sizeof(php_stream_dirent);
	}
	return 0;
}

static int php_plain_files_dirstream_close(php_stream *stream, int close_handle)
{
	return closedir((DIR *)stream->abstract);
}

static int php_plain_files_dirstream_rewind(php_stream *stream, zend_off_t offset, int whence, zend_off_t *newoffs)
{
	rewinddir((DIR *)stream->abstract);
	return 0;
}

static php_stream_ops	php_plain_files_dirstream_ops = {
	NULL, php_plain_files_dirstream_read,
	php_plain_files_dirstream_close, NULL,
	"dir",
	php_plain_files_dirstream_rewind,
	NULL, /* cast */
	NULL, /* stat */
	NULL  /* set_option */
};

static php_stream *php_plain_files_dir_opener(php_stream_wrapper *wrapper, const char *path, const char *mode,
		int options, zend_string **opened_path, php_stream_context *context STREAMS_DC)
{
	DIR *dir = NULL;
	php_stream *stream = NULL;

#ifdef HAVE_GLOB
	if (options & STREAM_USE_GLOB_DIR_OPEN) {
		return php_glob_stream_wrapper.wops->dir_opener((php_stream_wrapper*)&php_glob_stream_wrapper, path, mode, options, opened_path, context STREAMS_REL_CC);
	}
#endif

	if (((options & STREAM_DISABLE_OPEN_BASEDIR) == 0) && php_check_open_basedir(path)) {
		return NULL;
	}

	dir = opendir(path);

#ifdef PHP_WIN32
	if (!dir) {
		php_win32_docref2_from_error(GetLastError(), path, path);
	}

	if (dir && dir->finished) {
		closedir(dir);
		dir = NULL;
	}
#endif
	if (dir) {
		stream = php_stream_alloc(&php_plain_files_dirstream_ops, dir, 0, mode);
		if (stream == NULL)
			closedir(dir);
	}

	return stream;
}
/* }}} */

static php_stream *stream_fopen_rel(const char *filename, const char *mode, zend_string **opened_path, int options STREAMS_DC)
{
    char _realpath[MAXPATHLEN];
    int open_flags;
    int fd;
    php_stream *ret;
    int persistent = options & STREAM_OPEN_PERSISTENT;
    char *persistent_id = NULL;

    if (FAILURE == sw_php_stream_parse_fopen_modes(mode, &open_flags))
    {
        if (options & REPORT_ERRORS)
        {
            php_error_docref(NULL, E_WARNING, "`%s' is not a valid mode for fopen", mode);
        }
        return NULL;
    }

    if (options & STREAM_ASSUME_REALPATH)
    {
        strlcpy(_realpath, filename, sizeof(_realpath));
    }
    else
    {
        if (expand_filepath(filename, _realpath) == NULL)
        {
            return NULL;
        }
    }

    if (persistent)
    {
        spprintf(&persistent_id, 0, "streams_stdio_%d_%s", open_flags, _realpath);
        switch (php_stream_from_persistent_id(persistent_id, &ret))
        {
        case PHP_STREAM_PERSISTENT_SUCCESS:
            if (opened_path)
            {
                //TODO: avoid reallocation???
                *opened_path = zend_string_init(_realpath, strlen(_realpath), 0);
            }
            /* fall through */

        case PHP_STREAM_PERSISTENT_FAILURE:
            efree(persistent_id);
            return ret;
        }
    }
#ifdef PHP_WIN32
	fd = php_win32_ioutil_open(_realpath, open_flags, 0666);
#else
	fd = open(_realpath, open_flags, 0666);
#endif
    if (fd != -1)
    {
        ret = stream_fopen_from_fd_rel(fd, mode, persistent_id);
        if (ret)
        {
            if (opened_path)
            {
                *opened_path = zend_string_init(_realpath, strlen(_realpath), 0);
            }
            if (persistent_id)
            {
                efree(persistent_id);
            }

			/* WIN32 always set ISREG flag */
#ifndef PHP_WIN32
			/* sanity checks for include/require.
			 * We check these after opening the stream, so that we save
			 * on fstat() syscalls */
			if (options & STREAM_OPEN_FOR_INCLUDE) {
				php_stdio_stream_data *self = (php_stdio_stream_data*)ret->abstract;
				int r;

				r = do_fstat(self, 0);
				if ((r == 0 && !S_ISREG(self->sb.st_mode))) {
					if (opened_path) {
						zend_string_release(*opened_path);
						*opened_path = NULL;
					}
					php_stream_close(ret);
					return NULL;
				}
			}

			if (options & STREAM_USE_BLOCKING_PIPE) {
				php_stdio_stream_data *self = (php_stdio_stream_data*)ret->abstract;
				self->is_pipe_blocking = 1;
			}
#endif

			return ret;
		}
		close(fd);
	}
	if (persistent_id) {
		efree(persistent_id);
	}
	return NULL;
}

static php_stream *stream_opener(php_stream_wrapper *wrapper, const char *path, const char *mode, int options,
        zend_string **opened_path, php_stream_context *context STREAMS_DC)
{
    if (((options & STREAM_DISABLE_OPEN_BASEDIR) == 0) && php_check_open_basedir(path))
    {
        return NULL;
    }
    /**
     * include file, cannot use async-io
     */
    if (options & STREAM_OPEN_FOR_INCLUDE)
    {
        return php_stream_fopen_rel(path, mode, opened_path, options);
    }
    else
    {
        return stream_fopen_rel(path, mode, opened_path, options STREAMS_REL_CC);
    }
}

static int php_plain_files_url_stater(php_stream_wrapper *wrapper, const char *url, int flags, php_stream_statbuf *ssb, php_stream_context *context)
{
	if (strncasecmp(url, "file://", sizeof("file://") - 1) == 0) {
		url += sizeof("file://") - 1;
	}

	if (php_check_open_basedir_ex(url, (flags & PHP_STREAM_URL_STAT_QUIET) ? 0 : 1)) {
		return -1;
	}

#ifdef PHP_WIN32
	if (flags & PHP_STREAM_URL_STAT_LINK) {
		return lstat(url, &ssb->sb);
	}
#else
# ifdef HAVE_SYMLINK
	if (flags & PHP_STREAM_URL_STAT_LINK) {
		return lstat(url, &ssb->sb);
	} else
# endif
#endif
		return stat(url, &ssb->sb);
}

static int php_plain_files_unlink(php_stream_wrapper *wrapper, const char *url, int options, php_stream_context *context)
{
	int ret;

	if (strncasecmp(url, "file://", sizeof("file://") - 1) == 0) {
		url += sizeof("file://") - 1;
	}

	if (php_check_open_basedir(url)) {
		return 0;
	}

	ret = unlink(url);
	if (ret == -1) {
		if (options & REPORT_ERRORS) {
			php_error_docref1(NULL, url, E_WARNING, "%s", strerror(errno));
		}
		return 0;
	}

	/* Clear stat cache (and realpath cache) */
	php_clear_stat_cache(1, NULL, 0);

	return 1;
}

static int php_plain_files_rename(php_stream_wrapper *wrapper, const char *url_from, const char *url_to, int options, php_stream_context *context)
{
	int ret;

	if (!url_from || !url_to) {
		return 0;
	}

#ifdef PHP_WIN32
	if (!php_win32_check_trailing_space(url_from, (int)strlen(url_from))) {
		php_win32_docref2_from_error(ERROR_INVALID_NAME, url_from, url_to);
		return 0;
	}
	if (!php_win32_check_trailing_space(url_to, (int)strlen(url_to))) {
		php_win32_docref2_from_error(ERROR_INVALID_NAME, url_from, url_to);
		return 0;
	}
#endif

	if (strncasecmp(url_from, "file://", sizeof("file://") - 1) == 0) {
		url_from += sizeof("file://") - 1;
	}

	if (strncasecmp(url_to, "file://", sizeof("file://") - 1) == 0) {
		url_to += sizeof("file://") - 1;
	}

	if (php_check_open_basedir(url_from) || php_check_open_basedir(url_to)) {
		return 0;
	}

	ret = rename(url_from, url_to);

	if (ret == -1) {
#ifndef PHP_WIN32
# ifdef EXDEV
		if (errno == EXDEV) {
			zend_stat_t sb;
			if (php_copy_file(url_from, url_to) == SUCCESS) {
				if (stat(url_from, &sb) == 0) {
#  if !defined(TSRM_WIN32) && !defined(NETWARE)
					if (chmod(url_to, sb.st_mode)) {
						if (errno == EPERM) {
							php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
							unlink(url_from);
							return 1;
						}
						php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
						return 0;
					}
					if (chown(url_to, sb.st_uid, sb.st_gid)) {
						if (errno == EPERM) {
							php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
							unlink(url_from);
							return 1;
						}
						php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
						return 0;
					}
#  endif
					unlink(url_from);
					return 1;
				}
			}
			php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
			return 0;
		}
# endif
#endif

#ifdef PHP_WIN32
		php_win32_docref2_from_error(GetLastError(), url_from, url_to);
#else
		php_error_docref2(NULL, url_from, url_to, E_WARNING, "%s", strerror(errno));
#endif
		return 0;
	}

	/* Clear stat cache (and realpath cache) */
	php_clear_stat_cache(1, NULL, 0);

	return 1;
}

static int php_plain_files_mkdir(php_stream_wrapper *wrapper, const char *dir, int mode, int options, php_stream_context *context)
{
	int ret, recursive = options & PHP_STREAM_MKDIR_RECURSIVE;
	char *p;

	if (strncasecmp(dir, "file://", sizeof("file://") - 1) == 0) {
		dir += sizeof("file://") - 1;
	}

	if (!recursive) {
		ret = mkdir(dir, mode);
	} else {
		/* we look for directory separator from the end of string, thus hopefuly reducing our work load */
		char *e;
		zend_stat_t sb;
		int dir_len = (int)strlen(dir);
		int offset = 0;
		char buf[MAXPATHLEN];

		if (!expand_filepath_with_mode(dir, buf, NULL, 0, CWD_EXPAND )) {
			php_error_docref(NULL, E_WARNING, "Invalid path");
			return 0;
		}

		e = buf +  strlen(buf);

		if ((p = (char*)memchr(buf, DEFAULT_SLASH, dir_len))) {
			offset = p - buf + 1;
		}

		if (p && dir_len == 1) {
			/* buf == "DEFAULT_SLASH" */
		}
		else {
			/* find a top level directory we need to create */
			while ( (p = strrchr(buf + offset, DEFAULT_SLASH)) || (offset != 1 && (p = strrchr(buf, DEFAULT_SLASH))) ) {
				int n = 0;

				*p = '\0';
				while (p > buf && *(p-1) == DEFAULT_SLASH) {
					++n;
					--p;
					*p = '\0';
				}
				if (stat(buf, &sb) == 0) {
					while (1) {
						*p = DEFAULT_SLASH;
						if (!n) break;
						--n;
						++p;
					}
					break;
				}
			}
		}

		if (p == buf) {
			ret = mkdir(dir, mode);
		} else if (!(ret = mkdir(buf, mode))) {
			if (!p) {
				p = buf;
			}
			/* create any needed directories if the creation of the 1st directory worked */
			while (++p != e) {
				if (*p == '\0') {
					*p = DEFAULT_SLASH;
					if ((*(p+1) != '\0') &&
						(ret = mkdir(buf, (mode_t)mode)) < 0) {
						if (options & REPORT_ERRORS) {
							php_error_docref(NULL, E_WARNING, "%s", strerror(errno));
						}
						break;
					}
				}
			}
		}
	}
	if (ret < 0) {
		/* Failure */
		return 0;
	} else {
		/* Success */
		return 1;
	}
}

static int php_plain_files_rmdir(php_stream_wrapper *wrapper, const char *url, int options, php_stream_context *context)
{
	if (strncasecmp(url, "file://", sizeof("file://") - 1) == 0) {
		url += sizeof("file://") - 1;
	}

	if (php_check_open_basedir(url)) {
		return 0;
	}

#ifdef PHP_WIN32
	if (!php_win32_check_trailing_space(url, (int)strlen(url))) {
		php_error_docref1(NULL, url, E_WARNING, "%s", strerror(ENOENT));
		return 0;
	}
#endif

	if (rmdir(url) < 0) {
		php_error_docref1(NULL, url, E_WARNING, "%s", strerror(errno));
		return 0;
	}

	/* Clear stat cache (and realpath cache) */
	php_clear_stat_cache(1, NULL, 0);

	return 1;
}

static int php_plain_files_metadata(php_stream_wrapper *wrapper, const char *url, int option, void *value, php_stream_context *context)
{
	struct utimbuf *newtime;
#if !defined(WINDOWS) && !defined(NETWARE)
	uid_t uid;
	gid_t gid;
#endif
	mode_t mode;
	int ret = 0;
#ifdef PHP_WIN32
	int url_len = (int)strlen(url);
#endif

#ifdef PHP_WIN32
	if (!php_win32_check_trailing_space(url, url_len)) {
		php_error_docref1(NULL, url, E_WARNING, "%s", strerror(ENOENT));
		return 0;
	}
#endif

	if (strncasecmp(url, "file://", sizeof("file://") - 1) == 0) {
		url += sizeof("file://") - 1;
	}

	if (php_check_open_basedir(url)) {
		return 0;
	}

	switch(option) {
		case PHP_STREAM_META_TOUCH:
			newtime = (struct utimbuf *)value;
			if (access(url, F_OK) != 0) {
				int file = open(url, O_CREAT|O_WRONLY|O_TRUNC, 0666);
				if (file == -1) {
					php_error_docref1(NULL, url, E_WARNING, "Unable to create file %s because %s", url, strerror(errno));
					return 0;
				}
				close(file);
			}

			ret = utime(url, newtime);
			break;
#if !defined(WINDOWS) && !defined(NETWARE)
		case PHP_STREAM_META_OWNER_NAME:
		case PHP_STREAM_META_OWNER:
			if(option == PHP_STREAM_META_OWNER_NAME) {
				if(php_get_uid_by_name((char *)value, &uid) != SUCCESS) {
					php_error_docref1(NULL, url, E_WARNING, "Unable to find uid for %s", (char *)value);
					return 0;
				}
			} else {
				uid = (uid_t)*(long *)value;
			}
			ret = chown(url, uid, -1);
			break;
		case PHP_STREAM_META_GROUP:
		case PHP_STREAM_META_GROUP_NAME:
			if(option == PHP_STREAM_META_GROUP_NAME) {
				if(php_get_gid_by_name((char *)value, &gid) != SUCCESS) {
					php_error_docref1(NULL, url, E_WARNING, "Unable to find gid for %s", (char *)value);
					return 0;
				}
			} else {
				gid = (gid_t)*(long *)value;
			}
			ret = chown(url, -1, gid);
			break;
#endif
		case PHP_STREAM_META_ACCESS:
			mode = (mode_t)*(zend_long *)value;
			ret = chmod(url, mode);
			break;
		default:
			php_error_docref1(NULL, url, E_WARNING, "Unknown option %d for stream_metadata", option);
			return 0;
	}
	if (ret == -1) {
		php_error_docref1(NULL, url, E_WARNING, "Operation failed: %s", strerror(errno));
		return 0;
	}
	php_clear_stat_cache(0, NULL, 0);
	return 1;
}

static php_stream *_sw_php_stream_fopen_from_fd(int fd, const char *mode, const char *persistent_id STREAMS_DC)
{
    php_stream *stream = sw_php_stream_fopen_from_fd_int_rel(fd, mode, persistent_id);

    if (stream)
    {
        php_stdio_stream_data *self = (php_stdio_stream_data*) stream->abstract;

        /* detect if this is a pipe */
        if (self->fd >= 0)
        {
            self->is_pipe = (do_fstat(self, 0) == 0 && S_ISFIFO(self->sb.st_mode)) ? 1 : 0;
        }

        if (self->is_pipe)
        {
            stream->flags |= PHP_STREAM_FLAG_NO_SEEK;
        }
        else
        {
            stream->position = zend_lseek(self->fd, 0, SEEK_CUR);
#ifdef ESPIPE
            if (stream->position == (zend_off_t) -1 && errno == ESPIPE)
            {
                stream->position = 0;
                stream->flags |= PHP_STREAM_FLAG_NO_SEEK;
                self->is_pipe = 1;
            }
#endif
        }
    }

    return stream;
}

static void php_stream_mode_sanitize_fdopen_fopencookie(php_stream *stream, char *result)
{
    /* replace modes not supported by fdopen and fopencookie, but supported
     * by PHP's fread(), so that their calls won't fail */
    const char *cur_mode = stream->mode;
    int has_plus = 0, has_bin = 0, i, res_curs = 0;

    if (cur_mode[0] == 'r' || cur_mode[0] == 'w' || cur_mode[0] == 'a')
    {
        result[res_curs++] = cur_mode[0];
    }
    else
    {
        /* assume cur_mode[0] is 'c' or 'x'; substitute by 'w', which should not
         * truncate anything in fdopen/fopencookie */
        result[res_curs++] = 'w';

        /* x is allowed (at least by glibc & compat), but not as the 1st mode
         * as in PHP and in any case is (at best) ignored by fdopen and fopencookie */
    }

    /* assume current mode has at most length 4 (e.g. wbn+) */
    for (i = 1; i < 4 && cur_mode[i] != '\0'; i++)
    {
        if (cur_mode[i] == 'b')
        {
            has_bin = 1;
        }
        else if (cur_mode[i] == '+')
        {
            has_plus = 1;
        }
        /* ignore 'n', 't' or other stuff */
    }

    if (has_bin)
    {
        result[res_curs++] = 'b';
    }
    if (has_plus)
    {
        result[res_curs++] = '+';
    }
    result[res_curs] = '\0';
}

static php_stream_wrapper_ops wrapper_ops = {
	stream_opener,
	NULL,
	NULL,
	php_plain_files_url_stater,
	php_plain_files_dir_opener,
	"plainfile/coroutine",
	php_plain_files_unlink,
	php_plain_files_rename,
	php_plain_files_mkdir,
	php_plain_files_rmdir,
	php_plain_files_metadata
};

PHPAPI php_stream_wrapper sw_php_plain_files_wrapper = {
	&wrapper_ops,
	NULL,
	0
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
