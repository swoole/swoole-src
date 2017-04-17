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
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

typedef struct
{
    size_t size;
    off_t offset;
    char *filename;
    void *memory;
    void *ptr;
} swMmapFile;

static size_t mmap_stream_write(php_stream * stream, const char *buffer, size_t length TSRMLS_DC);
static size_t mmap_stream_read(php_stream *stream, char *buffer, size_t length TSRMLS_DC);
static int mmap_stream_flush(php_stream *stream TSRMLS_DC);
static int mmap_stream_seek(php_stream *stream, off_t offset, int whence, off_t *newoffset TSRMLS_DC);
static int mmap_stream_close(php_stream *stream, int close_handle TSRMLS_DC);
static PHP_METHOD(swoole_mmap, open);

static zend_class_entry swoole_mmap_ce;
zend_class_entry *swoole_mmap_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mmap_open, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, size)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_mmap_methods[] =
{
    PHP_ME(swoole_mmap, open, arginfo_swoole_mmap_open, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

php_stream_ops mmap_ops =
{
    mmap_stream_write,
    mmap_stream_read,
    mmap_stream_close,
    mmap_stream_flush,
    "swoole_mmap",
    mmap_stream_seek,
    NULL,
    NULL,
    NULL
};

static size_t mmap_stream_write(php_stream * stream, const char *buffer, size_t length TSRMLS_DC)
{
    swMmapFile *res = stream->abstract;

    int n_write = MIN(res->memory + res->size - res->ptr, length);
    if (n_write == 0)
    {
        return 0;
    }
    memcpy(res->ptr, buffer, n_write);
    res->ptr += n_write;
    return n_write;
}

static size_t mmap_stream_read(php_stream *stream, char *buffer, size_t length TSRMLS_DC)
{
    swMmapFile *res = stream->abstract;

    int n_read = MIN(res->memory + res->size - res->ptr, length);
    if (n_read == 0)
    {
        return 0;
    }
    memcpy(buffer, res->ptr, n_read);
    res->ptr += n_read;
    return n_read;
}

static int mmap_stream_flush(php_stream *stream TSRMLS_DC)
{
    swMmapFile *res = stream->abstract;
    return msync(res->memory, res->size, MS_SYNC | MS_INVALIDATE);
}

static int mmap_stream_seek(php_stream *stream, off_t offset, int whence, off_t *newoffset TSRMLS_DC)
{
    swMmapFile *res = stream->abstract;

    switch (whence)
    {
    case SEEK_SET:
        if (offset < 0 || offset > res->size)
        {
            *newoffset = (off_t) -1;
            return -1;
        }
        res->ptr = res->memory + offset;
        *newoffset = offset;
        return 0;
    case SEEK_CUR:
        if (res->ptr + offset < res->memory || res->ptr + offset > res->memory + res->size)
        {
            *newoffset = (off_t) -1;
            return -1;
        }
        res->ptr += offset;
        *newoffset = res->ptr - res->memory;
        return 0;
    case SEEK_END:
        if (offset > 0 || -1 * offset > res->size)
        {
            *newoffset = (off_t) -1;
            return -1;
        }
        res->ptr += offset;
        *newoffset = res->ptr - res->memory;
        return 0;
    default:
        *newoffset = (off_t) -1;
        return -1;
    }
}

static int mmap_stream_close(php_stream *stream, int close_handle TSRMLS_DC)
{
    swMmapFile *res = stream->abstract;
    if (close_handle)
    {
        munmap(res->memory, res->size);
    }
    efree(res);
    return 0;
}

void swoole_mmap_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mmap_ce, "swoole_mmap", "Swoole\\Mmap", swoole_mmap_methods);
    swoole_mmap_class_entry_ptr = zend_register_internal_class(&swoole_mmap_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_mmap, "Swoole\\Mmap");
}

static PHP_METHOD(swoole_mmap, open)
{
    char *filename;
    zend_size_t l_filename;
    long offset = 0;
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &filename, &l_filename, &size, &offset) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_filename <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "require filename.");
        RETURN_FALSE;
    }

    int fd;
    if ((fd = open(filename, O_RDWR)) < 0)
    {
        swoole_php_sys_error(E_WARNING, "open(%s, O_RDWR) failed.", filename);
        RETURN_FALSE;
    }

    if (size <= 0)
    {
        struct stat _stat;
        if (fstat(fd, &_stat) < 0)
        {
            swoole_php_sys_error(E_WARNING, "fstat(%s) failed.", filename);
            close(fd);
            RETURN_FALSE;
        }
        if (_stat.st_size == 0)
        {
            swoole_php_sys_error(E_WARNING, "file[%s] is empty.", filename);
            close(fd);
            RETURN_FALSE;
        }
        if (offset > 0)
        {
            size = _stat.st_size - offset;
        }
        else
        {
            size = _stat.st_size;
        }
    }

    void *addr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, offset);
    if (addr == NULL)
    {
        swoole_php_sys_error(E_WARNING, "mmap(%ld) failed.", size);
        RETURN_FALSE;
    }

    swMmapFile *res = emalloc(sizeof(swMmapFile));
    res->filename = filename;
    res->size = size;
    res->offset = offset;
    res->memory = addr;
    res->ptr = addr;

    close(fd);
    php_stream *stream = php_stream_alloc(&mmap_ops, res, NULL, "r+");
    php_stream_to_zval(stream, return_value);
}
