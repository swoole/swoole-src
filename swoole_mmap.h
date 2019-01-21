//
// Created by lyx on 19-1-21.
//

#ifndef SWOOLE_MMAP_H_
#define SWOOLE_MMAP_H_

typedef struct
{
    size_t size;
    off_t offset;
    char *filename;
    void *memory;
    void *ptr;
} swMmapFile;

void *php_swoole_mmap_get_memory(zval *zmmap, size_t offset, size_t need_size);

#endif // SWOOLE_MMAP_H_
