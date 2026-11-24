#define _GNU_SOURCE
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef void *(*alloc_fn)(size_t, void **);
typedef void (*free_fn)(void *, void **);
typedef void *(*realloc_fn)(void *, size_t, void **);
typedef void *(*session_init_fn)(alloc_fn, free_fn, realloc_fn, void *);
typedef int (*session_free_fn)(void *);

/* Shared with PHP via a temporary mmap file. These tests use one PHP thread. */
struct counters {
    uint64_t live;
    uint64_t allocations;
    uint64_t frees;
    uint64_t sessions;
    uint64_t session_frees;
    uint64_t active;
};

static struct counters *counts;
static alloc_fn original_alloc;
static free_fn original_free;
static realloc_fn original_realloc;
static session_init_fn original_session_init;
static session_free_fn original_session_free;

static void *counted_alloc(size_t size, void **abstract) {
    void *ptr = original_alloc(size, abstract);
    if (ptr) {
        counts->live++;
        counts->allocations++;
    }
    return ptr;
}

static void counted_free(void *ptr, void **abstract) {
    if (ptr) {
        counts->live--;
        counts->frees++;
    }
    original_free(ptr, abstract);
}

static void *counted_realloc(void *ptr, size_t size, void **abstract) {
    int had_pointer = ptr != NULL;
    void *result = original_realloc(ptr, size, abstract);
    if (!had_pointer && result) {
        counts->live++;
        counts->allocations++;
    } else if (had_pointer && size == 0 && !result) {
        counts->live--;
        counts->frees++;
    }
    return result;
}

static void *counted_session_init(alloc_fn alloc, free_fn free_cb, realloc_fn realloc_cb, void *abstract) {
    original_alloc = alloc;
    original_free = free_cb;
    original_realloc = realloc_cb;
    void *session = original_session_init(counted_alloc, counted_free, counted_realloc, abstract);
    if (session) {
        counts->sessions++;
    }
    return session;
}

static int counted_session_free(void *session) {
    if (getenv("SWOOLE_SSH2_FAIL_FREE")) {
        return -9; /* LIBSSH2_ERROR_TIMEOUT */
    }
    int rc = original_session_free(session);
    if (rc == 0) {
        counts->session_frees++;
    }
    return rc;
}

unsigned int la_version(unsigned int version) {
    const char *path = getenv("SWOOLE_SSH2_AUDIT_REPORT");
    int fd = path ? open(path, O_RDWR) : -1;
    if (fd < 0) {
        return 0;
    }
    counts = mmap(NULL, sizeof(*counts), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (counts == MAP_FAILED) {
        return 0;
    }
    counts->active = 1;
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

uintptr_t la_symbind64(
    Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, unsigned int *flags, const char *name) {
    if (strcmp(name, "libssh2_session_init_ex") == 0) {
        original_session_init = (session_init_fn) sym->st_value;
        return (uintptr_t) counted_session_init;
    }
    if (strcmp(name, "libssh2_session_free") == 0) {
        original_session_free = (session_free_fn) sym->st_value;
        return (uintptr_t) counted_session_free;
    }
    return sym->st_value;
}
