/*
 * memory.h
 *
 *  Created on: 2013-4-25
 *      Author: htf
 */

#ifndef SW_MEMORY_H_
#define SW_MEMORY_H_

#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SW_SHM_MMAP_FILE_LEN  64
typedef struct _swShareMemory_mmap
{
	int size;
	char mapfile[SW_SHM_MMAP_FILE_LEN];
	int tmpfd;
	void *mem;
} swShareMemory_mmap;

typedef struct _swShareMemory_sysv
{
	int size;
	int key;
	int shmid;
	void *mem;
} swShareMemory_sysv;

void *swShareMemory_mmap_create(swShareMemory_mmap *object, int size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory_sysv *object, int size, int key);
int swShareMemory_sysv_free(swShareMemory_sysv *object, int rm);
int swShareMemory_mmap_free(swShareMemory_mmap *object);
#endif /* SW_MEMORY_H_ */
