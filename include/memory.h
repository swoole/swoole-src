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
	int key;
	int shmid;
	void *mem;
} swShareMemory;

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory *object, int size, int key);
int swShareMemory_sysv_free(swShareMemory *object, int rm);
int swShareMemory_mmap_free(swShareMemory *object);

#endif /* SW_MEMORY_H_ */
