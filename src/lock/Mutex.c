#include "swoole.h"

int swMutex_create(swMutex *object, int use_in_process)
{
	int ret;
	bzero(object, sizeof(swMutex));
	if(use_in_process == 1)
	{
		pthread_mutexattr_setpshared(&object->attr, PTHREAD_PROCESS_SHARED);
	}
	if((ret = pthread_mutex_init(&object->mutex, &object->attr)) < 0)
	{
		return -1;
	}
	object->lock = swMutex_lock;
	object->unlock = swMutex_unlock;
	object->trylock = swMutex_trylock;
	object->unlock = swMutex_free;
	return 0;
}

int swMutex_lock(swMutex *object)
{
	return pthread_mutex_lock(&object->mutex);
}

int swMutex_unlock(swMutex *object)
{
	return pthread_mutex_unlock(&object->mutex);
}

int swMutex_trylock(swMutex *object)
{
	return pthread_mutex_trylock(&object->mutex);
}

int swMutex_free(swMutex *object)
{
	return pthread_mutex_destroy(&object->mutex);
}

