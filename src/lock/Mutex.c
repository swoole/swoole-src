#include "swoole.h"

int swMutex_create(swMutex *object, int use_in_process)
{
	int ret;
	bzero(object, sizeof(swMutex));
	pthread_mutexattr_init(&object->attr);
	if(use_in_process == 1)
	{
		pthread_mutexattr_setpshared(&object->attr, PTHREAD_PROCESS_SHARED);
	}
	if((ret = pthread_mutex_init(&object->mutex, &object->attr)) < 0)
	{
		swWarn("swMutex_create fail. Error: %s [%d]", strerror(errno), errno);
		return SW_ERR;
	}
	object->lock = swMutex_lock;
	object->unlock = swMutex_unlock;
	object->trylock = swMutex_trylock;
	object->free = swMutex_free;
	return SW_OK;
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

