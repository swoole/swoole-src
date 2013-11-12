#include "swoole.h"

static int swCond_notify(swCond *cond);
static int swCond_broadcast(swCond *cond);
static int swCond_timewait(swCond *cond, long sec, long nsec);
static int swCond_wait(swCond *cond);

static int swCond_lock(swCond *cond);
static int swCond_trylock(swCond *cond);
static int swCond_unlock(swCond *cond);
static void swCond_free(swCond *cond);


int swCond_create(swCond *cond)
{
	if (pthread_cond_init(&cond->cond, NULL) < 0)
	{
		swWarn("pthread_cond_init fail. Error: %s [%d]", strerror(errno), errno);
		return SW_ERR;
	}
	if (swMutex_create(&cond->mutex, 0) < 0)
	{
		return SW_ERR;
	}
	cond->notify = swCond_notify;
	cond->broadcast = swCond_broadcast;
	cond->wait = swCond_wait;
	cond->timewait = swCond_timewait;
	cond->lock = swCond_lock;
	cond->trylock = swCond_trylock;
	cond->unlock = swCond_unlock;
	cond->free = swCond_free;
	return SW_OK;
}

static int swCond_notify(swCond *cond)
{
	return pthread_cond_signal(&cond->cond);
}

static int swCond_lock(swCond *cond)
{
	return cond->mutex.lock(&cond->mutex);
}

static int swCond_trylock(swCond *cond)
{
	return cond->mutex.trylock(&cond->mutex);
}

static int swCond_unlock(swCond *cond)
{
	return cond->mutex.unlock(&cond->mutex);
}

static int swCond_notify(swCond *cond)
{
	return pthread_cond_signal(&cond->cond);
}

static int swCond_broadcast(swCond *cond)
{
	return pthread_cond_broadcast(&cond->cond);
}

static int swCond_timewait(swCond *cond, long sec, long nsec)
{
	int ret;
	struct timespec timeo;

	timeo.tv_sec = sec;
	timeo.tv_nsec = nsec;

	cond->mutex.lock(&cond->mutex);
	ret = pthread_cond_timedwait(&cond->cond, &cond->mutex, &timeo);
	cond->mutex.unlock(&cond->mutex);
	return ret;
}

static int swCond_wait(swCond *cond)
{
	int ret;
	cond->mutex.lock(&cond->mutex);
	ret = pthread_cond_wait(&cond->cond, &cond->mutex);
	cond->mutex.unlock(&cond->mutex);
	return ret;
}

static void swCond_free(swCond *cond)
{
	pthread_cond_destroy(&cond->cond);
	cond->mutex.free(&cond->mutex);
}
