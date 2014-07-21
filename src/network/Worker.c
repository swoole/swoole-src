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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "Server.h"

int swWorker_create(swWorker *worker)
{
	/**
	 * Create shared memory storage
	 */
	void *store = sw_shm_malloc(SwooleG.serv->buffer_output_size);
	if (store == NULL)
	{
		swWarn("malloc for worker->store failed.");
		return SW_ERR;
	}

	swPipe *worker_notify = sw_malloc(sizeof(swPipe));
	if (worker_notify == NULL)
	{
		swWarn("malloc for worker->notify failed.");
		sw_shm_free(store);
		return SW_ERR;
	}

	/**
	 * Create notify pipe
	 */
	if (swPipeNotify_auto(worker_notify, 1, 0))
	{
		sw_shm_free(store);
		sw_free(worker_notify);
		return SW_ERR;
	}

	worker->notify = worker_notify;
	worker->store.ptr = store;
	worker->store.lock = 0;
	return SW_OK;
}

void swWorker_free(swWorker *worker)
{
	sw_shm_free(worker->store.ptr);
	worker->notify->close(worker->notify);

#ifdef SW_USE_RINGBUFFER
	if (worker->pool_input)
	{
	    worker->pool_input->destroy(worker->pool_input);
	}
#endif
}

void swWorker_signal_init(void)
{
	swSignal_add(SIGHUP, NULL);
	swSignal_add(SIGPIPE, NULL);
	swSignal_add(SIGUSR1, NULL);
	swSignal_add(SIGUSR2, NULL);
	swSignal_add(SIGTERM, swWorker_signal_handler);
	swSignal_add(SIGALRM, swTimer_signal_handler);
	//for test
	swSignal_add(SIGVTALRM, swWorker_signal_handler);
}

void swWorker_signal_handler(int signo)
{
	switch (signo)
	{
	case SIGTERM:
		SwooleG.running = 0;
		break;
	case SIGALRM:
		swTimer_signal_handler(SIGALRM);
		break;
	/**
	 * for test
	 */
	case SIGVTALRM:
		swWarn("SIGVTALRM coming");
		break;
	case SIGUSR1:
	case SIGUSR2:
		break;
	default:
		break;
	}
}

