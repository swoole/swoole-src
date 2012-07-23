#ifndef SW_TASK_H_
#define SW_TASK_H_

typedef struct _swTask
{
	swFactory factory;
	swReactor reactor;

	int factory_mode;
	int writer_num;
	int worker_num;
	int timeout_sec;
	int timeout_usec;

	int event_fd;
	void *ptr; //reserve
	void *ptr2; //reserve 2
} swTask;


#endif /* SW_TASK_H_ */
