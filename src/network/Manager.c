//#include "swoole.h"
//
//typedef struct {
//	swCallback call;
//	swPipe pipe;
//	pid_t pid;
//} swWorker;
//
//typedef struct {
//	int max_num;
//	int cur_id;
//	swWorker *workers;
//} swManager;
//
///**
// * Process manager
// */
//int swManager_create(swManager *ma, int max_num)
//{
//	bzero(ma, sizeof(swManager));
//	ma->workers = sw_calloc(max_num, sizeof(swWorker));
//	ma->max_num = max_num;
//	if(ma->workers == NULL)
//	{
//		swWarn("[swManager_create] malloc fail.");
//		return SW_ERR;
//	}
//	return SW_OK;
//}
//
//int swManager_add_worker(swManager *ma, swCallback cb)
//{
//	if(ma->cur_id >= ma->max_num)
//	{
//		swWarn("[swManager_create] too many worker[max_num=%d]", ma->max_num);
//		return SW_ERR;
//	}
//	int cur_id = ma->cur_id++;
//	ma->workers[cur_id].call = cb;
//	if(swPipeUnsock_create(&(ma->workers[cur_id].pipe), 1, SOCK_STREAM) <0)
//	{
//		return SW_ERR;
//	}
//	return cur_id;
//}
//
//int swManager_run(swManager *ma)
//{
//	int i;
//	pid_t pid;
//
//	for(i=0; i <ma->cur_id; i++)
//	{
//		pid = fork();
//		switch(pid)
//		{
//		//child
//		case 0:
//			ma->workers[i].call(i);
//			exit(0);
//			break;
//		case -1:
//			swWarn("[swManager_run] fork fail. Error: %s [%d]", strerror(errno), errno);
//			break;
//		//parent
//		default:
//			ma->workers[i].pid = pid;
//			break;
//		}
//	}
//}
//
//
//int swManager_shutdown(swManager *ma)
//{
//
//}
//
//
//int swManager_free(swManager *ma)
//{
//
//}
