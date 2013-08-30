#include "swoole.h"

#define SW_LOG_BUFFER_SIZE 512
static FILE *fp;
static char bufr[SW_LOG_BUFFER_SIZE];

int sw_log_init(char *logfile)
{
	fp = fopen(logfile, "a+");
	if(fp == NULL)
	{
		return SW_ERR;
	}
	if (setvbuf(fp, bufr, _IOLBF, SW_LOG_BUFFER_SIZE) < 0)
	{
		return SW_ERR;
	}
	return SW_OK;
}

void sw_log(int level, char *cnt, int len)
{
	fputs(cnt, fp);
}
