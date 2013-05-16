#include "swoole.h"

static char *parse(char *str)
{
    char *ptr=str;
    sprintf(ptr,ptr,strlen(str)-1));
    ptr[k]='\0';
    return ptr;
}

int load_conf(swServer *serv)
{
	char *filename = serv->cfile;
	if (!filename)
    {
        return SW_ERR;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        swTrace("open file %s failed\n", filename);
        return SW_ERR;
    }
    char *name, line[100];
    int len;

    while (!feof(fp))
    {
        if (fgets(line, 1024, fp)
        {
            len = strlen(line);
            
            if(len <= 1) 
            {
                continue;
            } 
            else if (line[0]=='#' || line[0]==';') 
            {
                continue;
            } 
            else if (line[0]=='[' && line[len-1]==']') 
            {
                continue;   
            }

            name = strtok(line, "=");
            
            if(!strcasecmp("timeout", name))
            {
            	int timeout = atoi(strtok(0, "="));
            	serv->timeout_sec = timeout;
				serv->timeout_usec = (int)((timeout*1000*1000) - (serv->timeout_sec*1000*1000));
            } 
            else if(!strcasecmp("host", name))
            {
            	serv->host = strSub(strtok(0, "="));
            }
            else if(!strcasecmp("port", name))
            {
            	serv->port = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("mode", name))
            {
                serv->factory_mode = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("daemonize", name))
            {
            	serv->daemonize = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("backlog", name))
            {
            	serv->backlog = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("poll_thread_num", name))
            {
            	serv->poll_thread_num = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("poll_thread_num", name))
            {
            	serv->poll_thread_num = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("writer_num", name))
            {
            	serv->writer_num = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("worker_num", name))
            {
            	serv->worker_num = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("max_conn", name))
            {
            	serv->max_conn = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("max_request", name))
            {
            	serv->max_request = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("open_cpu_affinity", name))
            {
            	serv->open_cpu_affinity = atoi(strtok(0, "="));
            }
            else if(!strcasecmp("open_tcp_nodelay", name))
            {
            	serv->open_tcp_nodelay = atoi(strtok(0, "="));
            }
            
        }
    }

    fclose(fp);

    return SW_OK;
}