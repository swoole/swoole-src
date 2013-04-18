#include <sys/poll.h>
#include "swoole.h"

typedef struct _swReactorPoll
{

} swReactorPoll;

int swReactorPoll_add(swReactor *reactor, int fd, int fdtype);
int swReactorPoll_del(swReactor *reactor, int fd);
int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo);
void swReactorPoll_free(swReactor *reactor);

