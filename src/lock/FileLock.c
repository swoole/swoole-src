#include "swoole.h"

int swFileLock_create(swFileLock *this, int fd)
{
	this->fd = fd;
	bzero(&this->rwlock, sizeof(this->rwlock));
	this->lock_rd = swFileLock_lock_rd;
	this->lock = swFileLock_lock_rw;
	this->trylock_rd = swFileLock_trylock_rd;
	this->trylock = swFileLock_trylock_rw;
	this->unlock = swFileLock_unlock;
	return 0;
}

int swFileLock_lock_rd(swFileLock *this)
{
	this->rwlock.l_type = F_RDLCK;
	return fcntl(this->fd, F_SETLKW, &this->rwlock);
}

int swFileLock_lock_rw(swFileLock *this)
{
	this->rwlock.l_type = F_WRLCK;
	return fcntl(this->fd, F_SETLKW, &this->rwlock);
}

int swFileLock_unlock(swFileLock *this)
{
	this->rwlock.l_type = F_UNLCK;
	return fcntl(this->fd, F_SETLKW, &this->rwlock);
}

int swFileLock_trylock_rw(swFileLock *this)
{
	this->rwlock.l_type = F_RDLCK;
	return fcntl(this->fd, F_SETLK, &this->rwlock);
}

int swFileLock_trylock_rd(swFileLock *this)
{
	this->rwlock.l_type = F_WRLCK;
	return fcntl(this->fd, F_SETLK, &this->rwlock);
}
