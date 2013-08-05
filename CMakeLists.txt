PROJECT(swoole)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
INCLUDE_DIRECTORIES(BEFORE ./include ./)

set(SRC_LIST src/core/Base.c 
    src/core/RingQueue.c 
    src/core/Chan.c 
    src/memory/ShareMemory.c 
    src/memory/MemPool.c 
    src/factory/Factory.c 
    src/factory/FactoryThread.c 
    src/factory/FactoryProcess.c 
    src/reactor/ReactorBase.c 
    src/reactor/ReactorSelect.c 
    src/reactor/ReactorPoll.c 
    src/reactor/ReactorEpoll.c 
    src/reactor/ReactorKqueue.c 
    src/pipe/PipeBase.c 
    src/pipe/PipeEventfd.c 
    src/pipe/PipeUnsock.c 
    src/pipe/PipeMsg.c 
    src/lock/Semaphore.c 
    src/lock/Mutex.c 
    src/lock/RWLock.c 
    src/lock/FileLock.c 
    src/network/Server.c 
    src/network/Client.c 
    src/network/buffer.c 
    examples/server.c)
    
add_definitions(-DHAVE_EPOLL -DHAVE_EVENTFD -DHAVE_TIMERFD -DHAVE_CPU_AFFINITY)

#AUX_SOURCE_DIRECTORY(./src DIR_SRCS)
#AUX_SOURCE_DIRECTORY(. DIR_BIN_SRCS)

ADD_EXECUTABLE(server ${SRC_LIST})
TARGET_LINK_LIBRARIES(server pthread rt)
