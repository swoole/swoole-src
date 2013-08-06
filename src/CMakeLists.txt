cmake_minimum_required(VERSION 2.4)

include_directories(BEFORE ../include ../)

set(SRC_LIST core/Base.c 
    core/RingQueue.c 
    core/Chan.c 
    memory/ShareMemory.c 
    memory/MemPool.c 
    factory/Factory.c 
    factory/FactoryThread.c 
    factory/FactoryProcess.c 
    reactor/ReactorBase.c 
    reactor/ReactorSelect.c 
    reactor/ReactorPoll.c 
    reactor/ReactorEpoll.c 
    reactor/ReactorKqueue.c 
    pipe/PipeBase.c 
    pipe/PipeEventfd.c 
    pipe/PipeUnsock.c 
    pipe/PipeMsg.c 
    lock/Semaphore.c 
    lock/Mutex.c 
    lock/RWLock.c 
    lock/FileLock.c 
    network/Server.c 
    network/Client.c 
    network/buffer.c )

SET(LIBRARY_OUTPUT_PATH ../lib)

add_definitions(-DHAVE_EPOLL -DHAVE_EVENTFD -DHAVE_TIMERFD -DHAVE_CPU_AFFINITY)

add_library(swoole_shared SHARED ${SRC_LIST})
add_library(swoole_static STATIC ${SRC_LIST})

set_target_properties(swoole_shared PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)
set_target_properties(swoole_static PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)

target_link_libraries(swoole_shared pthread rt)
target_link_libraries(swoole_static pthread rt)

INSTALL(TARGETS swoole_shared swoole_static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${DIR_HEADER} DESTINATION include/swoole)

