PROJECT(swoole_server)

SET(SWOOLE_VERSION 1.7.10)
SET(SWOOLE_CLFLAGS pthread rt dl ssl crypt crypto)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

SET(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

#for Linux
add_definitions(-DHAVE_EPOLL -DHAVE_ACCEPT4 -DHAVE_EVENTFD -DHAVE_TIMERFD -DHAVE_CPU_AFFINITY -DHAVE_OPENSSL -DSW_USE_OPENSSL)

#for FreeBSD
#add_definitions(-DHAVE_KQUEUE)

INCLUDE_DIRECTORIES(BEFORE ./include ./)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#libary
add_library(swoole_shared SHARED ${SRC_LIST})
add_library(swoole_static STATIC ${SRC_LIST})

set_target_properties(swoole_shared PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
set_target_properties(swoole_static PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})

target_link_libraries(swoole_shared ${SWOOLE_CLFLAGS})
target_link_libraries(swoole_static ${SWOOLE_CLFLAGS})

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#test_server
set(TEST_SRC_LIST examples/test_server.c)
add_executable(test_server ${TEST_SRC_LIST};${SRC_LIST})
target_link_libraries(test_server ${SWOOLE_CLFLAGS})

#unittest
file(GLOB_RECURSE UNITTEST_SRC_LIST FOLLOW_SYMLINKS tests/*.c)
add_executable(unittest ${UNITTEST_SRC_LIST};${SRC_LIST})
target_link_libraries(unittest ${SWOOLE_CLFLAGS})

#add_dependencies(test_server swoole_static swoole_shared)
#TARGET_LINK_LIBRARIES(test_server swoole)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS swoole_shared swoole_static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/swoole_config.h DESTINATION include/swoole)
