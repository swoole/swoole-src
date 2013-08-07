PROJECT(server)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(SERVER_SRC_LIST examples/server.c)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_EPOLL -DHAVE_EVENTFD -DHAVE_TIMERFD -DHAVE_CPU_AFFINITY)

INCLUDE_DIRECTORIES(BEFORE ./include ./)

#bin
add_library(swoole_shared SHARED ${SRC_LIST})
add_library(swoole_static STATIC ${SRC_LIST})

set_target_properties(swoole_shared PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)
set_target_properties(swoole_static PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)

target_link_libraries(swoole_shared pthread rt)
target_link_libraries(swoole_static pthread rt)

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})
ADD_EXECUTABLE(server ${SERVER_SRC_LIST})
add_dependencies(server swoole_shared swoole_static)
TARGET_LINK_LIBRARIES(server swoole)

#install
INSTALL(TARGETS swoole_shared swoole_static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)

