PROJECT(server)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)


#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_EPOLL -DHAVE_EVENTFD -DHAVE_TIMERFD -DHAVE_CPU_AFFINITY)

INCLUDE_DIRECTORIES(BEFORE ./include ./)

#libary
add_library(swoole_shared SHARED ${SRC_LIST})
add_library(swoole_static STATIC ${SRC_LIST})

set_target_properties(swoole_shared PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)
set_target_properties(swoole_static PROPERTIES OUTPUT_NAME "swoole" VERSION 1.5.2)

target_link_libraries(swoole_shared pthread rt)
target_link_libraries(swoole_static pthread rt)

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#test_server
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(TEST_SRC_LIST examples/test_server.c)
add_executable(test_server ${TEST_SRC_LIST};${SRC_LIST})
target_link_libraries(test_server pthread rt)
#add_dependencies(test_server swoole_static swoole_shared)
#TARGET_LINK_LIBRARIES(test_server swoole)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS swoole_shared swoole_static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/swoole_config.h DESTINATION include/swoole)
