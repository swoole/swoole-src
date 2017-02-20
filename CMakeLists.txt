PROJECT(swoole_server)

SET(SWOOLE_VERSION 1.9.5)
SET(SWOOLE_CLFLAGS pthread rt dl ssl crypt crypto nghttp2)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

SET(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)

INCLUDE_DIRECTORIES(BEFORE ./include ./ /usr/local/php/include /usr/local/php/include/Zend /usr/local/php/include/main)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#libary
add_library(shared SHARED ${SRC_LIST})
add_library(static STATIC ${SRC_LIST})

set_target_properties(shared PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
set_target_properties(static PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})

target_link_libraries(shared ${SWOOLE_CLFLAGS})
target_link_libraries(static ${SWOOLE_CLFLAGS})

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#test_server
set(TEST_SRC_LIST examples/test_server.c)
add_executable(test_server ${TEST_SRC_LIST})
add_dependencies(test_server static)
target_link_libraries(test_server ${SWOOLE_CLFLAGS} swoole)

#unittest
file(GLOB_RECURSE UNITTEST_SRC_LIST FOLLOW_SYMLINKS tests/*.c)
add_executable(unittest ${SRC_LIST} ${UNITTEST_SRC_LIST})
target_link_libraries(unittest ${SWOOLE_CLFLAGS})

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS shared static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/swoole_config.h DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)
