PROJECT(server)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

INCLUDE_DIRECTORIES(BEFORE ./include ./)

add_subdirectory(src)

set(SERVER_SRC_LIST examples/server.c)

LINK_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_EXECUTABLE(server ${SERVER_SRC_LIST})
add_dependencies(server swoole_shared)
add_dependencies(server swoole_static)
TARGET_LINK_LIBRARIES(server swoole)
