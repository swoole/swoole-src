cmake_minimum_required(VERSION 2.8)
project(server)

set(SOURCE_FILES server.cpp)
set(CMAKE_BUILD_TYPE Debug)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})

add_definitions(-DHAVE_CONFIG_H)

include_directories(./include ./ $ENV{SWOOLE_DIR}/ $ENV{SWOOLE_DIR}/include/ BEFORE)


link_directories($ENV{SWOOLE_DIR}/lib)
add_executable(server ${SOURCE_FILES})
target_link_libraries(server swoole)



