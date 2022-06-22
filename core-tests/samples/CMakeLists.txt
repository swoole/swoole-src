cmake_minimum_required(VERSION 2.8)
project(samples)
#set(CMAKE_BUILD_TYPE Released)
set(CMAKE_CXX_STANDARD 11)
file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS src/*.cc)

add_definitions(-DHAVE_CONFIG_H)

link_directories($ENV{SWOOLE_DIR}/lib)
include_directories(. ./include $ENV{SWOOLE_DIR} $ENV{SWOOLE_DIR}/include BEFORE)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
add_executable(core_samples ${SOURCE_FILES})
target_link_libraries(core_samples swoole)
