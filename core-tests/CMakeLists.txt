cmake_minimum_required(VERSION 2.8)

project(core_tests)

#set(CMAKE_BUILD_TYPE Released)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS src/*.cpp)

add_definitions(-DHAVE_CONFIG_H)
link_directories(${ROOT_DIR}/lib)
include_directories(./include/ /usr/local/include/ /usr/include/ /usr/local/include/swoole /usr/include/swoole BEFORE)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
add_executable(core_tests ${SOURCE_FILES})
target_link_libraries(core_tests gtest gtest_main pthread swoole)
