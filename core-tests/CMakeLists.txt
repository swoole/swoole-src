cmake_minimum_required(VERSION 2.8)

project(core_tests)

#set(CMAKE_BUILD_TYPE Released)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS src/*.cpp)

add_definitions(-DHAVE_CONFIG_H)

if (DEFINED swoole_dir)
    add_definitions(-DHAVE_SWOOLE_DIR)
    include_directories(BEFORE ${swoole_dir} ${swoole_dir}/include)
endif()

if (DEFINED openssl_dir) 
    include_directories(BEFORE ${openssl_dir}/include)
    link_directories(${openssl_dir}/lib)
endif()

if (DEFINED brotli_dir) 
    include_directories(BEFORE ${brotli_dir}/include)
    link_directories(${brotli_dir}/lib)
endif()

link_directories(${ROOT_DIR}/lib)
link_directories(/usr/local/lib)

include_directories(./include/ /usr/local/include/ /usr/include/ /usr/local/include/swoole /usr/include/swoole BEFORE)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
add_executable(core_tests ${SOURCE_FILES})
target_link_libraries(core_tests gtest gtest_main pthread swoole)
