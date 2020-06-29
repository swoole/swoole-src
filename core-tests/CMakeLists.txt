cmake_minimum_required(VERSION 2.8.1)

project(core_tests)

#set(CMAKE_BUILD_TYPE Released)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
        
file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS src/*.cpp)

add_definitions(-DHAVE_CONFIG_H)

set(core_tests_includes ./include/)
set(core_tests_libraries)

list(APPEND core_tests_libraries pthread)

# find GTest
find_package(GTest)
if (!${GTEST_FOUND})
    message(FATAL_ERROR "Not found GTest")
endif()
message(STATUS "Found GTest")

list(APPEND core_tests_libraries ${GTEST_BOTH_LIBRARIES})
list(APPEND core_tests_includes ${GTEST_INCLUDE_DIRS})

if (DEFINED swoole_dir)
    list(APPEND core_tests_includes ${swoole_dir}/include)
    list(APPEND core_tests_libraries ${swoole_dir}/lib)
else()
    list(APPEND core_tests_includes /usr/local/include/swoole /usr/include/swoole)
    list(APPEND core_tests_libraries swoole)
endif()

# find OpenSSL
if (DEFINED openssl_dir) 
    list(APPEND core_tests_includes ${openssl_dir}/include)
    list(APPEND core_tests_libraries ${openssl_dir}/lib)
else()
    find_package(OpenSSL)
    if (${OPENSSL_FOUND})
        message(STATUS "Found OpenSSL")
        list(APPEND core_tests_includes ${OPENSSL_INCLUDE_DIR})
        list(APPEND core_tests_libraries ${OPENSSL_LIBRARIES})
    else()
        message(STATUS "Not found OpenSSL")
    endif()
endif()

if (DEFINED brotli_dir) 
    list(APPEND core_tests_includes ${brotli_dir}/include)
    list(APPEND core_tests_libraries ${brotli_dir}/lib)
endif()

if (DEFINED enable_asan) 
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
add_executable(core_tests ${SOURCE_FILES})
target_include_directories(core_tests PRIVATE ${core_tests_includes})
target_link_libraries(core_tests ${core_tests_libraries})
