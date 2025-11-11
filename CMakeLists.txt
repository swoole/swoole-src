cmake_minimum_required(VERSION 3.10)
project(libswoole)

enable_language(ASM)
set(SWOOLE_VERSION 6.1.2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")

file(READ ./config.h SWOOLE_CONFIG_FILE)

set(CMAKE_MACOSX_RPATH 1)
set(SWOOLE_LINK_LIBRARIES pthread dl)

if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")
    include_directories(BEFORE /usr/local/include)
    link_directories(BEFORE /usr/local/lib)
else()
    list(APPEND SWOOLE_LINK_LIBRARIES rt crypt)
endif()

find_package(PkgConfig REQUIRED)

if (UNIX AND NOT APPLE)
    find_library(URING_LIBRARIES uring)
    if (URING_LIBRARIES)
        message(STATUS "Found iouring")
        list(APPEND SWOOLE_LINK_LIBRARIES ${URING_LIBRARIES})
    else()
        message(WARNING "liburing not found.")
    endif()
endif()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif ()

# Code Coverage Configuration
add_library(coverage_config INTERFACE)

option(CODE_COVERAGE "Enable coverage reporting" OFF)
if(CODE_COVERAGE)
    message(STATUS "Open coverage")
    # --coverage => -fprofile-arcs -ftest-coverage
    target_compile_options(coverage_config INTERFACE
        -O0
        -g
        -fprofile-update=atomic
        --coverage
    )
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_options(coverage_config INTERFACE --coverage)
    else()
        target_link_libraries(coverage_config INTERFACE --coverage)
    endif()
endif(CODE_COVERAGE)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c src/*.cc
            thirdparty/boost/asm/combined.S
            thirdparty/hiredis/alloc.c
            thirdparty/hiredis/async.c
            thirdparty/hiredis/hiredis.c
            thirdparty/hiredis/net.c
            thirdparty/hiredis/read.c
            thirdparty/hiredis/sds.c
            thirdparty/llhttp/api.c
            thirdparty/llhttp/http.c
            thirdparty/llhttp/llhttp.c
        	thirdparty/multipart_parser.c
)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)
file(GLOB_RECURSE HEAD_WAPPER_FILES FOLLOW_SYMLINKS include/wrapper/*.hpp)

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)
# test
#add_definitions(-DSW_USE_THREAD_CONTEXT)

include_directories(BEFORE ./include ./include/wrapper ext-src/ thirdparty/ thirdparty/llhttp ./)

# find OpenSSL
if (DEFINED openssl_dir)
    include_directories(BEFORE ${openssl_dir}/include)
    link_directories(${openssl_dir}/lib)
else()
    find_package(OpenSSL)
    if (${OPENSSL_FOUND})
        message(STATUS "Found OpenSSL, ${OPENSSL_LIBRARIES}")
        include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})
        list(APPEND SWOOLE_LINK_LIBRARIES ssl crypto)
    else()
        message(STATUS "Not found OpenSSL")
    endif()
endif()

if (DEFINED brotli_dir)
    include_directories(BEFORE ${brotli_dir}/include)
    link_directories(${brotli_dir}/lib)
endif()

foreach (LINE ${SWOOLE_CONFIG_FILE})
  if ("${LINE}" MATCHES "define SW_USE_CARES 1")
      message(STATUS "enable c-ares")
      list(APPEND SWOOLE_LINK_LIBRARIES cares)
  endif()
endforeach()

if (DEFINED enable_trace_log)
	add_definitions(-DSW_LOG_TRACE_OPEN)
endif()

if (DEFINED enable_asan)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    add_definitions(-DSW_USE_ASAN)
endif()

if (DEFINED enable_thread)
    add_definitions(-DSW_THREAD)
endif()

if (DEFINED async_io)
    # This macro is exclusively used for kernel unit testing to
    # verify the asynchronous operation functionality of the file thread pool.
    add_definitions(-DSW_USE_ASYNC)
endif()

if (DEFINED verbose)
    add_definitions(-DSW_VERBOSE)
endif()

set(php_dir "" CACHE STRING "Set the root directory of PHP")

if (DEFINED php_dir)
    set(PHP_CONFIG "${php_dir}/bin/php-config")
else ()
    set(PHP_CONFIG "php-config")
endif()

execute_process(COMMAND ${PHP_CONFIG} --includes OUTPUT_VARIABLE PHP_INCLUDES OUTPUT_STRIP_TRAILING_WHITESPACE  RESULT_VARIABLE PHP_CONFIG_RESULT)
if (NOT PHP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to execute php-config: ${PHP_CONFIG_RESULT}")
endif()

execute_process(COMMAND ${PHP_CONFIG} --extension-dir OUTPUT_VARIABLE PHP_EXTENSION_DIR OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE PHP_CONFIG_RESULT)
if (NOT PHP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to execute php-config: ${PHP_CONFIG_RESULT}")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PHP_INCLUDES}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PHP_INCLUDES}")

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    execute_process(COMMAND ldconfig -p OUTPUT_VARIABLE LDCONFIG_LIST OUTPUT_STRIP_TRAILING_WHITESPACE)
    #message(STATUS LDCONFIG_LIST)
    if (LDCONFIG_LIST MATCHES brotlienc)
         list(APPEND SWOOLE_LINK_LIBRARIES brotlienc)
    endif()

    if (LDCONFIG_LIST MATCHES brotlidec)
        list(APPEND SWOOLE_LINK_LIBRARIES brotlidec)
    endif()
endif()

# lib-swoole
link_directories(${LIBRARY_OUTPUT_PATH})
add_library(lib-swoole SHARED ${SRC_LIST})
set_target_properties(lib-swoole PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
target_link_libraries(lib-swoole ${SWOOLE_LINK_LIBRARIES})

if (CODE_COVERAGE)
    target_link_libraries(lib-swoole coverage_config gcov)
endif(CODE_COVERAGE)

# test_server
set(TEST_SRC_LIST examples/cpp/test_server.cc)
add_executable(test_server ${TEST_SRC_LIST})
add_dependencies(test_server lib-swoole)
target_link_libraries(test_server swoole pthread)

# co
set(TEST_SRC_LIST examples/cpp/co.cc)
add_executable(co ${TEST_SRC_LIST})
add_dependencies(co lib-swoole)
target_link_libraries(co swoole)

# ext-swoole
file(GLOB ext_cxx_files ext-src/*.cc)
set(ext_src_list  ${ext_cxx_files}
        thirdparty/php/curl/interface.cc
        thirdparty/php/curl/multi.cc
        thirdparty/php/sockets/multicast.cc
        thirdparty/php/sockets/sendrecvmsg.cc
        thirdparty/php/sockets/conversions.cc
        thirdparty/php/sockets/sockaddr_conv.cc
        thirdparty/php/standard/proc_open.cc
        thirdparty/nghttp2/nghttp2_hd.c
        thirdparty/nghttp2/nghttp2_rcbuf.c
        thirdparty/nghttp2/nghttp2_helper.c
        thirdparty/nghttp2/nghttp2_buf.c
        thirdparty/nghttp2/nghttp2_mem.c
        thirdparty/nghttp2/nghttp2_hd_huffman.c
        thirdparty/nghttp2/nghttp2_hd_huffman_data.c
    )
add_library(ext-swoole SHARED ${ext_src_list})
set_target_properties(ext-swoole PROPERTIES PREFIX "")
set_target_properties(ext-swoole PROPERTIES OUTPUT_NAME "swoole")
add_dependencies(ext-swoole lib-swoole)

# core-tests
pkg_check_modules(NGHTTP2 REQUIRED libnghttp2)
if (${NGHTTP2_FOUND})
    message(STATUS "Found nghttp2")
else()
    message(STATUS "Not found nghttp2")
endif()

# find GTest
find_package(GTest REQUIRED)
if (!${GTEST_FOUND})
    message(FATAL_ERROR "Not found GTest")
endif()
message(STATUS "Found GTest")

file(GLOB_RECURSE core_test_files core-tests/src/*.cpp thirdparty/llhttp/*.c)
add_executable(core-tests ${core_test_files})
add_dependencies(core-tests lib-swoole)
include_directories(BEFORE core-tests/include thirdparty thirdparty/hiredis thirdparty/llhttp/ ${GTEST_INCLUDE_DIRS} ${NGHTTP2_INCLUDE_DIR})
target_link_libraries(core-tests swoole pthread ssl crypto ${GTEST_BOTH_LIBRARIES} ${NGHTTP2_LIBRARIES})

# find libpq
if (DEFINED libpq_dir)
    include_directories(BEFORE ${libpq_dir}/include)
    link_directories(${libpq_dir}/lib)
else()
    pkg_check_modules(LIBPQ REQUIRED libpq)
    target_include_directories(ext-swoole PRIVATE ${LIBPQ_INCLUDE_DIRS})
endif()

target_link_libraries(ext-swoole swoole pq)

# install
INSTALL(TARGETS ext-swoole LIBRARY DESTINATION ${PHP_EXTENSION_DIR})
INSTALL(TARGETS lib-swoole LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${HEAD_WAPPER_FILES} DESTINATION include/swoole/wrapper)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)
