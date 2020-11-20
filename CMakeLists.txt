PROJECT(libswoole)

ENABLE_LANGUAGE(ASM)
SET(SWOOLE_VERSION 4.5.8)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

set(CMAKE_MACOSX_RPATH 1)
set(SWOOLE_LINK_LIBRARIES pthread dl)

if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")
else()
    list(APPEND SWOOLE_LINK_LIBRARIES rt crypt)
endif()

SET(CMAKE_BUILD_TYPE Debug)

# Code Coverage Configuration
add_library(coverage_config INTERFACE)

option(CODE_COVERAGE "Enable coverage reporting" OFF)
if(CODE_COVERAGE)
    message(STATUS "Open coverage")
    # --coverage => -fprofile-arcs -ftest-coverage
    target_compile_options(coverage_config INTERFACE
        -O0
        -g
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
            thirdparty/hiredis/async.c
            thirdparty/hiredis/hiredis.c
            thirdparty/hiredis/net.c
            thirdparty/hiredis/read.c
            thirdparty/hiredis/sds.c
)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)
file(GLOB_RECURSE HEAD_WAPPER_FILES FOLLOW_SYMLINKS include/wrapper/*.hpp)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)
# test
#add_definitions(-DSW_USE_THREAD_CONTEXT)

include_directories(BEFORE ./include ./include/wrapper ext-src/ ./)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

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

execute_process(COMMAND php-config --includes OUTPUT_VARIABLE PHP_INCLUDES OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND php-config --extension-dir OUTPUT_VARIABLE PHP_EXTENSION_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
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
if(CODE_COVERAGE)
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
        thirdparty/php/sockets/multicast.cc
        thirdparty/php/sockets/sendrecvmsg.cc
        thirdparty/php/sockets/conversions.cc
        thirdparty/php/sockets/sockaddr_conv.cc
        thirdparty/php/standard/proc_open.cc
        thirdparty/swoole_http_parser.c
        thirdparty/multipart_parser.c
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

target_link_libraries(ext-swoole swoole)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS ext-swoole LIBRARY DESTINATION ${PHP_EXTENSION_DIR})
INSTALL(TARGETS lib-swoole LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${HEAD_WAPPER_FILES} DESTINATION include/swoole/wrapper)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)
