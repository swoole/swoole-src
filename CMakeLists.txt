PROJECT(libswoole)

ENABLE_LANGUAGE(ASM)
SET(SWOOLE_VERSION 4.4.14)
SET(SWOOLE_CLFLAGS pthread rt dl ssl crypt crypto)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c src/*.cc thirdparty/boost/asm/combined.S)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)
file(GLOB_RECURSE HEAD_WAPPER_FILES FOLLOW_SYMLINKS include/wrapper/*.hpp)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)
# test
#add_definitions(-DSW_USE_THREAD_CONTEXT)

INCLUDE_DIRECTORIES(BEFORE ./include ./include/wrapper ./)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

execute_process(COMMAND php-config --includes OUTPUT_VARIABLE PHP_INCLUDES OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PHP_INCLUDES}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PHP_INCLUDES}")

# lib-swoole
LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})
add_library(lib-swoole SHARED ${SRC_LIST})
set_target_properties(lib-swoole PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
target_link_libraries(lib-swoole ${SWOOLE_CLFLAGS})

# test_server
set(TEST_SRC_LIST examples/cpp/test_server.c)
add_executable(test_server ${TEST_SRC_LIST})
add_dependencies(test_server lib-swoole)
target_link_libraries(test_server ${SWOOLE_CLFLAGS} swoole)

# co
set(TEST_SRC_LIST examples/cpp/co.cc)
add_executable(co ${TEST_SRC_LIST})
add_dependencies(co lib-swoole)
target_link_libraries(co ${SWOOLE_CLFLAGS} swoole)

# ext-swoole
set(ext_src_list  php_swoole_cxx.cc
        swoole.cc
        swoole_async_coro.cc
        swoole_atomic.cc
        swoole_buffer.c
        swoole_channel_coro.cc
        swoole_client.cc
        swoole_client_coro.cc
        swoole_coroutine.cc
        swoole_coroutine_scheduler.cc
        swoole_coroutine_system.cc
        swoole_event.cc
        swoole_http2_client_coro.cc
        swoole_http2_server.cc
        swoole_http_client_coro.cc
        swoole_http_request.cc
        swoole_http_response.cc
        swoole_http_server.cc
        swoole_http_server_coro.cc
        swoole_lock.cc
        swoole_mysql_coro.cc
        swoole_mysql_proto.cc
        swoole_process.cc
        swoole_process_pool.cc
        swoole_redis_coro.cc
        swoole_redis_server.cc
        swoole_runtime.cc
        swoole_server.cc
        swoole_server_port.cc
        swoole_socket_coro.cc
        swoole_table.cc
        swoole_timer.cc
        swoole_websocket_server.cc
        thirdparty/php/sockets/multicast.cc
        thirdparty/php/sockets/sendrecvmsg.cc
        thirdparty/php/sockets/conversions.cc
        thirdparty/php/sockets/sockaddr_conv.cc
        thirdparty/php/standard/proc_open.cc
        thirdparty/swoole_http_parser.c
	    thirdparty/multipart_parser.c
        thirdparty/hiredis/async.c
        thirdparty/hiredis/hiredis.c
        thirdparty/hiredis/net.c
        thirdparty/hiredis/read.c
        thirdparty/hiredis/sds.c
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
target_link_libraries(ext-swoole ${SWOOLE_CLFLAGS} swoole)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS lib-swoole LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${HEAD_WAPPER_FILES} DESTINATION include/swoole/wrapper)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)
