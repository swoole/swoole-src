PROJECT(libswoole)

ENABLE_LANGUAGE(ASM)
SET(SWOOLE_VERSION 4.5.3-alpha)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

add_definitions(-DHAVE_CONFIG_H)

set(libswoole_libraries pthread dl)
set(libswoole_headers_dir ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(libswoole_includes ${CMAKE_CURRENT_SOURCE_DIR}/.. ${libswoole_headers_dir} ${libswoole_headers_dir}/wrapper)
set(libswoole_thirdparty_dir ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty)

if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")
else()
    list(APPEND libswoole_libraries rt crypt)
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

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS *.cc ${libswoole_thirdparty_dir}/boost/asm/combined.S)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS ${libswoole_headers_dir}/*.h)
file(GLOB_RECURSE HEAD_WAPPER_FILES FOLLOW_SYMLINKS ${libswoole_headers_dir}/wrapper/*.hpp)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)

# find OpenSSL
if (DEFINED openssl_dir) 
    include_directories(BEFORE ${openssl_dir}/include)
    list(APPEND libswoole_includes ${openssl_dir}/include)
    link_directories(${openssl_dir}/lib)
else()
    find_package(OpenSSL)
    if (${OPENSSL_FOUND})
        message(STATUS "Found OpenSSL")
        list(APPEND libswoole_includes ${OPENSSL_INCLUDE_DIR})
        list(APPEND libswoole_libraries ${OPENSSL_LIBRARIES})
    else()
        message(STATUS "Not found OpenSSL")
    endif()
endif()

if (DEFINED brotli_dir) 
    list(APPEND libswoole_includes ${brotli_dir}/include)
    link_directories(${brotli_dir}/lib)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PHP_INCLUDES}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PHP_INCLUDES}")

# lib-swoole
link_directories(${LIBRARY_OUTPUT_PATH})
add_library(lib-swoole SHARED ${SRC_LIST})
set_target_properties(lib-swoole PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
target_include_directories(lib-swoole PRIVATE ${libswoole_includes})
target_link_libraries(lib-swoole ${libswoole_libraries})
if(CODE_COVERAGE)
    target_link_libraries(lib-swoole coverage_config gcov)
endif(CODE_COVERAGE)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS lib-swoole LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${HEAD_WAPPER_FILES} DESTINATION include/swoole/wrapper)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../config.h DESTINATION include/swoole)
