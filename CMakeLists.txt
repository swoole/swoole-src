PROJECT(libswoole)

ENABLE_LANGUAGE(ASM)
SET(SWOOLE_VERSION 4.3.1)
SET(SWOOLE_CLFLAGS pthread rt dl ssl crypt crypto)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c src/*.cc thirdparty/boost/asm/jump_x86_64_sysv_elf_gas.S thirdparty/boost/asm/make_x86_64_sysv_elf_gas.S)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)
file(GLOB_RECURSE HEAD_WAPPER_FILES FOLLOW_SYMLINKS include/wrapper/*.hpp)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)

INCLUDE_DIRECTORIES(BEFORE ./include ./include/wrapper ./ /usr/local/php/include /usr/local/php/include/Zend /usr/local/php/include/main)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#shared library
add_library(shared SHARED ${SRC_LIST})
set_target_properties(shared PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
target_link_libraries(shared ${SWOOLE_CLFLAGS})

#static library
# set_target_properties(static PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
# add_library(static STATIC ${SRC_LIST})
# target_link_libraries(static ${SWOOLE_CLFLAGS})

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#test_server
set(TEST_SRC_LIST examples/test_server.c)
add_executable(test_server ${TEST_SRC_LIST})
add_dependencies(test_server shared)
target_link_libraries(test_server ${SWOOLE_CLFLAGS} swoole)

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${HEAD_WAPPER_FILES} DESTINATION include/swoole/wrapper)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/swoole_config.h DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)
