# The C++ examples link against libswoole (the C++ library), NOT ext-swoole
# (the PHP extension modules/swoole.so). CMake knows the versioned library
# name; a bare `-lswoole` cannot find lib/libswoole.so.<version>.
.PHONY: all co repeat test_server clean

all: co repeat test_server

lib-swoole:
	cmake .
	cmake --build . --target lib-swoole --parallel 1

co: lib-swoole
	cmake --build . --target co --parallel 1

repeat: lib-swoole
	cmake --build . --target repeat --parallel 1

test_server: lib-swoole
	cmake --build . --target test_server --parallel 1

clean:
	cmake --build . --target clean
