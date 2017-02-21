SWOOLE_SRC = "/home/htf/workspace/swoole"
PHP_INCLUDE = `php-config --includes`
PHP_LIBS = `php-config --libs`
PHP_LDFLAGS = `php-config --ldflags`

all: test.cpp
	c++ -DHAVE_CONFIG_H -g -o test.so -O0 -fPIC -shared test.cpp ${PHP_INCLUDE} -std=c++11 -I${SWOOLE_SRC}/include -I${SWOOLE_SRC}
embed: embed.cpp
	c++ -DHAVE_CONFIG_H -g -o embed -O0 embed.cpp -std=c++11 -I${SWOOLE_SRC} ${PHP_INCLUDE} ${PHP_LDFLAGS} -lphp7 ${PHP_LIBS}
clean: test.so
	rm test.so
