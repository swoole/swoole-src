SWOOLE_SRC = "/home/htf/workspace/swoole"

all: test.cpp
	c++ -DHAVE_CONFIG_H -g -o test.so -O0 -fPIC -shared test.cpp -ldl `php-config --includes` -std=c++11 -I${SWOOLE_SRC}/include -I${SWOOLE_SRC}
clean: test.so
	rm test.so
