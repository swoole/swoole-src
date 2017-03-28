PHP_INCLUDE = `php-config --includes`
PHP_LIBS = `php-config --libs`
PHP_LDFLAGS = `php-config --ldflags`
PHP_INCLUDE_DIR = `php-config --include-dir`
PHP_EXTENSION_DIR = `php-config --extension-dir`

all: test.cpp
	clang -DHAVE_CONFIG_H -g -o test.so -O0 -fPIC -shared test.cpp -std=c++11 ${PHP_INCLUDE} -I${PHP_INCLUDE_DIR}/ext/swoole -I${PHP_INCLUDE_DIR}/ext/swoole/include
embed: embed.cpp
	c++ -DHAVE_CONFIG_H -g -o embed -O0 embed.cpp -std=c++11 ${PHP_INCLUDE} -I${PHP_INCLUDE_DIR}/ext/swoole -I${PHP_INCLUDE_DIR}/ext/swoole/include ${PHP_LDFLAGS} -lphp7 ${PHP_LIBS}
clean: test.so
	rm test.so
