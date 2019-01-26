Swoole C++ library
==========


Build libswoole.so
------
```shell
git clone https://github.com/swoole/swoole-src.git
cd swoole-src
phpize
./configure
cmake .
make -j
export SWOOLE_DIR=/path/to/your/swoole-src
```

Build example server
------
```shell
cd examples
cmake .
make
```

Run
------
```shell
./server
```
