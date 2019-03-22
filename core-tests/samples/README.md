编译 swoole.so
------
`git clone`源代码，然后设置环境变量`export SWOOLE_DIR=/home/htf/workspace/swoole-src`

```shell
cd swoole-src
phpize
./configure
cmake .
make -j
```

编译示例程序
-----
```shell
cd swoole-src/core-tests/samples
cmake .
make -j
./bin/core_samples
```
