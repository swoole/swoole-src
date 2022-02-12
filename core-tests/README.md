**Swoole core unit testing**
===========
## **1. compiling googletest**
Since swoole core unit testing rely on googletest, we need compile googletest at first.

gcc compiler version > 4.8.5 and gcc-c++ compiler version > 4.8.5.
```shell
wget https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz
tar zxf release-1.11.0.tar.gz
cd googletest-release-1.11.0
mkdir ./build && cd ./build
cmake ..
make -j
make install
```
The output still contains the following messages after compiling higher version gcc and gcc-c++.

```shell
- The C compiler identification is GNU 4.8.5
- The CXX compiler identification is GNU 4.8.5
```
Please execute following code and retry.
```shell
export CC=/usr/local/bin/gcc
export CXX=/usr/local/bin/g++
```

## **2. How to compile swoole.so**
```shell
export SWOOLE_DIR=/your-path/swoole-src/
git clone https://github.com/swoole/swoole-src.git
cd /your-path/swoole-src/
./make.sh cmake
```

## **3. Run swoole core testing**
```shell
cd /your-path/swoole-src/core-tests
./run.sh
```
