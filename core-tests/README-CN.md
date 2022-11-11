**Swoole 核心单元测试**
===========
## **1. 编译googletest**
swoole单元测试依赖于googletest，因此第一步我们需要编译googletest。

这里要求gcc和和g++编译器的版本要大于4.8.5。
```shell
wget https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz
tar zxf release-1.11.0.tar.gz
cd googletest-release-1.11.0
mkdir ./build && cd ./build
cmake ..
make -j
make install
```
如果你已经安装了更高版本的gcc和g++编译器，但是在执行cmake . 的过程中还是发现如下输出。
```shell
- The C compiler identification is GNU 4.8.5
- The CXX compiler identification is GNU 4.8.5
```
请执行下面的代码并重试。
```shell
export CC=/usr/local/bin/gcc
export CXX=/usr/local/bin/g++
```

## **2. 编译swoole.so**
```shell
export SWOOLE_DIR=/your-path/swoole-src/
git clone https://github.com/swoole/swoole-src.git
cd /your-path/swoole-src/
./make.sh cmake
```

## **3. 拉取基础镜像**
```shell
docker pull vimagick/tinyproxy
docker create --name vimagicktinyproxy -p 8888:8888 vimagick/tinyproxy
docker start vimagicktinyproxy

docker pull xkuma/socks5
docker create --name xkumasocks5 -p 1080:1080  -e "PROXY_USER=user" -e "PROXY_PASSWORD=password" -e "PROXY_SERVER=0.0.0.0:1080" xkuma/socks5
docker start xkumasocks5
```

## **4. 运行swoole单元测试**
```shell
cd /your-path/swoole-src/core-tests
./run.sh
```
