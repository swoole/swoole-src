## Swoole Tests

## Core Tests
Used to test the core code in the `src/` directory, only as a C++ library, not related to php.
The core tests depends on the googletest framework, and googletest needs to be installed.
The core test cases must be written with `C++`.

`GCC/G++` version `8.0` or higher is required, with full support for `C++17`.

### **Build googletest**
Since swoole core unit testing rely on googletest, we need compile googletest at first.

```shell
wget https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz
tar zxf googletest-1.15.2.tar.gz
cd googletest-1.15.2
mkdir ./build && cd ./build
cmake ..
make -j
sudo make install
```

### Build libswoole.so

```shell
cd swoole-src
cmake .
make -j$(nproc) lib-swoole
```
### Build core-tests
```shell
make -j$(nproc) core-tests
```

### Run core-tests
```shell
# run all dependency services
cd core-tests
docker compose up -d
# run all tests
./bin/core-tests
# run some test cases
./bin/core-tests --gtest_filter=server.*
# list all tests
./bin/core_tests --gtest_list_tests
```

## PHP Tests
Used to test the php extension code in the `ext-src/` directory. The swoole php test depends on php environment.
The `php-dev` related components must be installed.

The php test cases must be written with `PHP`.

### Build ext-swoole
```shell
cd swoole-src
phpize
./configure ${options}
make -j$(nproc)
make install
```
Need to configure `php.ini`, add `extension=swoole.so` to enable `ext-swoole`.

### Run tests
```shell
./scripts/route.sh
```

The automated test scripts in this directory can not only run on Github Action CI. Powered by docker container technology, it can run on any systems. You only need to run the `route.sh` script to create containers of multiple PHP environments then it will run Swoole's build tests and unit tests on multiple systems automatically.

### With special branch

```shell
SWOOLE_BRANCH=alpine ./scripts/route.sh
```

### Enter the container

> You can cancel the unit test by `CTRL+C`

```shell
docker exec -it -e LINES=$(tput lines) -e COLUMNS=$(tput cols) swoole /bin/bash
```
