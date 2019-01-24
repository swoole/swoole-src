cpp-swoole
==========
C++ wrapper for libswoole.


Install swoole
------
```shell
git clone https://github.com/swoole/swoole-src.git
phpize
./configure
cmake .
#cmake -DCMAKE_INSTALL_PREFIX=/opt/swoole .
sudo make install
```

Build libswoole_cpp.so
------
```shell
cmake .
#cmake -DCMAKE_INSTALL_PREFIX=/opt/swoole .
make
sudo make install
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
