LIBURING_VERSION=2.13
wget https://github.com/axboe/liburing/archive/refs/tags/liburing-${LIBURING_VERSION}.tar.gz
tar zxf liburing-${LIBURING_VERSION}.tar.gz
cd liburing-liburing-${LIBURING_VERSION} || exit
./configure
make -j"${SWOOLE_BUILD_JOBS:-1}" install
