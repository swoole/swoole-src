phpize --clean
phpize
./configure --enable-openssl --enable-sockets --enable-mysqlnd --enable-http2 --enable-coroutine-postgresql --enable-debug-log
make clean
make -j
make install
