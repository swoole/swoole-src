phpize --clean
phpize
./configure --enable-openssl --enable-sockets --enable-mysqlnd --enable-http2
make clean
make -j
make install
