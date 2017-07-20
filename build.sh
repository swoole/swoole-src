make clean
phpize --clean
phpize
./configure --enable-openssl --enable-sockets --enable-async-redis --enable-mysqlnd
make -j
make install
 
