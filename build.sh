git submodule update --init --recursive
cd thirdparty/hiredis
make 
sudo make install
cd ../nghttp2
cmake .
make
sudo make install
sudo ldconfig
cd ../..
phpize --clean
phpize
make clean
./configure --enable-openssl --enable-sockets --enable-async-redis --enable-mysqlnd --enable-http2
make -j
make install

