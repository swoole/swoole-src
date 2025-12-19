#!/bin/sh -e
if [ "$(uname -m)" = "aarch64" ]; then
  arch="-arm64"
else
  arch="x64"
fi

apt update
bash ./install-deps-on-ubuntu.sh

# sshd
apt install -y openssh-server
service ssh start

# MariaDB ODBC Connector
wget https://github.com/mariadb-corporation/mariadb-connector-odbc/archive/refs/tags/3.1.21.tar.gz
tar zxf 3.1.21.tar.gz
mkdir build
cd build
cmake ../mariadb-connector-odbc-3.1.21/ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCONC_WITH_UNIT_TESTS=Off -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_SSL=OPENSSL
cmake --build . --config RelWithDebInfo
make install
echo '/usr/local/lib/mariadb/' > /etc/ld.so.conf.d/odbc-mariadb.conf
ldconfig

wget -nv https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linux${arch}.zip
unzip instantclient-basiclite-linux${arch}.zip && rm instantclient-basiclite-linux${arch}.zip
wget -nv https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linux${arch}.zip
unzip instantclient-sdk-linux${arch}.zip && rm instantclient-sdk-linux${arch}.zip
mv instantclient_*_* ./instantclient
rm ./instantclient/sdk/include/ldap.h
# fix debug build warning: zend_signal: handler was replaced for signal (2) after startup
echo DISABLE_INTERRUPT=on > ./instantclient/network/admin/sqlnet.ora
mv ./instantclient /usr/local/
echo '/usr/local/instantclient' > /etc/ld.so.conf.d/oracle-instantclient.conf
ldconfig

LIBURING_VERSION=2.13
wget https://github.com/axboe/liburing/archive/refs/tags/liburing-${LIBURING_VERSION}.tar.gz
tar zxf liburing-${LIBURING_VERSION}.tar.gz
cd liburing-liburing-${LIBURING_VERSION} && ./configure && make -j$(cat /proc/cpuinfo | grep processor | wc -l) && make install
