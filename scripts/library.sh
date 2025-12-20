#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ "$(uname -m)" = "aarch64" ]; then
  arch="-arm64"
else
  arch="x64"
fi

cd "${__DIR__}/"

apt update
bash ./install-deps-on-ubuntu.sh

# sshd
apt install -y openssh-server
service ssh start

# MariaDB ODBC Connector
MARIADB_CONNECTOR_VERSION=3.1.22
wget https://github.com/mariadb-corporation/mariadb-connector-odbc/archive/refs/tags/${MARIADB_CONNECTOR_VERSION}.tar.gz
tar zxf ${MARIADB_CONNECTOR_VERSION}.tar.gz
mkdir build
cd build
cmake ../mariadb-connector-odbc-${MARIADB_CONNECTOR_VERSION}/ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCONC_WITH_UNIT_TESTS=Off -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_SSL=OPENSSL
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

cd "${__DIR__}/"
bash ./install-liburing.sh

cd -
