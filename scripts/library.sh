#!/bin/sh -e
apt update
apt install -y libaio-dev libaio1 sqlite3 libsqlite3-dev unixodbc unixodbc-dev odbc-mariadb libzstd-dev
wget -nv https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip
unzip instantclient-basiclite-linuxx64.zip && rm instantclient-basiclite-linuxx64.zip
wget -nv https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip
unzip instantclient-sdk-linuxx64.zip && rm instantclient-sdk-linuxx64.zip
mv instantclient_*_* ./instantclient
rm ./instantclient/sdk/include/ldap.h
# fix debug build warning: zend_signal: handler was replaced for signal (2) after startup
echo DISABLE_INTERRUPT=on > ./instantclient/network/admin/sqlnet.ora
mv ./instantclient /usr/local/
echo '/usr/local/instantclient' > /etc/ld.so.conf.d/oracle-instantclient.conf
ldconfig

wget https://github.com/axboe/liburing/archive/refs/tags/liburing-2.6.tar.gz
tar zxf liburing-2.6.tar.gz
cd liburing-liburing-2.6 && ./configure && make -j$(cat /proc/cpuinfo | grep processor | wc -l) && make install

