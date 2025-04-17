# This Dockerfile is designed to create a debug version of the PHP and Swoole environment,
 # enabling ASAN (`--enable-address-sanitizer`) to facilitate debugging and analysis of runtime crashes.
FROM ubuntu:22.04
ARG PHP_VERSION=8.2.28
RUN apt update
RUN apt install -y g++ cmake automake wget
RUN apt install -y libssl-dev libcurl4-openssl-dev libxml2-dev libzip-dev libsqlite3-dev libreadline-dev libonig-dev
RUN mkdir /work
WORKDIR /work
RUN wget https://www.php.net/distributions/php-8.2.28.tar.xz

RUN apt install -y xz-utils
RUN tar -xvf php-${PHP_VERSION}.tar.xz

RUN apt install -y pkg-config
RUN apt install -y git
RUN apt install -y libbz2-dev
RUN apt install -y libffi-dev
RUN apt install -y libxslt-dev
RUN apt install -y unixodbc-dev
RUN apt install -y libpq-dev
RUN apt install -y libbrotli-dev
RUN apt install -y libc-ares-dev

COPY . /work/php-${PHP_VERSION}/ext/swoole

RUN cd php-${PHP_VERSION} && ./buildconf --force && \
    ./configure --enable-mbstring --with-curl --with-openssl \
    --enable-soap --enable-intl --enable-bcmath --enable-sockets \
    --with-pear --with-webp --with-jpeg --with-ffi \
    --enable-sysvsem --enable-sysvshm --enable-sysvmsg --with-zlib --with-bz2 --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-xsl \
    --without-pdo-sqlite \
    --enable-debug --enable-address-sanitizer \
    --enable-swoole \
    --enable-swoole-curl   \
    --enable-swoole-pgsql  \
    --enable-swoole-sqlite \
    --enable-openssl \
    --enable-mysqlnd \
    --enable-cares \
    --with-swoole-odbc=unixODBC,/usr \
    --enable-brotli && \
    make clean && make -j $(nproc) && make install

RUN php -v
RUN php -m
RUN php --ri swoole
RUN php --ri curl
RUN php --ri openssl
RUN cd /work/php-${PHP_VERSION} && make clean
RUN cd /work && rm php-${PHP_VERSION}.tar.xz && rm -rf php-${PHP_VERSION}/ext/swoole/.git
RUN rm -rf /var/lib/apt/lists/* /usr/bin/qemu-*-static
