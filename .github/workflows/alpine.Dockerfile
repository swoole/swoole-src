ARG PHP_VERSION
ARG ALPINE_VERSION

FROM phpswoole/php:${PHP_VERSION}-alpine

LABEL maintainer="Swoole Team <team@swoole.com>" version="1.0" license="Apache2"

ARG PHP_VERSION

COPY . /swoole

WORKDIR /swoole

RUN set -ex \
    && phpize \
    && ./configure --enable-openssl --enable-swoole-curl \
    && make -s -j$(nproc) && make install

RUN echo "extension=swoole.so" > "/usr/local/etc/php/conf.d/swoole.ini"
RUN php -v
RUN php -m
RUN php --ri swoole
RUN echo -e "\033[42;37m Build Completed :).\033[0m\n"
