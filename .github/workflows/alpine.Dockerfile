ARG PHP_VERSION
ARG ALPINE_VERSION

FROM phpswoole/php:${PHP_VERSION}-alpine

LABEL maintainer="Swoole Team <team@swoole.com>" version="1.0" license="Apache2"

ARG PHP_VERSION

COPY . /opt/www

WORKDIR /opt/www

RUN set -ex \
    && phpize \
    && ./configure --enable-openssl --enable-swoole-curl \
    && make -s -j$(nproc) && make install  \

RUN php-config
RUN echo "extension=swoole.so" > "$(php-config --lib-dir)/php.ini"
RUN php -v
RUN php -m
RUN php --ri swoole
RUN echo -e "\033[42;37m Build Completed :).\033[0m\n"
