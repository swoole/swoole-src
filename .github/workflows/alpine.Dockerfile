ARG PHP_VERSION
ARG ALPINE_VERSION

FROM hyperf/hyperf:${PHP_VERSION}-alpine-v${ALPINE_VERSION}-dev

LABEL maintainer="Swoole Team <team@swoole.com>" version="1.0" license="Apache2"

ARG PHP_VERSION

COPY . /opt/www

WORKDIR /opt/www

RUN set -ex \
    && phpize \
    && ./configure --enable-openssl --enable-swoole-curl \
    && make -s -j$(nproc) && make install \
    && echo "extension=swoole.so" > /etc/php$(echo $PHP_VERSION | sed 's/\.//g')/conf.d/50_swoole.ini \
    # check
    && php -v \
    && php -m \
    && php --ri swoole \
    && echo -e "\033[42;37m Build Completed :).\033[0m\n"
