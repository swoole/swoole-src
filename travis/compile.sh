#!/bin/sh
phpize && ./configure --enable-async-httpclient --enable-async-redis && make clean && make

