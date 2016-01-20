#!/bin/sh
phpize && ./configure --enable-async-httpclient && make clean && make

