#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os

dir = os.path.dirname(os.path.realpath(__file__))
print("generating swoole php library")

with open(dir + '/php_swoole_library.h', 'w') as outputFile:
    outputFile.write('const char *PHP_SWOOLE_LIBRARY_SOURCE = "')

    with open(dir + '/_library.i', 'r') as libIndexFile:
        while True:
            filename = libIndexFile.readline().strip()
            if not filename:
                break
            with open(dir + '/' + filename, 'r') as libSrcFile:
                source = libSrcFile.read()
                outputFile.write("\\\n" + source.replace('<?php', '', 1).replace('"', '\\"').replace("\n", "\\\n") + "\\\n")

    outputFile.write('";')
