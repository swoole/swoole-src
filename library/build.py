#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os

os.chdir(os.path.dirname(os.path.realpath(__file__)))
print("generating swoole php library")

with open('php_swoole_library.h', 'w') as outputFile:
    outputFile.write('const char *PHP_SWOOLE_LIBRARY_SOURCE = "')

    with open('_library', 'r') as libIndexFile:
        while True:
            filename = libIndexFile.readline()
            if not filename:
                break
            with open(filename, 'r') as libSrcFile:
                source = libSrcFile.read()
                outputFile.write("\\\n" + source.replace('"', '\\"').replace("\n", "\\\n") + "\\\n")

    outputFile.write('";')
