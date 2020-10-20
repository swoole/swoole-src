#!/bin/bash
cmake .
make -j8
ipcs -q
./bin/core_tests
