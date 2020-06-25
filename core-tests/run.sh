#!/bin/bash
cmake . && make -j8 && ./bin/core_tests
