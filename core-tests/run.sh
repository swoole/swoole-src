#!/bin/bash
cmake -DUSE_CARES=ON . && make -j8 && ./bin/core_tests
