# core source file
clang-format -i src/core/*.cc
clang-format -i src/coroutine/*.cc
clang-format -i src/lock/*.cc
clang-format -i src/memory/*.cc
clang-format -i src/network/*.cc
clang-format -i src/os/*.cc
clang-format -i src/pipe/*.cc
clang-format -i src/protocol/*.cc
clang-format -i src/reactor/*.cc
clang-format -i src/server/*.cc
clang-format -i src/wrapper/*.cc
# core header file
clang-format -i include/*.h

# ext source file
clang-format -i *.cc
clang-format -i *.h

clang-format -i examples/cpp/*.cc

# core-tests source file
clang-format -i core-tests/src/_lib/*.cpp
clang-format -i core-tests/src/client/*.cpp
clang-format -i core-tests/src/core/*.cpp
clang-format -i core-tests/src/coroutine/*.cpp
clang-format -i core-tests/src/lock/*.cpp
clang-format -i core-tests/src/memory/*.cpp
clang-format -i core-tests/src/network/*.cpp
clang-format -i core-tests/src/os/*.cpp
clang-format -i core-tests/src/process/*.cpp
clang-format -i core-tests/src/protocol/*.cpp
clang-format -i core-tests/src/reactor/*.cpp
clang-format -i core-tests/src/server/*.cpp
clang-format -i core-tests/src/main.cpp