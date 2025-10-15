## Basic C API
These functions enable you to obtain the spool version and insert some hooks into the spool,
such as `SW_GLOBAL_HOOK_BEFORE_SERVER_START`. The set function is called when the server starts.

The header file is `swoole_api.h`.
The symbol of this file will export the function name in `C` format, not `C++`.
Similarly, functions in the `Coroutine API` are also exported as `C` functions.

- `swoole_version()` Get the current version of Swoole
- `swoole_add_hook()` Add a hook function to the specified hook point

## Coroutine C API

These functions are similar to the C function in `unistd.h`, for example, read corresponds to
`swoole_coroutine_read()` in the coroutine environment.

In addition to the `POSIX API` like functions, some additional functions can be provided.
For example, the `swoole_coroutine_get_current_id()` can obtain the ID of the coroutine,
which is equivalent to the `getpid()` of the process.

The function similar to creating a process or thread is `swoole_coroutine_create()`,
which can be used to create a coroutine.

The header file is `swoole_coroutine_api.h`.

## C MACRO HOOK
Use `C/C++` macros to automatically replace read/write and other synchronously blocked unistd C functions as non blocking
coroutine functions (starts with `swoole_coroutine_`).
This method enables C++ network client code to be used in the swoole coroutine environment.

Including network and file system:

- `swoole_file_hook.h` Replace file system related functions, such as `open()`, `mkdir()`, etc
- `swoole_socket_hook.h` Replace network related functions, such as `socket()`, `recv()`, `send()`, etc

## C++ API

In addition to the above header files, others are only used in `C++` code.

### Independent header file

These header files have no dependencies. They can only contain C standard library header files, C++ header files,
and platform related or basic library header files.

- `swoole_config.h`: Buffer size, string, constant, etc
- `swoole_version.h`: Swoole version information
- `swoole_atomic.h`: Atomic operations
- `swoole_asm_context.h`: Assembly context switching
- `swoole_util.h`: Common utility functions
- `swoole_log.h`: Log related functions
- `swoole_memory.h`: Memory pool related functions
- `swoole_base64.h`: Base64 encoding and decoding
- `swoole_error.h`: Error code related functions
- and more ...

### Core header file
- `swoole.h`: Core class and function declarations
- `swoole_string.h`: String class and function declarations
- `swoole_coroutine.h`: Coroutine class and function declarations
- `swoole_async.h`: Asynchronous IO class and function declarations
- `swoole_process_pool.h`: Process pool class and function declarations
- `swoole_signal.h`: Signal handling class and function declarations
- `swoole_timer.h`: Timer class and function declarations
- `swoole_reactor.h`: Reactor class and function declarations
- and more ...

### Facade header file
These header files depend on the core header files and provide a higher level of abstraction.

- `swoole_server.h`: Server side class and function declarations
- `swoole_client.h`: Client side class and function declarations
- `swoole_coroutine_socket.h`: Coroutine socket class and function declarations
- `swoole_coroutine_system.h`: Coroutine system API class and function declarations
- `swoole_coroutine_channel.h`: Coroutine channel class and function declarations
