# Thread entry selection

`new Swoole\Thread($entry, ...$args)` accepts a script path, an internal
function name, or a public static method of an internal class:

```php
$script = new Swoole\Thread(__DIR__ . '/worker.php', $queue);
$function = new Swoole\Thread('App\\worker', $queue);
$method = new Swoole\Thread('App\\Worker::run', $queue);
```

Function and class names are resolved from the current symbol tables without
autoloading. Matching is case insensitive and accepts a leading backslash.
Only `ZEND_INTERNAL_FUNCTION` functions qualify. A method additionally requires
an internal class and a public, static, non-abstract internal method. TypePHP
exports provide these same Zend entries; they need no separate Swoole registry.
User functions, user classes, object methods and magic dispatch do not qualify.

A matching internal entry takes precedence over a same-named file. Prefix a
relative filename with `./` (or use an absolute path) to select that file.
Nonmatching strings follow the existing script execution path, including its
normal errors for missing files. Named arguments use `entry:`. Swoole Server's thread bootstrap
continues to use its explicit script execution path.

Each worker initializes its own PHP request before resolving and calling the
entry again. Only the entry name and arguments cross the thread boundary; the
parent's function pointers, call caches and execution context do not. Arguments
use the existing Swoole thread transfer rules and are passed positionally to
the function or method. Internal-entry array arguments are serialized so they
remain native PHP arrays, including nested values. Objects inside those arrays
must be serializable; shared thread resources can be passed as separate arguments.
Script-entry argument conversion remains unchanged. They also remain available through `getArguments()`.
By-reference arguments operate on worker-local copies, not parent variables.
The return value is transferred before the worker request is destroyed.

## Reading the result

See [the complete example](../examples/thread/result.php) for local-file or URL reading.

```php
$thread = new Swoole\Thread('file_get_contents', $filename);
$thread->join();
$contents = $thread->getResult();
```

The constructor starts the worker immediately; no `start()` call is needed.
`getResult()` throws `Error` until the worker has finished request shutdown and
thread-local cleanup. After `join()` it is safe to call repeatedly. A retained
detached Thread object can read its result after the worker has completed too.

Results use PHP serialization. The worker stores a persistent serialized buffer
before destroying its request. After completion, getResult() reconstructs a fresh
value in the caller's request. Arrays remain PHP arrays; ordinary request-owned
zvals never cross threads. Objects must support PHP serialization, including any
nested objects. Unserializable results fail the worker. A function with no return value, an early
exit or an uncaught exception yields null; use `getExitStatus()` to distinguish
successful completion from failure. Script entries also provide their `return` value, defaulting to 1 on normal
completion without return. PHP 8.2/8.3 retain the existing script execution path
and getResult() returns null after the thread exits.

An entry that is unavailable in the worker, throws an uncaught exception, or
otherwise fails produces the normal worker diagnostic and a nonzero exit
status. `join()` waits for completion; `getExitStatus()` reports that status.
Every worker still completes request shutdown and resource cleanup.

Registering an internal function does not itself make its implementation
thread-safe. Its extension must support PHP ZTS and independent requests.
TypePHP applications must initialize request state without automatically
running the application main entry in worker RINIT.
