# Swoole Library

## How to contribute

```
update the PHP scripts in this dir
if ( new script ) {
    update "./config.inc"
}
if ( new hook function ) {
    update  "/swoole_runtime.cc" (search "hook_func")
}
run "/remake_library.sh" (recompile the library)
```

then new pull request (we need unit tests for new features)

## Code requirements

1. PHP 7.1+
2. PSR1 and PSR2
3. Strict type
