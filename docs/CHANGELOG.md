# Swoole Changelog

## 2024-01-24 v5.1.2
- Added support for embed sapi @matyhtf
- Fixed compatibility with PHP 8.3 ZEND_CHECK_STACK_LIMIT @Yurunsoft
- Fixed no Content-Range response header when the range request returns all the contents of the file @Yurunsoft
- Optimized HTTP server performance @NathanFreeman
- Fixed truncated cookie @stnguyen90
- Fixed native-curl crash on PHP 8.3 @NathanFreeman
- Added CLOSE_SERVICE_RESTART, CLOSE_TRY_AGAIN_LATER, CLOSE_BAD_GATEWAY as valid close reasons for websocket @cjavad
- Fixed invalid errno after Server::Manager::wait() @JacobBrownAustin
- Fixed HTTP2 Typo @leocavalcante

## 2022-07-22 v5.0.0

### Added
* Added `max_concurrency` option for `Server`
* Added `max_retries` option for `Coroutine\Http\Client`
* Added `name_resolver` global option
* Added `upload_max_filesize` option for `Server`
* Added `Coroutine::getExecuteTime()`
* Added `SWOOLE_DISPATCH_CONCURRENT_LB` dispatch_mode for `Server`

### Changed
* Enhanced type system, added types for parameters and return values of all functions
* Optimized error handling, all constructors will throw exceptions when fail
* Adjusted the default mode of Server, the default is `SWOOLE_BASE` mode

### Removed

- Removed `PSR-0` style class names
- Removed the automatic addition of `Event::wait()` in shutdown function
- Removed `Server::tick/after/clearTimer/defer` aliases
- Removed `--enable-http`/`--enable-swoole-json`, adjusted to be enable by default

### Deprecated
- Deprecated `Coroutine\Redis` and `Coroutine\MySQL`
