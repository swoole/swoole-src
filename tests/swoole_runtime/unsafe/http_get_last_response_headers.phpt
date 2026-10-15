--TEST--
swoole_runtime: reject request-global HTTP response headers in coroutines
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

var_dump(http_get_last_response_headers());
for ($i = 0; $i < 2; $i++) {
    Co\run(function () {
        var_dump(http_get_last_response_headers());
    });
    var_dump(http_get_last_response_headers());
}
?>
--EXPECTF--
NULL

Warning: http_get_last_response_headers() is not supported in Swoole coroutines in %s on line %d
NULL
NULL

Warning: http_get_last_response_headers() is not supported in Swoole coroutines in %s on line %d
NULL
NULL
