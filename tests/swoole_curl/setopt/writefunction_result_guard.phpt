--TEST--
swoole_curl/setopt: CURLOPT_WRITEFUNCTION result is converted and released with the callback guard still set
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.3');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

function reset_handle(CurlHandle $handle, string $from): void
{
    try {
        curl_reset($handle);
        echo "{$from}: reset accepted\n";
    } catch (Error $e) {
        echo "{$from}: ", $e->getMessage(), PHP_EOL;
    }
}

class ResetOnDestruct
{
    public function __construct(private CurlHandle $handle)
    {
    }

    public function __destruct()
    {
        reset_handle($this->handle, '__destruct');
    }
}

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $ch = curl_init("http://{$host}/get.php");
    // Converting the object to an int warns, and releasing it runs its destructor.
    set_error_handler(function () use ($ch) {
        reset_handle($ch, 'error handler');
        return true;
    });
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, fn ($ch) => new ResetOnDestruct($ch));
    var_dump(curl_exec($ch));
    var_dump(curl_errno($ch) === CURLE_WRITE_ERROR);
});
?>
--EXPECT--
error handler: curl_reset(): Attempt to reset cURL handle from a callback
__destruct: curl_reset(): Attempt to reset cURL handle from a callback
bool(false)
bool(true)
