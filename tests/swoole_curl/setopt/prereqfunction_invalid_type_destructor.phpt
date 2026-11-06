--TEST--
swoole_curl/setopt: CURLOPT_PREREQFUNCTION invalid return value is destroyed with the callback guard still set
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip('curl >= 7.80.0 is required', curl_version()['version_number'] < 0x075000);
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

class InvalidResult {
    public function __construct(private CurlHandle $handle) {}

    public function __destruct() {
        try {
            curl_reset($this->handle);
            echo "Reset accepted\n";
        } catch (Error $e) {
            echo $e->getMessage(), PHP_EOL;
        }
    }
}

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $ch = curl_init("http://{$host}/get.php");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_PREREQFUNCTION, fn () => new InvalidResult($ch));
    try {
        curl_exec($ch);
    } catch (TypeError $e) {
        echo $e->getMessage(), PHP_EOL;
    }
    echo "Done\n";
});
?>
--EXPECT--
curl_reset(): Attempt to reset cURL handle from a callback
The CURLOPT_PREREQFUNCTION callback must return either CURL_PREREQFUNC_OK or CURL_PREREQFUNC_ABORT
Done
