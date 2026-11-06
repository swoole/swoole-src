--TEST--
swoole_curl: GH-23814 (Curl callback receivers are destroyed with the callback guard still set)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip('file protocol not supported', !in_array('file', curl_version()['protocols'], true));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class Callback {
    public function __construct(private CurlHandle $handle) {}

    public function write(CurlHandle $handle, string $data): int {
        curl_setopt($handle, CURLOPT_WRITEFUNCTION, null);
        echo "Callback returning\n";
        return strlen($data);
    }

    public function __destruct() {
        foreach (['curl_reset', 'curl_close'] as $function) {
            try {
                $function($this->handle);
            } catch (Error $e) {
                echo $e->getMessage(), "\n";
            }
        }
        curl_setopt($this->handle, CURLOPT_WRITEFUNCTION,
            static function (CurlHandle $handle, string $data): int {
                echo "Callback installed by destructor\n";
                return strlen($data);
            });
    }
}

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () {
    $handle = curl_init('file://' . __FILE__);
    curl_setopt($handle, CURLOPT_WRITEFUNCTION, [new Callback($handle), 'write']);
    var_dump(curl_exec($handle));
    var_dump(curl_exec($handle));
    curl_reset($handle);
    echo "Reset outside callback succeeded\n";
});
?>
--EXPECT--
Callback returning
curl_reset(): Attempt to reset cURL handle from a callback
curl_close(): Attempt to close cURL handle from a callback
bool(true)
Callback installed by destructor
bool(true)
Reset outside callback succeeded
