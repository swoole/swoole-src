--TEST--
swoole_curl: GH-23814 (Curl callbacks keep their receiver alive when replacing or clearing themselves)
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
    public string $value = 'Still alive';

    public function __construct(private string $action, private CurlHandle $handle) {}

    public function write(CurlHandle $handle, string $data): int {
        if ($this->action === 'clear') {
            curl_setopt_array($handle, [CURLOPT_WRITEFUNCTION => null]);
        } else {
            curl_setopt($handle, CURLOPT_WRITEFUNCTION, static fn($handle, $data) => strlen($data));
        }
        gc_collect_cycles();
        echo $this->value, "\n";
        if ($this->action === 'throw') {
            throw new Exception('Callback exception');
        }
        return strlen($data);
    }

    public function __call(string $name, array $args): int {
        return $this->write(...$args);
    }

    public function __destruct() {
        echo "Destroyed\n";
    }
}

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () {
    foreach (['replace' => 'write', 'clear' => 'missing', 'throw' => 'write'] as $action => $method) {
        echo "$method / $action\n";
        $handle = curl_init('file://' . __FILE__);
        curl_setopt($handle, CURLOPT_WRITEFUNCTION, [new Callback($action, $handle), $method]);
        try {
            var_dump(curl_exec($handle));
        } catch (Exception $e) {
            echo $e->getMessage(), "\n";
        }
        unset($handle);
    }
});
?>
--EXPECT--
write / replace
Still alive
Destroyed
bool(true)
missing / clear
Still alive
Destroyed
bool(true)
write / throw
Still alive
Destroyed
Callback exception
