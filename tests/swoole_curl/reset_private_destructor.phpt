--TEST--
swoole_curl: curl_reset() releases CURLOPT_PRIVATE after the handle is reset
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip('file protocol not supported', !in_array('file', curl_version()['protocols'], true));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

class PrivateValue
{
    public function __construct(private CurlHandle $handle, private Closure $onDestruct)
    {
    }

    public function __destruct()
    {
        ($this->onDestruct)($this->handle);
    }
}

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    // options the destructor sets are kept
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_PRIVATE, new PrivateValue($ch, function (CurlHandle $ch) {
        curl_setopt($ch, CURLOPT_PRIVATE, 'replacement');
        curl_setopt($ch, CURLOPT_URL, 'file://' . __FILE__);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    }));
    curl_reset($ch);
    var_dump(curl_getinfo($ch, CURLINFO_PRIVATE));
    var_dump(curl_exec($ch) === file_get_contents(__FILE__));

    // the destructor can reset the handle again
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_PRIVATE, new PrivateValue($ch, function (CurlHandle $ch) {
        curl_reset($ch);
    }));
    curl_reset($ch);
    var_dump(curl_getinfo($ch, CURLINFO_PRIVATE));
});
?>
--EXPECT--
string(11) "replacement"
bool(true)
bool(false)
