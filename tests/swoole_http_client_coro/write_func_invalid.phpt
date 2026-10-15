--TEST--
swoole_http_client_coro: invalid write_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$client = new Swoole\Coroutine\Http\Client('127.0.0.1', 80);
Assert::true($client->set(['timeout' => 1]));
$settings = $client->setting;
try {
    $client->set(['write_func' => 'not_found_function']);
    Assert::true(false, 'invalid write_func must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::contains($exception->getMessage(), 'callback must be callable');
}
Assert::same($client->setting, $settings);
echo "DONE\n";
?>
--EXPECT--
DONE
