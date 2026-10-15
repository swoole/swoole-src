--TEST--
swoole_server: parse option value to size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.2.0');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0);
$server->set([
    'buffer_output_size' => '2M',
]);
$server->set([
    'buffer_output_size' => 2 * 1024 * 1024,
]);
try {
    $server->set([
        'buffer_output_size' => 'xxx--2M',
    ]);
    Assert::true(false, 'invalid size must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::contains($exception->getMessage(), "failed to parse 'xxx--2M' to size");
    Assert::contains($exception->getMessage(), 'Invalid quantity');
}
Assert::same($server->setting['buffer_output_size'], 2 * 1024 * 1024);
echo "DONE\n";
?>
--EXPECT--
DONE
