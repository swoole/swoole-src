--TEST--
swoole_http_client_coro: negative max_retries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;

$errors = [];
set_error_handler(function (int $errno, string $errstr) use (&$errors) {
    $errors[] = $errstr;
    return true;
});

$cli = new Client('127.0.0.1', get_one_free_port());
try {
    $cli->set(['max_retries' => -1]);
    Assert::true(false, 'invalid size must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::contains($exception->getMessage(), 'max_retries');
}

restore_error_handler();

Assert::same($errors, []);

echo "DONE\n";
?>
--EXPECT--
DONE
