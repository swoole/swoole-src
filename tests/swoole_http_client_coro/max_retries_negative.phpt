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
Assert::false($cli->set(['max_retries' => -1]));

restore_error_handler();

Assert::eq(count($errors), 1);
Assert::contains($errors[0], 'max_retries');

echo "DONE\n";
?>
--EXPECT--
DONE
