--TEST--
swoole_http_client_coro: invalid write_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$client = new Swoole\Coroutine\Http\Client('127.0.0.1', 80);
Assert::false($client->set(['write_func' => 'not_found_function']));
echo "DONE\n";
?>
--EXPECTF--
Warning: Swoole\Coroutine\Http\Client::set(): function 'not_found_function' is not callable in %s on line %d
DONE
