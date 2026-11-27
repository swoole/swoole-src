--TEST--
swoole_client_async: failed connect() and invalid settings release the client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

function make(int $type): Swoole\Async\Client {
    $cli = new Swoole\Async\Client($type);
    foreach (['connect', 'receive', 'close', 'error'] as $event) {
        $cli->on($event, function () use ($event) {
            echo "unexpected $event\n";
        });
    }
    return $cli;
}

// Synchronous failure without onError being invoked.
$cli = make(SWOOLE_SOCK_UNIX_STREAM);
Assert::false(@$cli->connect('/tmp/' . str_repeat('a', 200)));
Assert::false($cli->isConnected());
Assert::eq($cli->sock, -1);
$ref = WeakReference::create($cli);
unset($cli);
Assert::null($ref->get());

// Invalid settings throw, and the client created by connect() is released.
$cli = make(SWOOLE_SOCK_TCP);
$cli->set(['open_length_check' => true, 'package_length_type' => 'Z']);
try {
    $cli->connect('127.0.0.1', 1);
    echo "no exception\n";
} catch (Swoole\Exception $e) {
    echo "exception\n";
}
Assert::eq($cli->sock, -1);
Assert::false($cli->isConnected());
$ref = WeakReference::create($cli);
unset($cli);
Assert::null($ref->get());
echo "DONE\n";
?>
--EXPECT--
exception
DONE
