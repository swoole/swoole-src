--TEST--
swoole_client_async: release clients and callbacks after close or connection failure
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach (['error', 'close'] as $expectedEvent) {
    // Binding without listening reserves the port while making connections fail.
    $flags = STREAM_SERVER_BIND | ($expectedEvent === 'close' ? STREAM_SERVER_LISTEN : 0);
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr, $flags);
    Assert::resource($server);
    $address = stream_socket_get_name($server, false);
    $port = (int) substr(strrchr($address, ':'), 1);

    if ($expectedEvent === 'close') {
        Swoole\Event::add($server, static function ($server) {
            $connection = stream_socket_accept($server, 0);
            Assert::resource($connection);
            fclose($connection);
            Swoole\Event::del($server);
        });
    }

    $completed = 0;
    $state = new stdClass;
    $stateReference = WeakReference::create($state);
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $clientReference = WeakReference::create($client);
    $client->on('connect', static function () use ($expectedEvent) {
        Assert::same($expectedEvent, 'close');
    });
    $client->on('receive', static function () {
        Assert::true(false, 'server should not send data');
    });
    foreach (['close', 'error'] as $event) {
        $client->on($event, static function () use ($state, &$completed, $event, $expectedEvent) {
            Assert::same($event, $expectedEvent);
            $completed++;
        });
    }
    Assert::true($client->connect('127.0.0.1', $port));
    unset($client, $state);

    Swoole\Event::wait();
    Assert::same($completed, 1);
    Assert::null($stateReference->get());
    Assert::null($clientReference->get());
    fclose($server);
}
echo "DONE\n";
?>
--EXPECT--
DONE
