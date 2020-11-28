--TEST--
swoole_server/object: event object
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Server\Event;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            echo "Over flow. errno=" . $client->errCode;
            die("\n");
        }

        $data = base64_encode(random_bytes(rand(1024, 8192))) . "\r\n\r\n";;
        $client->send($data);
        $recv_data = $client->recv();
        Assert::assert($recv_data);
        $json = json_decode($recv_data);
        Assert::eq($json->data, $data);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(
        array(
            "worker_num" => 1,
            'event_object' => true,
            'log_file' => '/dev/null',
        )
    );
    $serv->on(
        'WorkerStart',
        function (Server $serv) use ($pm) {
            $pm->wakeup();
        }
    );
    $serv->on(
        'Connect',
        function (Server $serv, Event $object) {
            Assert::eq($object->fd, 1);
        }
    );
    $serv->on(
        'Close',
        function (Server $serv, Event $object) {
            Assert::eq($object->fd, 1);
        }
    );
    $serv->on(
        'receive',
        function (Server $serv, Event $object) {
            $serv->send($object->fd, json_encode(['worker' => $serv->getWorkerId(), 'data' => $object->data]));
        }
    );
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
