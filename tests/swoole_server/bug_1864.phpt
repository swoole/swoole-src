--TEST--
swoole_server: bug Github#1864
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 64;
const M = 512;

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    function run()
    {
        global $pm;
        $client = new \Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        static $index = 0;
        if ($client->connect('127.0.0.1', $pm->getFreePort()) == false) {
            echo "connect error\n";
            return;
        }
        $count = rand(10240, 25600);
        for ($i = 0; $i < M; $i++) {
            $seq = $i % 10;
            $len = rand(10240, 25600);
            $message = "|||len=$len|||index=$index|||" . str_repeat(strval($seq), $len);
            $data = pack('N', $index++) . pack('N', strlen($message)) . $message;
            if ($client->send($data) == false) {
                echo "send failed, index=$index\n";
                break;
            }
        }
    }
    for ($i = 0; $i < N; $i ++) {
        run();
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $ss = [
        'daemonize' => 0,
        'dispatch_mode' => 1,
        'worker_num' => 1,
        'backlog' => 512,
        'max_request' => 0,
        'enable_coroutine' => false,
        'open_length_check' => true,
        'package_max_length' => 1048576, // 1MB
        'package_length_type' => 'N',
        'package_length_offset' => 4, // | seq || size || message |
        'package_body_offset' => 8, // seq + size
        'socket_buffer_size' => 1048576 * 4,
        'output_buffer_size' => 1048576,
        'log_file' => TEST_LOG_FILE,
    ];

    $status = new swoole_atomic(0);

    $tcp = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $tcp->set($ss);
    $tcp->on('receive', function (Server $server, $fd, $reactorID, $data) use ($status) {
        $size = unpack('N', substr($data, 4, 4))[1];
        if ($size !== strlen($data) - 8)
        {
            $server->shutdown();
            $status->set(1);
        }
    });
    $tcp->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $tcp->on("shutdown", function (Server $serv) use ($status) {
        if ($status->get() == 1) {
            exit(10);
        }
    });
    $tcp->start();
};

$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);

?>
--EXPECT--
