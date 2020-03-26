<?php

require __DIR__ . '/functions.php';

use Swoole\Server;

define('N', 32 * 1024 * 1024);
define('R_DATA', random_bytes(N));

const DEBUG = false;

$args = \SwooleBench\get_args();

//$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_BASE);
$serv = new Server("0.0.0.0", 9502);

$serv->set(
    array(
//	'worker_num' => 1,
//	'dispatch_mode' => 7,
        'open_length_check' => true,
        "package_length_type" => 'N',
        'package_body_offset' => 4,
        'enable_reuse_port' => true,
    )
);

$serv->on(
    'workerstart',
    function ($server, $id) {
        global $argv;
        swoole_set_process_name("php {$argv[0]}: worker");
    }
);

$serv->on(
    'connect',
    function (Server $serv, $fd, $rid) {
        //echo "connect\n";;
    }
);

$serv->on(
    'receive',
    function (Server $serv, $fd, $rid, $data) use ($args) {
        $header = unpack('Nid', substr($data, 4, 4));
        $id = $header['id'];
        $hash = substr($data, 8, 32);
        if ($hash !== md5(substr($data, -128, 128))) {
            echo "Client Request Data Error, id={$header['id']}, length=" . strlen($data) . "\n";
            $serv->close($fd);
        } else {
            $len = mt_rand(1024, 1024 * 1024);
            $send_data = substr(R_DATA, rand(0, N - $len), $len);
            if (!isset($args['readonly'])) {
                $serv->send($fd, pack('NN', $len + 32 + 4, $id) . md5(substr($send_data, -128, 128)) . $send_data);
            }
            if (DEBUG) {
                echo "Index-{$id} OK, length=" . strlen($data) . PHP_EOL;
            }
        }
    }
);

$serv->on(
    'close',
    function (Server $serv, $fd, $from_id) {
    }
);

$serv->start();
