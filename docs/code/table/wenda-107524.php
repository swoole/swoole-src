<?php
/**
 * @link https://wenda.swoole.com/detail/107524
 *
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

$table = new Swoole\Table(1024);
$table->column('fd', Swoole\Table::TYPE_INT);
$table->create();

$server = new Swoole\Server('127.0.0.1', 9501, SWOOLE_PROCESS);
$server->set(['worker_num' => 2, 'dispatch_mode' => 2]);

/** @var \Swoole\Table table */
$server->table = $table;

$server->on('Connect', function ($server, $fd) {
    $server->table->set('fd:' . $fd, ['fd' => $fd]);
    echo "Client: Connect.\n";
});

$server->on('Receive', function ($server, $fd, $reactor_id, $data) {
    echo "worker #{$server->worker_id}\tClient[$fd]: $data\n";
    if ($server->worker_id == 0) {
        for ($i=0;$i<10;$i++) {
            $server->table->set('fd:' . uniqid(), ['fd' => time()]);
        }
        foreach ($server->table as $key => $row) {
            var_dump($key);
//            $server->table->del($key);
        }
        $server->table->del('fd:' . $fd);
    } else {
        foreach ($server->table as $key => $row) {
            var_dump($key);
        }
    }
    $server->send($fd, 'Server:'.$data);
});

$server->on('Close', function ($server, $fd) {
    $server->table->del('fd:'.$fd);
    echo "client-{$fd} is closed\n";
});

$server->start();
