<?php
/**
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

$table = new Swoole\Table(1024);
$table->column('fd', Swoole\Table::TYPE_INT);
$table->create();

//创建WebSocket Server对象，监听0.0.0.0:9502端口
$ws = new Swoole\WebSocket\Server('0.0.0.0', 9502);

/** @var \Swoole\Table table */
$ws->table = $table;

//监听WebSocket连接打开事件
$ws->on('open', function ($ws, $request) {
    echo 'WebSocket 连接建立:' . $request->fd . PHP_EOL;
    $ws->table->set('fd:' . $request->fd, ['fd' => $request->fd]);
    $ws->push($request->fd, "hello, welcome");
});

//监听WebSocket消息事件
$ws->on('message', function ($ws, $frame) {
//    foreach ($ws->connections as $fd) {
//        if ($ws->isEstablished($fd)) {
//            // 调用 push 方法向客户端推送数据
//            $ws->push($fd, "{$frame->data}");
//        }
//    }

    foreach ($ws->table as $key => $row) {
        if (strpos($key, 'fd:') === 0 && $ws->isEstablished($row['fd'])) {
            // 调用 push 方法向客户端推送数据
            $ws->push($row['fd'], "{$frame->data}");
        }
    }
});

//监听WebSocket连接关闭事件
$ws->on('close', function ($ws, $fd) {
    $ws->table->del('fd:'.$fd);
    echo "client-{$fd} is closed\n";
    echo $ws->table->count();
});

$ws->start();
