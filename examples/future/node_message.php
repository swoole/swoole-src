<?php
class G
{
    static $cluster = array();
}

$server = new swoole_server("0.0.0.0", 9501);
$server->listen("192.168.1.100", 9509, SWOOLE_NODE);

G::$cluster[] = $server->addNode("192.168.1.102", 9509);
G::$cluster[] = $server->delNode("192.168.1.103", 9509);

$server->on('NodeMessage', function (swoole_server $serv, $nodeId, $message) {
    $replyMessage = "helo $message";
    //回复消息
    $serv->sendMessage($replyMessage, $nodeId);
    //向第二个节点发消息
    $serv->sendMessage($message, G::$cluster[1]);
    //添加新节点
    $cluster[] = $serv->addNode("192.168.1.103", 9509);
});

$server->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    $cmd = trim($data);
    //发给节点0
    $serv->sendMessage($cmd, G::$cluster[0]);
    //向所有节点广播
    foreach (G::$cluster as $nodeId)
    {
        $serv->sendMessage($cmd, $nodeId);
    }
});

$server->start();
