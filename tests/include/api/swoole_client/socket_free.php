<?php

// swoole socket 复用BUG

function onClose(swoole_client $cli) {
    $fd = \EventUtil::getSocketFd($cli->getSocket());
    echo "close fd <$fd>\n";
}

function onError(swoole_client $cli) {
    $fd = \EventUtil::getSocketFd($cli->getSocket());
    echo "error fd <$fd>\n";
}

$host = "127.0.0.1";
$port = 8050;

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("receive", function(swoole_client $cli, $data){ });
$cli->on("error", "onError");
$cli->on("close", "onClose");

$cli->on("connect", function(swoole_client $cli) use($host, $port) {
    $fd = \EventUtil::getSocketFd($cli->getSocket());
    echo "connected fd <$fd>\n";
    $cli->close(); // close(fd)


    // -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    $newCli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $newCli->on("receive", function(swoole_client $cli, $data){ });
    $newCli->on("error", "onError");
    $newCli->on("close", "onClose");
    $newCli->on("connect", function(swoole_client $newCli) use($cli)  {
        $fd = \EventUtil::getSocketFd($cli->getSocket());
        echo "connected fd <$fd>, reuse!!!\n";

        echo "free socket\n";
        $cli->__destruct();
        echo "send\n";
        $r = $newCli->send("HELLO");
    });
    $newCli->connect($host, $port);
    // -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

});

$cli->connect($host, $port);
