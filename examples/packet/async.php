<?php
$cli = new swoole_client(SWOOLE_TCP | SWOOLE_PACKET, SWOOLE_SOCK_ASYNC);
$cli->on("connect",
    function (swoole_client $cli)
    {
        $cli->send("async client connected");
        swoole_timer_add(1000,
            function () use ($cli)
            {
                $cli->send("hello world");
            }
        );
    }
);

$cli->on("receive",
    function ($cli, $data)
    {
        echo "receive:{$data},len:" . strlen($data) . "\r\n";
    }
);

$cli->on(
    "close",
    function ($cli)
    {
        $cli->close();
    }
);

$cli->on(
    "error",
    function ($cli)
    {
        exit("connect failed. Error:{$cli->errCode}\r\n");
    }
);

$cli->connect("127.0.0.1", 5900, -1);

