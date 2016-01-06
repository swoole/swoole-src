<?php
$cli = new swoole_http_client('127.0.0.1', 80);
//post request
//$cli->setData(http_build_query(['a'=>123,'b'=>"哈哈"]));
//$cli->setHeaders(['User-Agent' => "swoole"]);

$cli->on('close', function ($cli)
{
    echo "close\n";
});

$cli->on('error', function ($cli)
{
    echo "error\n";
});

$cli->execute('/index.php', function ($cli) {
    echo "finish. page1 size".strlen($cli->body)."\n";
});
