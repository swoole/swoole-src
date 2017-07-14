<?php
$cli = new Swoole\Http\Client('127.0.0.1', 9501, false);
$cli->setHeaders(array('User-Agent' => 'swoole-http-client'));

$cli->on('close', function($_cli) {
    echo "connection is closed\n";
});
$cli->get('/?dump.php?corpid=ding880f44069a80bca1&corpsecret=YB1cT8FNeN7VCm3eThwDAncsmSl4Ajl_1DmckaOFmOZhTFzexLbIzq5ueH3YcHrx', function ($cli) {
    var_dump($cli);
    var_dump($cli->headers);
    echo $cli->body;
    //$cli->close();
});
