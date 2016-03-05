<?php
$cli = new swoole_http_client('127.0.0.1', 80);
//post request
//$cli->setData(http_build_query(['a'=>123,'b'=>"哈哈"]));
$cli->setHeaders(['User-Agent' => "swoole"]);

$cli->post('/dump.php', array("test" => 'abc'), function ($cli) {
    echo $cli->body;
    
    $cli->get('/dump.php', function ($cli) {
        echo $cli->body;
    });
});
