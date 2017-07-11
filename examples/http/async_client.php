<?php
$cli = new swoole_http_client('127.0.0.1', 9501);
//post request
//$cli->setData(http_build_query(['a'=>123,'b'=>"哈哈"]));
$cli->setHeaders(['User-Agent' => "swoole"]);

$cli->get('/index.php', function ($cli)
{
    var_dump($cli);
});

//$cli->post('/dump.php', array("test" => 'abc'), function ($cli) {
//    echo $cli->body;
//    $cli->get('/index.php', function ($cli) {
//        file_put_contents(__DIR__.'/t.html', $cli->body);
//        $cli->download('/index.php', __DIR__.'/phpinfo.html', function ($cli)
//        {
//            var_dump($cli->downloadFile);
//        });
//    });
//});
