<?php
//$host = '127.0.0.1';
//$host = "wiki.swoole.com";
$host = 'www.jd.com';

//$port = 9501;
$port = 443;

//$ssl = false;
$ssl = true;

$array = array(
    "host" => $host,
    "accept-encoding" => "gzip, deflate",
    'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'accept-language' => 'zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2',
    'cache-control' => 'max-age=0',
    'user-agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3026.3 Safari/537.36',
);
$list = array();
for($i = 0; $i < 1; $i++) {
    $client = new swoole_http2_client($host , $port, $ssl);
    
    $client->setHeaders($array);
    //$client->setCookies(array("a" => "1", "b" => "2"));

    $client->get("/", function ($o) use($client) {
        echo "#{$client->sock} hello world 1\n";
        //var_dump($o);
        echo $o->body;
        $client->close();
    });

    /*$client->post("/", $array, function ($o) use($client) {
        echo "{$client->sock} hello world 2\n";  
    });

    
    $client->post("/", $array, function ($o) use($client) {
        echo "{$client->sock} hello world 3\n";
        echo $o->body;
        $client->close();        
    });*/
    $list[] = $client;
}

Swoole\Event::wait();
