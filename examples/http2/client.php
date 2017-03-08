<?php
//$host = "www.jd.com";
$host = "www.echoteen.com";
$array = array(
    "accept" => '*/*',
    "host" => $host,
    "accept-encoding" => "gzip, deflate", 
    "user-agent" => 'nghttp2/1.7.1',
);
$list = array();
for($i = 0; $i < 1; $i++) {
    $client = new swoole_http2_client($host , 443, true);
    
    $client->setHeaders($array);
    //$client->setCookies(array("a" => "1", "b" => "2"));

    $client->get("/", function ($o) use($client) {
        echo "#{$client->sock} hello world 1\n";
        var_dump($o);
        echo $o->body;
        //$client->close();
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
