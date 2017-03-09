<?php
Swoole\Async::dnsLookup("www.htmleaf.com", function ($domainName, $ip) {
//Swoole\Async::dnsLookup("www.baidu.com", function ($domainName, $ip) {
   $cli = new swoole_http_client($ip, 80);
//$cli = new swoole_http_client($ip, 443,true);
    $cli->set(array(
     'http_proxy_host'=>"127.0.0.1",
      'http_proxy_port'=>3128,

    ));
    $cli->setHeaders([
        'Host' => $domainName,
        "User-Agent" => 'Chrome/49.0.2587.3',
    ]);
    $cli->get('/', function ($cli) {
        echo "Length: " . strlen($cli->body) . "\n";
$cli->close();     
 // echo $cli->body;
    });
});




?>
