--TEST--
swoole_http2_client: get
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
swoole_async_dns_lookup("www.jd.com", function ($domain, $ip)
{
    $client = new Swoole\Http2\Client($ip, 443, true);
    $array = array(
        "host" => "www.jd.com",
        "accept-encoding" => "gzip, deflate",
        'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'accept-language' => 'zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2',
        'user-agent' => 'Mozilla/5.0 (X11; Linux x86_64) Chrome/58.0.3026.3 Safari/537.36',
    );
    $client->setHeaders($array);
    $client->get("/", function ($o) use ($client)
    {
        assert($o->statusCode == 200);
        assert(strlen($o->body) > 1024);
        $client->close();
    });
});
swoole_event::wait();
?>
--EXPECT--
