--TEST--
swoole_http_client: post with empty content

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
$httpClient = new \swoole_http_client("115.239.210.27", "80");
@$httpClient->post("/", null, function ($client)
{
    echo "SUCCESS";
    $client->close();
});

$httpClient = new \swoole_http_client("115.239.210.27", "80");
@$httpClient->post("/", "", function ($client)
{
    echo "SUCCESS";
    $client->close();
});
Swoole\Event::wait();
?>

--EXPECT--
