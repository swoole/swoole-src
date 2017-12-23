--TEST--
swoole_http_client: HEAD method
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php

require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_http_client/simple_http_client.php";

$cli = new swoole_http_client('stackoverflow.com');
$cli->set(array(
    'timeout' => 3,
));

$cli->on('close', function ($cli)
{
    echo "close\n";
});
$cli->on('error', function ($cli)
{
    echo "error\n";
});

$cli->setMethod('HEAD');

$cli->get('/', function ($cli)
{
    var_dump($cli->statusCode);
});
swoole_event::wait();
?>
--EXPECT--
SUCCESS
