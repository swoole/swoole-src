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

$cli = new swoole_http_client('jd.com');
$cli->set(array(
    'timeout' => 3,
));

$cli->on('close', function ($cli)
{

});
$cli->on('error', function ($cli)
{
    echo "error\n";
});

$cli->setMethod('HEAD');

$cli->get('/', function ($cli)
{
    assert($cli->statusCode == 302);
    $cli->close();
});
swoole_event::wait();
?>
--EXPECT--

