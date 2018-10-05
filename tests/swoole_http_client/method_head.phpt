--TEST--
swoole_http_client: HEAD method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/simple_http_client.php';

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

