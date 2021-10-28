--TEST--
swoole_library/name_service: resolve
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Http\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\NameService\Consul;

use function Swoole\Coroutine\run;

$ns = new Consul('http://127.0.0.1:8500');
Coroutine::set(['name_resolver' => [$ns]]);
run(function () {

});
echo "DONE\n";

?>
--EXPECTF--
DONE
