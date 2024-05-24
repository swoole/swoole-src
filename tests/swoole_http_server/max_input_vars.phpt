--TEST--
swoole_http_server: max_input_vars
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $maxInputVars = ini_get('max_input_vars') + 10;
        $data = [];
        $cookies = [];
        $temp = 'max_input_vars';
        for ($i = 0; $i < $maxInputVars; $i++) {
            $data[$temp . $i] = $temp;
            $cookies[] = $temp . $i.'='.$temp;
        }

        // post method
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}", ['data' => $data, 'headers' => ['Cookie' => implode(';', $cookies)]]);

        // get method
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}?".http_build_query($data));
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response){
        $maxInputVars = ini_get('max_input_vars');
        if ($request->get) {
            var_dump(count($request->get) == $maxInputVars);
        }

        if ($request->post) {
            var_dump(count($request->post) == $maxInputVars);
        }

        if ($request->cookie) {
            var_dump(count($request->cookie) == $maxInputVars);
        }
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%s To increase the limit change max_input_vars in php.ini.
%s To increase the limit change max_input_vars in php.ini.
bool(true)
bool(true)
%s To increase the limit change max_input_vars in php.ini.
bool(true)
DONE
