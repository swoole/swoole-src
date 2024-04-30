--TEST--
swoole_http_server: cookies with partitioned
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $uri = "http://127.0.0.1:{$pm->getFreePort()}";
        httpRequest($uri)['set_cookie_headers'];
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        // empty name
        $response->cookie('', '123456789');
        // name with illegal character
        $response->cookie('test=,;', '123456789');
        // value with illegal character
        $response->rawcookie('test', '12345,; 6789');
        // path with illegal character
        $response->cookie('test', '123456789', time() + 3600, '/path,; ');
        // domain with illegal character
        $response->cookie('test', '123456789', time() + 3600, '/', 'exam,; ple.com');
        // expires greater than 9999
        $response->cookie('test', '123456789', time() + 253402300800);
        $response->end('Hello World');
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::cookie(): Cookie name cannot be empty in %s

Warning: Swoole\Http\Response::cookie(): Cookie name cannot contain "=", ",", ";", " ", "\t", "\r", "\n", "\013", or "\014" in %s

Warning: Swoole\Http\Response::rawcookie(): Cookie value cannot contain ",", ";", " ", "\t", "\r", "\n", "\013", or "\014" in %s

Warning: Swoole\Http\Response::cookie(): Cookie path option cannot contain ",", ";", " ", "\t", "\r", "\n", "\013", or "\014" in %s

Warning: Swoole\Http\Response::cookie(): Cookie domain option cannot contain ",", ";", " ", "\t", "\r", "\n", "\013", or "\014" in %s

Warning: Swoole\Http\Response::cookie(): Cookie expires option cannot have a year greater than 9999 in %s
DONE
