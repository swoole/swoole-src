--TEST--
swoole_http2_server: add server addr for http2 server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$output = shell_exec('ip addr show');
preg_match_all('/inet (\d+\.\d+\.\d+\.\d+)\//', $output, $matches);
$ips = $matches[1];

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $ips) {
    go(function () use ($pm, $ips) {
        $domain = $ips[1];
        $cli = new Swoole\Coroutine\Http2\Client($domain, $pm->getFreePort(), true);
        $cli->set([
            'timeout' => 10,
            'ssl_cert_file' => SSL_FILE_DIR . '/client-cert.pem',
            'ssl_key_file' => SSL_FILE_DIR . '/client-key.pem'
        ]);
        Assert::assert($cli->connect());

        $req = new Swoole\Http2\Request;
        $req->method = 'POST';
        $req->path = '/';
        $req->headers = [
            'Host' => $domain,
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-encoding' => 'gzip'
        ];
        for ($n = MAX_REQUESTS; $n--;) {
            $req->data = get_safe_random(65535 + mt_rand(0, 65535));
            Assert::assert($cli->send($req));
            $res = $cli->recv();
            Assert::same($res->statusCode, 200);
            Assert::same(md5($req->data), md5($res->data));
        }
        $pm->kill();
    });
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm, $ips) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
            'worker_num' => 1,
            'log_file' => '/dev/null',
            'open_http2_protocol' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key'
        ] + (IS_IN_CI ? [] : [
            'ssl_verify_peer' => true,
            'ssl_allow_self_signed' => true,
            'ssl_client_cert_file' => SSL_FILE_DIR . '/ca-cert.pem'
        ])
    );
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($ips) {
        $server = $request->server;
        Assert::eq($server['server_addr'], $ips[1]);
        Assert::eq($server['remote_addr'], $ips[1]);
        Assert::true($server['server_port'] != $server['remote_port']);
        $response->end($request->rawcontent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
