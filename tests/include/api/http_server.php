<?php
/**
 * @var $pm \ProcessManager
 */
global $pm;

$http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_BASE);
$http->set(array(
    'log_file' => '/dev/null',
    "http_parse_post" => 1,
    "upload_tmp_dir" => "/tmp",
));
$http->on("WorkerStart", function (Swoole\Server $serv) {
    global $pm;
    if ($pm) {
        $pm->wakeup();
    }
});
$http->on('request', function ($request, Swoole\Http\Response $response) use ($pm) {
    $route = $request->server['request_uri'];
    if ($route == '/info') {
        $response->end($request->header['user-agent']);
        return;
    } elseif ($route == '/cookies') {
        $response->end(@json_encode($request->cookie));
        return;
    } elseif ($route == '/get') {
        $response->end(@json_encode($request->get));
        return;
    } elseif ($route == '/post') {
        $response->end(@json_encode($request->post));
        return;
    } elseif ($route == '/get_file') {
        $response->sendfile(TEST_IMAGE);
        return;
    } elseif ($route == '/upload_file') {
        $response->end(json_encode([
            'files' => $request->files,
            'md5' => md5_file($request->files['test_jpg']['tmp_name']),
            'post' => $request->post
        ]));
        return;
    } elseif ($route == '/gzip') {
        $response->gzip(5);
        $content = co::readFile(__DIR__ . '/../../../README.md');
        $response->end($content);
        return;
    } else {
        return;
    }
});
$http->start();
