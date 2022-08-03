--TEST--
swoole_http_server: upload files array parsed format
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
skip_if_function_not_exist('curl_file_create');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    $formData = [
        'file' => curl_file_create(TEST_IMAGE, 'application/octet-stream', 'image.jpg'),
        'form[file]' => curl_file_create(TEST_IMAGE, 'image/jpeg', 'photo.jpg'),
        'form[group][file]' => curl_file_create(TEST_IMAGE2, 'image/svg+xml', 'swoole-logo.svg'),
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Expect:']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $formData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($result, true);

    assert_upload_file($json['file'], '/tmp/swoole.upfile.fixture1', 'image.jpg', 'application/octet-stream', filesize(TEST_IMAGE), 0);
    assert_upload_file($json['form'], [
        'file' => '/tmp/swoole.upfile.fixture2',
        'group' => [
            'file' => '/tmp/swoole.upfile.fixture3',
        ],
    ], [
        'file' => 'photo.jpg',
        'group' => [
            'file' => 'swoole-logo.svg',
        ],
    ], [
        'file' => 'image/jpeg',
        'group' => [
            'file' => 'image/svg+xml',
        ],
    ], [
        'file' => filesize(TEST_IMAGE),
        'group' => [
            'file' => filesize(TEST_IMAGE2),
        ],
    ], [
        'file' => 0,
        'group' => [
            'file' => 0,
        ],
    ]);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null',
        'http_parse_files' => true,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $files = $request->files;
        if (!is_array($files)
            || empty($files['file']['tmp_name'])
            || empty($files['form']['tmp_name']['file'])
            || empty($files['form']['tmp_name']['group']['file'])
        ) {
            $response->end();
            return;
        }
        $files['file']['tmp_name'] = '/tmp/swoole.upfile.fixture1';
        $files['form']['tmp_name']['file'] = '/tmp/swoole.upfile.fixture2';
        $files['form']['tmp_name']['group']['file'] = '/tmp/swoole.upfile.fixture3';
        $response->end(json_encode($files));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
