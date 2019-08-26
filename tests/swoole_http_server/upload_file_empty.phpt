--TEST--
swoole_http_server: upload files empty
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
skip_if_function_not_exist('curl_file_create');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $formData = [
        'file1' => curl_file_create('/dev/null', 'text/plain', 'empty.txt'),
        'file2' => curl_file_create('/dev/null', 'application/octet-stream', ''),
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

    echo "$result\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $files = $request->files;
        if (isset($files['file1']['tmp_name'])) {
            $files['file1']['tmp_name'] = '/tmp/swoole.upfile.fixture1';
        }
        $response->end(var_export($files, true));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
array (
  'file1' => 
  array (
    'name' => 'empty.txt',
    'type' => 'text/plain',
    'tmp_name' => '/tmp/swoole.upfile.fixture1',
    'error' => 0,
    'size' => 0,
  ),
  'file2' => 
  array (
    'name' => '',
    'type' => '',
    'tmp_name' => '',
    'error' => 4,
    'size' => 0,
  ),
)
