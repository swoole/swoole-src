--TEST--
swoole_http_server: upload files array
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $filePath = TEST_IMAGE;
    $fileSize = filesize($filePath);
    $fileName = 'image.jpg';
    $fileType = 'image/jpeg';
    $fileInfo = function_exists('curl_file_create')
        ? curl_file_create($filePath, $fileType, $fileName)
        : "@$filePath;filename=$fileName;type=$fileType";
    $formData = [
        'file'              => $fileInfo,
        'form[file]'        => $fileInfo,
        'form[group][file]' => $fileInfo,
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Expect:']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $formData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $json = curl_exec($ch);
    curl_close($ch);

    Assert::assert(!empty($json));
    $result = json_decode($json, true);
    
    // Flat form field
    Assert::assert(isset($result['file']['name']));
    Assert::assert(isset($result['file']['type']));
    Assert::assert(isset($result['file']['error']));
    Assert::assert(isset($result['file']['size']));
    Assert::assert(isset($result['file']['tmp_name']));
    Assert::same($result['file']['name'], $fileName);
    Assert::same($result['file']['type'], $fileType);
    Assert::same($result['file']['error'], UPLOAD_ERR_OK);
    Assert::same($result['file']['size'], $fileSize);

    // Nested form field
    Assert::assert(isset($result['form']['file']['name']));
    Assert::assert(isset($result['form']['file']['type']));
    Assert::assert(isset($result['form']['file']['error']));
    Assert::assert(isset($result['form']['file']['size']));
    Assert::assert(isset($result['form']['file']['tmp_name']));
    Assert::same($result['form']['file']['name'], $fileName);
    Assert::same($result['form']['file']['type'], $fileType);
    Assert::same($result['form']['file']['error'], UPLOAD_ERR_OK);
    Assert::same($result['form']['file']['size'], $fileSize);

    // Deeply nested form field
    Assert::assert(isset($result['form']['group']['file']['name']));
    Assert::assert(isset($result['form']['group']['file']['type']));
    Assert::assert(isset($result['form']['group']['file']['error']));
    Assert::assert(isset($result['form']['group']['file']['size']));
    Assert::assert(isset($result['form']['group']['file']['tmp_name']));
    Assert::same($result['form']['group']['file']['name'], $fileName);
    Assert::same($result['form']['group']['file']['type'], $fileType);
    Assert::same($result['form']['group']['file']['error'], UPLOAD_ERR_OK);
    Assert::same($result['form']['group']['file']['size'], $fileSize);

    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(json_encode($request->files));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
