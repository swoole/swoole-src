--TEST--
swoole_curl/upload: CURL file uploading
--INI--
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "{$host}/get.php?test=file");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    testcurl($ch, __DIR__ . '/curl_testdata1.txt');
    testcurl($ch, __DIR__ . '/curl_testdata1.txt', 'text/plain');
    testcurl($ch, __DIR__ . '/curl_testdata1.txt', '', 'foo.txt');
    testcurl($ch, __DIR__ . '/curl_testdata1.txt', 'text/plain', 'foo.txt');

    $file = new CurlFile(__DIR__ . '/curl_testdata1.txt');
    $file->setMimeType('text/plain');
    var_dump($file->getMimeType());
    var_dump($file->getFilename());
    curl_setopt($ch, CURLOPT_POSTFIELDS, array("file" => $file));
    var_dump(curl_exec($ch));

    $file = curl_file_create(__DIR__ . '/curl_testdata1.txt');
    $file->setPostFilename('foo.txt');
    var_dump($file->getPostFilename());
    curl_setopt($ch, CURLOPT_POSTFIELDS, array("file" => $file));
    var_dump(curl_exec($ch));

    curl_setopt($ch, CURLOPT_SAFE_UPLOAD, 0);
    $params = array('file' => '@' . __DIR__ . '/curl_testdata1.txt');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    var_dump(curl_exec($ch));

    curl_setopt($ch, CURLOPT_SAFE_UPLOAD, true);
    $params = array('file' => '@' . __DIR__ . '/curl_testdata1.txt');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    var_dump(curl_exec($ch));

    curl_setopt($ch, CURLOPT_URL, "{$host}/get.php?test=post");
    $params = array('file' => '@' . __DIR__ . '/curl_testdata1.txt');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    var_dump(curl_exec($ch));

    curl_close($ch);
});

function testcurl($ch, $name, $mime = '', $postname = '')
{
	if(!empty($postname)) {
		$file = new CurlFile($name, $mime, $postname);
	} else if(!empty($mime)) {
		$file = new CurlFile($name, $mime);
	} else {
		$file = new CurlFile($name);
	}
	curl_setopt($ch, CURLOPT_POSTFIELDS, array("file" => $file));
	$ret = curl_exec($ch) or die("ERROR: Code=".curl_errno($ch). "Msg=".curl_error($ch)."\n");
	var_dump($ret);
}
?>
--EXPECTF--
string(%d) "curl_testdata1.txt|application/octet-stream|6"
string(%d) "curl_testdata1.txt|text/plain|6"
string(%d) "foo.txt|application/octet-stream|6"
string(%d) "foo.txt|text/plain|6"
string(%d) "text/plain"
string(%d) "%s/curl_testdata1.txt"
string(%d) "curl_testdata1.txt|text/plain|6"
string(%d) "foo.txt"
string(%d) "foo.txt|application/octet-stream|6"

Warning: %s(): Disabling safe uploads is no longer supported in %s on line %d
string(0) ""
string(0) ""
string(%d) "array(1) {
  ["file"]=>
  string(%d) "@%s/curl_testdata1.txt"
}
"
