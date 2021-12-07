--TEST--
swoole_curl/basic: Test curl_error() & curl_errno() function with problematic proxy
--CREDITS--
TestFest 2009 - AFUP - Perrick Penet <perrick@noparking.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
	if (!extension_loaded("curl")) print "skip";
	$addr = "www.".uniqid().".".uniqid();
	if (gethostbyname($addr) != $addr) {
		print "skip catch all dns";
	}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "http://www.example.org";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_PROXY, uniqid() . ":" . uniqid());
    curl_setopt($ch, CURLOPT_URL, $url);

    curl_exec($ch);
    Assert::eq(curl_errno($ch), CURLE_COULDNT_RESOLVE_PROXY);
    curl_close($ch);
    echo "DONE\n";
}, false);

?>
--EXPECT--
DONE
