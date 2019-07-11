--TEST--
swoole_library/curl/basic: Test curl_error() & curl_errno() function with problematic proxy
--CREDITS--
TestFest 2009 - AFUP - Perrick Penet <perrick@noparking.net>
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
	if (!extension_loaded("curl")) print "skip";
	$addr = "www.".uniqid().".".uniqid();
	if (gethostbyname($addr) != $addr) {
		print "skip catch all dns";
	}
?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "http://www.example.org";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_PROXY, uniqid() . ":" . uniqid());
    curl_setopt($ch, CURLOPT_URL, $url);

    curl_exec($ch);
    var_dump(curl_error($ch));
    var_dump(curl_errno($ch));
    curl_close($ch);

}, false);

?>
--EXPECTF--
string(%d) "%r(Couldn't resolve proxy|Could not resolve proxy:|Could not resolve host:|Could not resolve:)%r %s"
int(5)
