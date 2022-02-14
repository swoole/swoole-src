--TEST--
curl_share_close basic test
--SKIPIF--
<?php if( !extension_loaded( 'curl' ) ) print 'skip'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();

$cm->run(function ($host) {
    $sh = curl_share_init();
    // Show that there's a curl_share object
    var_dump($sh);

    curl_share_close($sh);
    var_dump($sh);
});
?>
--EXPECTF--
object(CurlShareHandle)#%d (0) {
}
object(CurlShareHandle)#%d (0) {
}
