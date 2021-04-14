--TEST--
swoole_curl/setopt: curl_setopt_array() function - tests setting multiple cURL options with curl_setopt_array()
--CREDITS--
Mattijs Hoitink mattijshoitink@gmail.com
#Testfest Utrecht 2009
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
/*
 * Prototype:     bool curl_setopt_array(resource $ch, array $options)
 * Description:   Sets multiple options for a cURL session.
 * Source:        ext/curl/interface.c
 * Documentation: http://wiki.php.net/qa/temp/ext/curl
 */

require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    // Use the set Environment variable
    $url = "{$host}/get.php?test=get";

// Start the test
    echo '== Starting test curl_setopt_array($ch, $options); ==' . "\n";

// curl handler
    $ch = curl_init();

// options for the curl handler
    $options = array(
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => 1
    );


    curl_setopt_array($ch, $options);
    $returnContent = curl_exec($ch);
    curl_close($ch);

    var_dump($returnContent);
});


?>
--EXPECT--
== Starting test curl_setopt_array($ch, $options); ==
string(25) "Hello World!
Hello World!"
