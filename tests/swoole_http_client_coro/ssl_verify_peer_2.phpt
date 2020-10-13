--TEST--
swoole_http_client_coro: ssl_verify_peer [2]
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\System;

Co\Run(function () {
    $client = new Client('www.baidu.com', 443, true);
    $client->set([
        'ssl_verify_peer' => true,
        'ssl_allow_self_signed' => true,
    ]);
    $result = $client->get("/");
    Assert::eq($result, true);
    Assert::eq($client->getStatusCode(), 200);
    $info = openssl_x509_parse($client->getPeerCert());
    Assert::contains($info['name'], 'baidu.com');
    Assert::contains($client->getBody(), 'baidu');
});

?>
--EXPECT--
