--TEST--
swoole_runtime: ssl capture_peer_cert
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function capture_peer_cert($domain)
{
    $g = stream_context_create([
        "ssl" => [
            "capture_peer_cert" => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false
        ]
    ]);
    $r = stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $g);
    if (!$r) {
        return false;
    }
    $cont = stream_context_get_params($r);
    if (!$cont) {
        return false;
    }
    return $cont;
}

Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);

Co\run(function ()  {
    $result = capture_peer_cert('www.baidu.com');
    $info1 = openssl_x509_parse($result["options"]["ssl"]["peer_certificate"]);
    Assert::isArray($info1);
    Assert::contains($info1['name'], 'baidu.com');
});
?>
--EXPECT--
