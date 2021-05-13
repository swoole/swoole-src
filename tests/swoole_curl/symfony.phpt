--TEST--
swoole_curl: symfony http client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use Symfony\Component\HttpClient\HttpClient as SymfonyHttpClient;
use Symfony\Component\HttpClient\HttplugClient as SymfonyHttplugClient;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr17FactoryDiscovery;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $httpClient = new SymfonyHttplugClient(
        SymfonyHttpClient::create(['max_duration' => 5])
    );
    $uid = uniqid();
    $req = Psr17FactoryDiscovery::findRequestFactory()
        ->createRequest('POST', 'http://www.httpbin.org/post')
        ->withHeader('Content-Type', 'application/json')
        ->withBody(Psr17FactoryDiscovery::findStreamFactory()->createStream(json_encode(['key' => $uid])));

    $res = (new PluginClient($httpClient))->sendAsyncRequest($req)->wait();

    $json = $res->getBody()->getContents();
    Assert::notEmpty($json);
    $data_1 = json_decode($json);
    $data_2 = json_decode($data_1->data);
    Assert::eq($data_2->key, $uid);
    echo 'Done' . PHP_EOL;
});

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
?>
--EXPECT--
Done
