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
    $req = Psr17FactoryDiscovery::findRequestFactory()
        ->createRequest('POST', 'http://www.qq.com')
        ->withHeader('Content-Type', 'application/json')
        ->withBody(Psr17FactoryDiscovery::findStreamFactory()->createStream('test'));

    $res = (new PluginClient($httpClient))->sendAsyncRequest($req)->wait();
    Assert::contains($res->getHeaders()['server'], 'nginx');
    echo 'Done' . PHP_EOL;
});

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
?>
--EXPECT--
Done
