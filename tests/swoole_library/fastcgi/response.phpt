--TEST--
swoole_library: FastCGI incremental CGI parsing and explicit record serialization
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!class_exists(Swoole\FastCGI\HttpResponse::class)) die('skip requires the bundled library');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\FastCGI\HttpResponse;
use Swoole\FastCGI\Record;
use Swoole\FastCGI\Record\EndRequest;
use Swoole\FastCGI\Record\Stdout;

$stdout = new Stdout("body\0\xff");
Assert::same(Record::unpack($stdout->toString())->getContentData(), "body\0\xff");
Assert::same($stdout->toString(), $stdout->__toString());

$records = (static function () use ($stdout) {
    yield new Stdout("Status: 201 Created\nContent-Type: text/plain\n");
    yield new Stdout("\n");
    yield $stdout;
    yield new EndRequest();
})();
$response = new HttpResponse($records);
Assert::same($response->getStatusCode(), 201);
Assert::same($response->getHeader('Content-Type'), 'text/plain');
Assert::same($response->getBody(), "body\0\xff");

$response = new HttpResponse([new Stdout("Location: https://example.com/target\r\n\r\n"), new EndRequest()]);
Assert::same($response->getStatusCode(), 302);
$response = new HttpResponse([new Stdout("Status: fish\r\n\r\nprivate body"), new EndRequest()]);
Assert::same($response->getStatusCode(), 502);
Assert::same($response->getBody(), '');

$params = new Record\Params(['a' => 'b']);
$params->setContentData('xyz');
Assert::same(strlen($params->toString()), 16);
Assert::same(Record::unpack($params->toString())->getContentData(), 'xyz');
echo "DONE\n";
?>
--EXPECT--
DONE
