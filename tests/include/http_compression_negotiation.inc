<?php

use SwooleTest\Assert;

function compression_negotiation_body(): string
{
    return str_repeat('compression negotiation ', 64);
}

function compression_negotiation_response($request, $response): void
{
    $vary = [
        'origin' => 'Origin',
        'encoding' => 'Origin, aCcEpT-EnCoDiNg',
        'star' => '*',
        'array' => ['Origin', 'Authorization'],
        'array-encoding' => ['Origin', 'Accept-Encoding'],
        'empty' => '',
    ];
    if (isset($vary[$request->get['vary'] ?? ''])) {
        $response->header('Vary', $vary[$request->get['vary']]);
    }
    $body = compression_negotiation_body();
    if (isset($request->get['custom'])) {
        $response->header('Content-Encoding', 'gzip');
        $body = gzencode($body);
    } elseif (isset($request->get['type'])) {
        $response->header('Content-Type', 'text/plain');
    } elseif (isset($request->get['small'])) {
        $body = 'small';
    }
    $response->end($body);
}

function compression_negotiation_test(int $port): void
{
    $preferred = defined('SWOOLE_HAVE_BROTLI') ? 'br' : 'gzip';
    $cases = [
        ['gzip;q=0', null],
        [null, null],
        ['', null],
        ['GZIP', 'gzip'],
        ['xgzip, deflate-extra', null],
        ['gzip;q=0.1, deflate;q=0.9', 'deflate'],
        ['gzip;q=0.9, deflate;q=0.1', 'gzip'],
        ['gzip;q=0, deflate;q=1.000', 'deflate'],
        ['gzip;q=0.001', 'gzip'],
        ['gzip;q=0.000', null],
        ['gzip;q=1.', 'gzip'],
        [" \tGZIP ;\tq=0.500 \t", 'gzip'],
        ['gzip;Q=1', 'gzip'],
        ['gzip;q=1.001', null],
        ['gzip;q=0.0001', null],
        ['gzip;q=invalid', null],
        ['gzip;q=', null],
        ['*;q=0', null],
        ['*;q=0.5', $preferred],
        ['gzip;q=0.1, *;q=0', 'gzip'],
        ['gzip;q=0, br;q=0, zstd;q=0, *;q=1', 'deflate'],
        ['gzip;q=0.5, identity;q=1', null],
        ['gzip;q=0.5, identity;q=0.1', 'gzip'],
    ];
    if (defined('SWOOLE_HAVE_BROTLI')) {
        $cases[] = ['br;q=0.1, gzip;q=0.9', 'gzip'];
        $cases[] = ['br;q=0.9, gzip;q=0.1', 'br'];
        $cases[] = ['gzip;q=1, br;q=1', 'br'];
    }
    if (defined('SWOOLE_HAVE_ZSTD')) {
        $cases[] = ['gzip;q=0.1, zstd;q=0.9', 'zstd'];
    }
    $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    $client->set(['timeout' => 3, 'http_compression' => false]);
    try {
        foreach ($cases as [$encoding, $expected]) {
            $client->setHeaders($encoding === null ? [] : ['Accept-Encoding' => $encoding]);
            Assert::true($client->get('/'));
            Assert::same($client->headers['content-encoding'] ?? null, $expected);
            Assert::same($client->body, compression_negotiation_body());
            Assert::same(strtolower($client->headers['vary']), 'accept-encoding');
        }
        foreach ([null, 'gzip'] as $encoding) {
            $client->setHeaders($encoding === null ? [] : ['Accept-Encoding' => $encoding]);
            foreach (['origin', 'encoding', 'star', 'array', 'array-encoding', 'empty'] as $vary) {
                Assert::true($client->get('/?vary=' . $vary));
                $tokens = array_map('trim', explode(',', strtolower(implode(',', (array) $client->headers['vary']))));
                if ($vary === 'star') {
                    Assert::same($tokens, ['*']);
                } else {
                    Assert::same(count(array_keys($tokens, 'accept-encoding')), 1);
                    if ($vary !== 'empty') {
                        Assert::true(in_array('origin', $tokens, true));
                    }
                    if ($vary === 'array') {
                        Assert::true(in_array('authorization', $tokens, true));
                    }
                }
                Assert::same($client->body, compression_negotiation_body());
            }
        }
        $client->setHeaders(['Accept-Encoding' => 'gzip']);
        foreach (['custom', 'type', 'small'] as $option) {
            Assert::true($client->get('/?' . $option . '=1'));
            Assert::false(isset($client->headers['vary']));
            Assert::same($client->body, $option === 'small' ? 'small' : compression_negotiation_body());
        }
    } finally {
        $client->close();
    }
}
