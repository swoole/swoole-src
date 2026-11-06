--TEST--
swoole_curl/setopt: CURLOPT_READFUNCTION result and stream are released with the callback guard still set
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

function reset_handle(CurlHandle $handle, string $from): void
{
    try {
        curl_reset($handle);
        echo "{$from}: reset accepted\n";
    } catch (Error $e) {
        echo "{$from}: ", $e->getMessage(), PHP_EOL;
    }
}

class ResetOnDestruct
{
    public function __construct(private CurlHandle $handle)
    {
    }

    public function __destruct()
    {
        reset_handle($this->handle, '__destruct');
    }
}

class ResetOnClose
{
    public $context;

    public static CurlHandle $handle;

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        return true;
    }

    public function stream_close()
    {
        reset_handle(self::$handle, 'stream_close');
    }
}

stream_wrapper_register('reset-on-close', ResetOnClose::class);

function upload(string $host): CurlHandle
{
    $ch = curl_init("http://{$host}/get.php?test=input");
    curl_setopt($ch, CURLOPT_UPLOAD, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Expect:']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return $ch;
}

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    // The returned object is released after the callback returns.
    $ch = upload($host);
    curl_setopt($ch, CURLOPT_READFUNCTION, fn ($ch) => new ResetOnDestruct($ch));
    var_dump(curl_exec($ch));

    // Replacing CURLOPT_INFILE leaves the callback's stream argument holding the last reference to the old stream.
    $ch                   = upload($host);
    ResetOnClose::$handle = $ch;
    curl_setopt($ch, CURLOPT_INFILE, fopen('reset-on-close://', 'r'));
    curl_setopt($ch, CURLOPT_READFUNCTION, function ($ch) {
        curl_setopt($ch, CURLOPT_INFILE, fopen('php://memory', 'r'));
        return '';
    });
    var_dump(curl_exec($ch));
});
?>
--EXPECT--
__destruct: curl_reset(): Attempt to reset cURL handle from a callback
string(0) ""
stream_close: curl_reset(): Attempt to reset cURL handle from a callback
string(0) ""
