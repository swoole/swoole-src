--TEST--
swoole_curl: each copied easy handle releases its state independently of shared options
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip_if_not_defined('SWOOLE_HOOK_NATIVE_CURL');
skip('file protocol not supported', !in_array('file', curl_version()['protocols'], true));
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use SwooleTest\Assert;

// Also run under Valgrind: leaked native Handle/easy_multi allocations are outside the Zend heap.
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () {
    $expected = file_get_contents(__FILE__);
    foreach ([false, true] as $performTransfer) {
        $source = curl_init('file://' . __FILE__);
        Assert::true(curl_setopt_array($source, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['X-Test: shared-options'],
        ]));
        for ($i = 0; $i < 16; $i++) {
            foreach ([curl_copy_handle($source), clone $source] as $copy) {
                if ($performTransfer) {
                    Assert::same(curl_exec($copy), $expected);
                }
                unset($copy);
            }
        }
        // The original keeps shared options alive while the temporary copies are destroyed.
        Assert::same(curl_exec($source), $expected);
        $survivor = clone $source;
        unset($source);
        // The same ownership rules apply when the original is destroyed first.
        Assert::same(curl_exec($survivor), $expected);
        unset($survivor);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
