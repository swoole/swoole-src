--TEST--
swoole_curl: destroy a native CurlHandle without enabling the native hook
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
$handle = curl_init();
var_dump($handle instanceof CurlHandle);

$references = [$handle, 42];
unset($handle, $references);
gc_collect_cycles();

echo "DONE\n";
?>
--EXPECT--
bool(true)
DONE
