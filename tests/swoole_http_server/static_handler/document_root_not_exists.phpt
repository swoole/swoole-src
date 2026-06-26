--TEST--
swoole_http_server/static_handler: document_root not exists
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$server = new Swoole\Http\Server('127.0.0.1', get_one_free_port(), SWOOLE_BASE);
$documentRoot = sys_get_temp_dir() . '/swoole-document-root-not-exists-' . getmypid();

Assert::false($server->set([
    'enable_static_handler' => true,
    'document_root' => $documentRoot,
]));

echo "DONE\n";
?>
--EXPECTF--
%sWARNING%sdocument_root%sdoes not exist%S
DONE
