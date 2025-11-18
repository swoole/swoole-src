--TEST--
swoole_pdo_firebird: test hook firebird sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/pdo_firebird.inc';
PdoFirebirdTest::skip();
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/pdo_firebird.inc';

const N = 20;

Co::set(['hook_flags' => SWOOLE_HOOK_PDO_FIREBIRD]);
Co\run(static function (): void {
    $sleep_count = 0;
    Co\go(function () use (&$sleep_count) {
        $n = N;
        while ($n--) {
            Co::sleep(0.002);
            $sleep_count++;
        }
    });

    $db = PdoFirebirdTest::create();

    $iterations = 50;
    for ($i = 0; $i < $iterations; $i++) {
        $statement = $db->query('SELECT COUNT(*) FROM RDB$RELATIONS');
        $statement->fetch();
    }

    Assert::greaterThanEq($sleep_count, 10);
});
echo "Done\n";
?>
--EXPECTF--
Done
