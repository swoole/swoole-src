--TEST--
swoole_pdo_oracle: repeated execute and closeCursor rebuild column buffers safely
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';

foreach ([0, SWOOLE_HOOK_PDO_ORACLE] as $flags) {
    Co::set(['hook_flags' => $flags]);
    Co\run(function () {
        $db = PdoOracleTest::create();
        $stmt = $db->prepare("SELECT 'A' AS id, 'B' AS val FROM dual UNION ALL SELECT 'C', 'D' FROM dual");
        $expected = [['A', 'B'], ['C', 'D']];
        for ($i = 0; $i < 3; $i++) {
            Assert::true($stmt->execute());
            Assert::same($stmt->fetchAll(PDO::FETCH_NUM), $expected);
            // Re-execution after exhausting a result must keep defines valid.
            Assert::true($stmt->execute());
            Assert::same($stmt->fetchAll(PDO::FETCH_NUM), $expected);
            // Also close an unfinished cursor, then rebuild its column buffers.
            Assert::true($stmt->execute());
            Assert::same($stmt->fetch(PDO::FETCH_NUM), $expected[0]);
            Assert::true($stmt->closeCursor());
        }
        Assert::true($stmt->execute());
        Assert::same($stmt->fetchAll(PDO::FETCH_NUM), $expected);
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
