--TEST--
swoole_pdo_sqlite: Bug #66033 (Segmentation Fault when constructor of PDO statement throws an exception)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
class DBStatement extends PDOStatement {
    public $dbh;
    protected function __construct($dbh) {
        $this->dbh = $dbh;
        throw new Exception("Blah");
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $pdo = new PDO('sqlite::memory:', null, null);
    $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS, array('DBStatement',
        array($pdo)));
    $pdo->exec("CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        title TEXT,
        message TEXT,
        time INTEGER)");

    try {
        $pdoStatement = $pdo->query("select * from messages");
    } catch (Exception $e) {
        var_dump($e->getMessage());
    }
});
?>
--EXPECT--
string(4) "Blah"
