--TEST--
swoole_pdo_sqlite:ATTR_STATEMENT_CLASS with ctor_args)
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
class bar extends PDOStatement {
    private function __construct() {
    }
}

class foo extends PDO {
    public $statementClass = 'bar';
    function __construct($dsn, $username, $password, $driver_options = array()) {
        $driver_options[PDO::ATTR_ERRMODE] = PDO::ERRMODE_EXCEPTION;
        parent::__construct($dsn, $username, $password, $driver_options);

        $this->setAttribute(PDO::ATTR_STATEMENT_CLASS, array($this->statementClass, array($this)));
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new foo('sqlite::memory:', '', '');
    $stmt = $db->query('SELECT 1');
    var_dump($stmt);
});
?>
--EXPECTF--
object(bar)#%d (1) {
  ["queryString"]=>
  string(8) "SELECT 1"
}
