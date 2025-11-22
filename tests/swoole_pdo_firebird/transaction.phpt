--TEST--
swoole_pdo_firebird: test transaction
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

use function Swoole\Coroutine\run;

Co::set(['hook_flags' => SWOOLE_HOOK_PDO_FIREBIRD]);
run(static function (): void {
    $db = PdoFirebirdTest::create();

    // 先尝试删除可能存在的表（忽略错误）
    try {
        $db->exec('DROP TABLE transaction_test');
        // 使用try-catch包围COMMIT
        try {
            $db->exec('COMMIT');
        } catch (PDOException $e) {
            // 忽略COMMIT失败的错误
        }
    } catch (PDOException $e) {
        // 表不存在时的错误可以忽略
    }

    // 创建测试表 - 将value改为test_value以避免保留关键字冲突
    $db->exec('CREATE TABLE transaction_test (id INTEGER PRIMARY KEY, test_value VARCHAR(50))');

    try {
        // 开始事务
        $db->beginTransaction();

        // 插入数据 - 更新列名
        $db->exec("INSERT INTO transaction_test VALUES (1, 'Value 1')");
        $db->exec("INSERT INTO transaction_test VALUES (2, 'Value 2')");

        // 提交事务
        $db->commit();

        // 验证数据已插入
        $stmt = $db->query('SELECT COUNT(*) FROM transaction_test');
        $count = $stmt->fetchColumn();
        echo "Count after commit: ", $count, "\n";

        // 再次开始事务
        $db->beginTransaction();
        $db->exec("INSERT INTO transaction_test VALUES (3, 'Value 3')");

        // 回滚事务
        $db->rollback();

        // 验证回滚后的数据
        $stmt = $db->query('SELECT COUNT(*) FROM transaction_test');
        $count = $stmt->fetchColumn();
        echo "Count after rollback: ", $count, "\n";

    } catch (PDOException $e) {
        echo "Error: ", $e->getMessage(), "\n";
    }

    // 清理测试表
    try {
        $db->exec('DROP TABLE transaction_test');
    } catch (PDOException $e) {
        // 如果删除失败，尝试使用更安全的方式处理事务
        try {
            // 首先尝试回滚任何活动事务
            $db->rollBack();
        } catch (PDOException $e) {
            // 忽略回滚失败的错误
        }
        // 再次尝试删除表
        try {
            $db->exec('DROP TABLE transaction_test');
        } catch (PDOException $e) {
            // 忽略第二次删除失败的错误
        }
    }
});

echo "DONE\n";
?>
--EXPECT--
Count after commit: 2
Count after rollback: 2
DONE
