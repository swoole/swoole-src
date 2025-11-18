--TEST--
swoole_pdo_firebird: test query
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

const N = 10;

Co::set(['hook_flags' => SWOOLE_HOOK_PDO_FIREBIRD]);
Co\run(static function (): void {
    $db = PdoFirebirdTest::create();

    // 准备测试表
    try {
        $db->exec('DROP TABLE concurrent_test');
        try {
            $db->exec('COMMIT');
        } catch (PDOException $e) {
            // 忽略COMMIT失败的错误
        }
    } catch (PDOException $e) {
        // 表不存在时的错误可以忽略
    }

    // 创建测试表
    $db->exec('CREATE TABLE concurrent_test (id INTEGER PRIMARY KEY, name VARCHAR(100), age INTEGER)');

    $stmt = $db->prepare('INSERT INTO concurrent_test (id, name, age) values (?, ?, ?)');

    $list = [];
    for ($i = 0; $i < N; $i++) {
        $id = $i + 1;
        $name = base64_encode(random_bytes(8));
        $age = random_int(18, 35);
        $stmt->bindValue(1, $id);
        $stmt->bindValue(2, $name);
        $stmt->bindValue(3, $age);
        $stmt->execute();

        $list[] = [
            'id' => $id,
            'name' => $name,
            'age' => $age
        ];
    }

    // 创建通道用于同步
    $channel = new Co\Channel(N);

    foreach ($list as $rs) {
        Co\go(function () use ($rs, $channel) {
            $db = PdoFirebirdTest::create();
            try {
                $statement = $db->query('SELECT * FROM concurrent_test WHERE id = ' . $rs['id'] . ' ROWS 1');
                $result = $statement->fetch(PDO::FETCH_ASSOC);
                Assert::eq($result['ID'], $rs['id']);
                Assert::eq($result['NAME'], $rs['name']);
                Assert::eq($result['AGE'], $rs['age']);
            } catch (PDOException $e) {
                echo "Error in coroutine: " . $e->getMessage() . "\n";
            }
            // 通知主协程当前协程已完成
            $channel->push(true);
        });
    }

    // 等待所有协程完成
    for ($i = 0; $i < N; $i++) {
        $channel->pop();
    }

    // 所有协程完成后再清理测试表
    try {
        $db->exec('DROP TABLE concurrent_test');
    } catch (PDOException $e) {
        // 忽略清理错误
    }
});

echo "Done\n";
?>
--EXPECTF--
Done
