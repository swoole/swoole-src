# Coroutine\PostgreSQL

协程`PostgreSQL`客户端。需要编译 [ext-postgresql](https://github.com/swoole/ext-postgresql) 扩展来开启此功能。

## 编译安装

下载源代码：[https://github.com/swoole/ext-postgresql](https://github.com/swoole/ext-postgresql)，必须安装和 Swoole 版本相对应的 releases 版本。

* 需要确保系统中已安装`libpq`库
* `mac`安装完`postgresql`自带`libpq`库，环境之间有差异，`ubuntu`可能需要`apt-get install libpq-dev`，`centos`可能需要`yum install postgresql10-devel`
* 也可以单独指定`libpq`库目录，如：`./configure --with-libpq-dir=/etc/postgresql`

## 使用示例

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=root password=");
    if (!$conn) {
        var_dump($pg->error);
        return;
    }
    $result = $pg->query('SELECT * FROM test;');
    $arr = $pg->fetchAll($result);
    var_dump($arr);
});
```

### 事务处理

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=root password=");
    $pg->query('BEGIN');
    $result = $pg->query('SELECT * FROM test');
    $arr = $pg->fetchAll($result);
    $pg->query('COMMIT');
    var_dump($arr);
});
```

## 属性

### error

获取错误信息。

## 方法

### connect()

建立`postgresql`非阻塞的协程连接。

```php
Swoole\Coroutine\PostgreSQL->connect(string $connection_string): bool
```

!> `$connection_string` 为连接信息，连接成功返回true，连接失败返回false，可以使用[error](/coroutine_client/postgresql?id=error)属性获取错误信息。
  * **示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu password=");
    var_dump($pg->error, $conn);
});
```

### query()

执行SQL语句。发送异步非阻塞协程命令。

```php
Swoole\Coroutine\PostgreSQL->query(string $sql): resource;
```

  * **参数** 

    * **`string $sql`**
      * **功能**：SQL语句
      * **默认值**：无
      * **其它值**：无

  * **示例**

    * **select**

    ```php
    use Swoole\Coroutine\PostgreSQL;
    use function Swoole\Coroutine\run;

    run(function () {
        $pg = new PostgreSQL();
        $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=root password=");
        $result = $pg->query('SELECT * FROM test;');
        $arr = $pg->fetchAll($result);
        var_dump($arr);
    });
    ```

    * **返回insert id**

    ```php
    use Swoole\Coroutine\PostgreSQL;
    use function Swoole\Coroutine\run;

    run(function () {
        $pg = new PostgreSQL();
        $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu password=");
        $result = $pg->query("insert into test (id,text) VALUES (24,'text') RETURNING id ;");
        $arr = $pg->fetchRow($result);
        var_dump($arr);
    });
    ```

    * **transaction**

    ```php
    use Swoole\Coroutine\PostgreSQL;
    use function Swoole\Coroutine\run;

    run(function () {
        $pg = new PostgreSQL();
        $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=root password=");
        $pg->query('BEGIN;');
        $result = $pg->query('SELECT * FROM test;');
        $arr = $pg->fetchAll($result);
        $pg->query('COMMIT;');
        var_dump($arr);
    });
    ```

### fetchAll()

```php
Swoole\Coroutine\PostgreSQL->fetchAll(resource $queryResult, $resultType = SW_PGSQL_ASSOC):? array;
```

  * **参数**
    * **`$resultType`**
      * **功能**：常量。可选参数，控制着怎样初始化返回值。
      * **默认值**：`SW_PGSQL_ASSOC`
      * **其它值**：无

      取值 | 返回值
      ---|---
      SW_PGSQL_ASSOC | 返回用字段名作为键值索引的关联数组
      SW_PGSQL_NUM | 返回用字段编号作为键值
      SW_PGSQL_BOTH | 返回同时用两者作为键值

  * **返回值**

    * 提取结果中所有行作为一个数组返回。

### affectedRows()

返回受影响的记录数目。 

```php
Swoole\Coroutine\PostgreSQL->affectedRows(resource $queryResult): int
```

### numRows()

返回行的数目。

```php
Swoole\Coroutine\PostgreSQL->numRows(resource $queryResult): int
```

### fetchObject()

提取一行作为对象。 

```php
Swoole\Coroutine\PostgreSQL->fetchObject(resource $queryResult, int $row): object;
```

  * **示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu");
    $result = $pg->query('SELECT * FROM test;');
    
    $row = 0;
    for ($row = 0; $row < $pg->numRows($result); $row++) {
        $data = $pg->fetchObject($result, $row);
        echo $data->id . " \n ";
    }
});
```
```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu");
    $result = $pg->query('SELECT * FROM test;');
    
    $row = 0;
    while ($data = $pg->fetchObject($result, $row)) {
        echo $data->id . " \n ";
        $row++;
    }
});
```

### fetchAssoc()

提取一行作为关联数组。

```php
Swoole\Coroutine\PostgreSQL->fetchAssoc(resource $queryResult, int $row): array
```

### fetchArray()

提取一行作为数组。

```php
Swoole\Coroutine\PostgreSQL->fetchArray(resource $queryResult, int $row, $resultType = SW_PGSQL_BOTH): array|false
```

  * **参数**
    * **`int $row`**
      * **功能**：`row` 是想要取得的行（记录）的编号。第一行为 `0`。
      * **默认值**：无
      * **其它值**：无
    * **`$resultType`**
      * **功能**：常量。可选参数，控制着怎样初始化返回值。
      * **默认值**：`SW_PGSQL_BOTH`
      * **其它值**：无

      取值 | 返回值
      ---|---
      SW_PGSQL_ASSOC | 返回用字段名作为键值索引的关联数组
      SW_PGSQL_NUM | 返回用字段编号作为键值
      SW_PGSQL_BOTH | 返回同时用两者作为键值

  * **返回值**

    * 返回一个与所提取的行（元组/记录）相一致的数组。如果没有更多行可供提取，则返回 `false`。

  * **使用示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu");
    $result = $pg->query('SELECT * FROM test;');
    $arr = $pg->fetchArray($result, 1, SW_PGSQL_ASSOC);
    var_dump($arr);
});
```

### fetchRow()

根据指定的 `result` 资源提取一行数据（记录）作为数组返回。每个得到的列依次存放在数组中，从偏移量 `0` 开始。

```php
Swoole\Coroutine\PostgreSQL->fetchRow(resource $queryResult, int $row, $resultType = SW_PGSQL_NUM): array|false
```

  * **参数**
    * **`int $row`**
      * **功能**：`row` 是想要取得的行（记录）的编号。第一行为 `0`。
      * **默认值**：无
      * **其它值**：无
    * **`$resultType`**
      * **功能**：常量。可选参数，控制着怎样初始化返回值。
      * **默认值**：`SW_PGSQL_NUM`
      * **其它值**：无

      取值 | 返回值
      ---|---
      SW_PGSQL_ASSOC | 返回用字段名作为键值索引的关联数组
      SW_PGSQL_NUM | 返回用字段编号作为键值
      SW_PGSQL_BOTH | 返回同时用两者作为键值

  * **返回值**

    * 返回的数组和提取的行相一致。如果没有更多行 `row` 可提取，则返回 `false`。

  * **使用示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu");
    $result = $pg->query('SELECT * FROM test;');
    while ($row = $pg->fetchRow($result)) {
        echo "name: $row[0]  mobile: $row[1]" . PHP_EOL;
    }
});
```

### metaData()

查看表的元数据。异步非阻塞协程版。

```php
Swoole\Coroutine\PostgreSQL->metaData(string $tableName): array
```
    
  * **使用示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu");
    $result = $pg->metaData('test');
    var_dump($result);
});
```

### prepare()

预处理。

```php
Swoole\Coroutine\PostgreSQL->prepare(string $name, string $sql);
Swoole\Coroutine\PostgreSQL->execute(string $name, array $bind);
```

  * **使用示例**

```php
use Swoole\Coroutine\PostgreSQL;
use function Swoole\Coroutine\run;

run(function () {
    $pg = new PostgreSQL();
    $conn = $pg->connect("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu password=112");
    $pg->prepare("my_query", "select * from  test where id > $1 and id < $2");
    $res = $pg->execute("my_query", array(1, 3));
    $arr = $pg->fetchAll($res);
    var_dump($arr);
});
```
