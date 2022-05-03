# Coroutine\MySQL

协程MySQL客户端。

!> 本客户端不再推荐使用，推荐使用 Swoole\Runtime::enableCoroutine + PDO或Mysqli 方式，即[一键协程化](/runtime)原生 PHP 的 MySQL 客户端。

!> 请勿同时使用`Swoole1.x`时代的异步回调写法和本协程MySQL客户端。

## 使用示例

```php
use Swoole\Coroutine\MySQL;
use function Swoole\Coroutine\run;

run(function () {
    $swoole_mysql = new MySQL();
    $swoole_mysql->connect([
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'user'     => 'user',
        'password' => 'pass',
        'database' => 'test',
    ]);
    $res = $swoole_mysql->query('select sleep(1)');
    var_dump($res);
});
```

## defer特性

请参考[并发Client](/coroutine/multi_call)一节。

## 存储过程

从`4.0.0`版本后, 支持`MySQL`存储过程和多结果集获取。

## MySQL8.0

`Swoole-4.0.1`或更高版本支持了`MySQL8`所有的安全验证能力, 可以直接正常使用客户端，而无需回退密码设定

### 4.0.1 以下版本

`MySQL-8.0`默认使用了安全性更强的`caching_sha2_password`插件, 如果是从`5.x`升级上来的, 可以直接使用所有`MySQL`功能, 如是新建的`MySQL`, 需要进入`MySQL`命令行执行以下操作来兼容:

```SQL
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';
flush privileges;
```

将语句中的 `'root'@'localhost'` 替换成你所使用的用户, `password` 替换成其密码.

如仍无法使用, 应在my.cnf中设置 `default_authentication_plugin = mysql_native_password`

## 属性

### serverInfo

连接信息，保存的是传递给连接函数的数组。

### sock

连接使用的文件描述符。

### connected

是否连接上了`MySQL`服务器。

!> 参考[connected 属性和连接状态不一致](/question/use?id=connected属性和连接状态不一致)

### connect_error

执行`connect`连接服务器时的错误信息。

### connect_errno

执行`connect`连接服务器时的错误码，类型为整型。

### error

执行`MySQL`指令时，服务器返回的错误信息。

### errno

执行`MySQL`指令时，服务器返回的错误码，类型为整型。

### affected_rows

影响的行数。

### insert_id

最后一个插入的记录`id`。

## 方法

### connect()

建立MySQL连接。

```php
Swoole\Coroutine\MySQL->connect(array $serverInfo): bool
```

!> `$serverInfo`：参数以数组形式传递

```php
[
    'host'        => 'MySQL IP地址', // 若是本地UNIXSocket则应以形如`unix://tmp/your_file.sock`的格式填写
    'user'        => '数据用户',
    'password'    => '数据库密码',
    'database'    => '数据库名',
    'port'        => 'MySQL端口 默认3306 可选参数',
    'timeout'     => '建立连接超时时间', // 仅影响connect超时时间，不影响query和execute方法,参考`客户端超时规则`
    'charset'     => '字符集',
    'strict_type' => false, //开启严格模式，query方法返回的数据也将转为强类型
    'fetch_mode'  => true,  //开启fetch模式, 可与pdo一样使用fetch/fetchAll逐行或获取全部结果集(4.0版本以上)
]
```

### query()

执行SQL语句。

```php
Swoole\Coroutine\MySQL->query(string $sql, float $timeout = 0): array|false
```

  * **参数** 

    * **`string $sql`**
      * **功能**：SQL语句
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：超时时间 【在规定的时间内`MySQL`服务器未能返回数据，底层将返回`false`，设置错误码为`110`，并切断连接】
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`0`
      * **其它值**：无
      * **参考[客户端超时规则](/coroutine_client/init?id=超时规则)**


  * **返回值**

    * 超时/出错返回`false`，否则 `array` 形式返回查询结果

  * **延迟接收**

  !> 设置`defer`后，调用`query`会直接返回`true`。调用`recv`才会进入协程等待，返回查询的结果。

  * **示例**

```php
use Swoole\Coroutine\MySQL;
use function Swoole\Coroutine\run;

run(function () {
    $swoole_mysql = new MySQL();
    $swoole_mysql->connect([
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'user'     => 'user',
        'password' => 'pass',
        'database' => 'test',
    ]);
    $res = $swoole_mysql->query('show tables');
    if ($res === false) {
        return;
    }
    var_dump($res);
});
```

### prepare()

向MySQL服务器发送SQL预处理请求。

!> `prepare`必须与`execute`配合使用。预处理请求成功后，调用`execute`方法向`MySQL`服务器发送数据参数。

```php
Swoole\Coroutine\MySQL->prepare(string $sql, float $timeout): Swoole\Coroutine\MySQL\Statement|false;
```

  * **参数** 

    * **`string $sql`**
      * **功能**：预处理语句【使用`?`作为参数占位符】
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：超时时间 
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`0`
      * **其它值**：无
      * **参考[客户端超时规则](/coroutine_client/init?id=超时规则)**


  * **返回值**

    * 失败返回`false`，可检查`$db->error`和`$db->errno`判断错误原因
    * 成功返回`Coroutine\MySQL\Statement`对象，可调用对象的[execute](/coroutine_client/mysql?id=statement-gtexecute)方法发送参数

  * **示例**

```php
use Swoole\Coroutine\MySQL;
use function Swoole\Coroutine\run;

run(function () {
    $db = new MySQL();
    $ret1 = $db->connect([
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'user'     => 'root',
        'password' => 'root',
        'database' => 'test',
    ]);
    $stmt = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    if ($stmt == false) {
        var_dump($db->errno, $db->error);
    } else {
        $ret2 = $stmt->execute(array(10));
        var_dump($ret2);
    }
});
```

### escape()

转义SQL语句中的特殊字符，避免SQL注入攻击。底层基于`mysqlnd`提供的函数实现，需要依赖`PHP`的`mysqlnd`扩展。

!> 编译时需要增加[--enable-mysqlnd](/environment?id=编译选项)来启用。

```php
Swoole\Coroutine\MySQL->escape(string $str): string
```

  * **参数** 

    * **`string $str`**
      * **功能**：转义字符
      * **默认值**：无
      * **其它值**：无

  * **使用示例**

```php
use Swoole\Coroutine\MySQL;
use function Swoole\Coroutine\run;

run(function () {
    $db = new MySQL();
    $db->connect([
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'user'     => 'root',
        'password' => 'root',
        'database' => 'test',
    ]);
    $data = $db->escape("abc'efg\r\n");
});
```

### begin()

开启事务。与`commit`和`rollback`结合实现`MySQL`事务处理。

```php
Swoole\Coroutine\MySQL->begin(): bool
```

!> 启动一个`MySQL`事务，成功返回`true`，失败返回`false`，请检查`$db->errno`获取错误码。
  
!> 同一个`MySQL`连接对象，同一时间只能启动一个事务；  
必须等到上一个事务`commit`或`rollback`才能继续启动新事务；  
否则底层会抛出`Swoole\MySQL\Exception`异常，异常`code`为`21`。

  * **示例**

    ```php
    $db->begin();
    $db->query("update userinfo set level = 22 where id = 1");
    $db->commit();
    ```

### commit()

提交事务。 

!> 必须与`begin`配合使用。

```php
Swoole\Coroutine\MySQL->commit(): bool
```

!> 成功返回`true`，失败返回`false`，请检查`$db->errno`获取错误码。

### rollback()

回滚事务。

!> 必须与`begin`配合使用。

```php
Swoole\Coroutine\MySQL->rollback(): bool
```

!> 成功返回`true`，失败返回`false`，请检查`$db->errno`获取错误码。

### Statement->execute()

向MySQL服务器发送SQL预处理数据参数。

!> `execute`必须与`prepare`配合使用，调用`execute`之前必须先调用`prepare`发起预处理请求。

!> `execute`方法可以重复调用。

```php
Swoole\Coroutine\MySQL\Statement->execute(array $params, float $timeout = -1): array|bool
```

  * **参数** 

    * **`array $params`**
      * **功能**：预处理数据参数 【必须与`prepare`语句的参数个数相同。`$params`必须为数字索引的数组，参数的顺序与`prepare`语句相同】
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：超时时间 【在规定的时间内`MySQL`服务器未能返回数据，底层将返回`false`，设置错误码为`110`，并切断连接】
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无
      * **参考[客户端超时规则](/coroutine_client/init?id=超时规则)**

  * **返回值** 

    * 成功时返回 `true`，如果设置 `connect` 的 `fetch_mode` 参数为 `true` 时
    * 成功时返回 `array` 数据集数组，如不是上述情况时，
    * 失败返回`false`，可检查`$db->error`和`$db->errno`判断错误原因

  * **使用示例** 

```php
use Swoole\Coroutine\MySQL;
use function Swoole\Coroutine\run;

run(function () {
    $db = new MySQL();
    $ret1 = $db->connect([
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'user'     => 'root',
        'password' => 'root',
        'database' => 'test',
    ]);
    $stmt = $db->prepare('SELECT * FROM userinfo WHERE id=? and name=?');
    if ($stmt == false) {
        var_dump($db->errno, $db->error);
    } else {
        $ret2 = $stmt->execute(array(10, 'rango'));
        var_dump($ret2);

        $ret3 = $stmt->execute(array(13, 'alvin'));
        var_dump($ret3);
    }
});
```

### Statement->fetch()

从结果集中获取下一行。

```php
Swoole\Coroutine\MySQL\Statement->fetch(): ?array
```

!> Swoole版本 >= `4.0-rc1`，需在`connect`时加入`fetch_mode => true`选项

  * **示例** 

```php
$stmt = $db->prepare('SELECT * FROM ckl LIMIT 1');
$stmt->execute();
while ($ret = $stmt->fetch()) {
    var_dump($ret);
}
```

!> 从`v4.4.0`的新`MySQL`驱动开始, `fetch`必须使用示例代码的方式读到`NULL`为止, 否则将无法发起新的请求 (由于底层按需读取机制, 可节省内存)

### Statement->fetchAll()

返回一个包含结果集中所有行的数组。

```php
Swoole\Coroutine\MySQL\Statement->fetchAll():? array
```

!> Swoole版本 >= `4.0-rc1`，需在`connect`时加入`fetch_mode => true`选项

  * **示例** 

```php
$stmt = $db->prepare('SELECT * FROM ckl LIMIT 1');
$stmt->execute();
$stmt->fetchAll();
```

### Statement->nextResult()

在一个多响应结果语句句柄中推进到下一个响应结果 (如存储过程的多结果返回)。

```php
Swoole\Coroutine\MySQL\Statement->nextResult():? bool
```

  * **返回值**

    * 成功时返回 `TRUE`
    * 失败时返回 `FALSE`
    * 无下一结果返回`NULL`

  * **示例** 

    * **非fetch模式**

    ```php
    $stmt = $db->prepare('CALL reply(?)');
    $res  = $stmt->execute(['hello mysql!']);
    do {
      var_dump($res);
    } while ($res = $stmt->nextResult());
    var_dump($stmt->affected_rows);
    ```

    * **fetch模式**

    ```php
    $stmt = $db->prepare('CALL reply(?)');
    $stmt->execute(['hello mysql!']);
    do {
      $res = $stmt->fetchAll();
      var_dump($res);
    } while ($stmt->nextResult());
    var_dump($stmt->affected_rows);
    ```

!> 从`v4.4.0`的新`MySQL`驱动开始, `fetch`必须使用示例代码的方式读到`NULL`为止, 否则将无法发起新的请求 (由于底层按需读取机制, 可节省内存)