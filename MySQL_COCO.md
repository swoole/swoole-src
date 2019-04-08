MySQL ORM User Guide
===

## Catalogue
  - Create test table
  - Start Coroutine MySQL
  - Native SQL query
  - Error Info
  - Where statement
  - Select statement
  - Insert statement
  - Replace statement
  - Update statement
  - Delete statement
  - Whole Example
  - Database Transaction
  - PHP Database Connection Pool

## Create test table
```sql
CREATE TABLE `user_info_test` (
  `uid` int(11) NOT NULL COMMENT 'userid' AUTO_INCREMENT,
  `username` varchar(64) NOT NULL COMMENT 'username',
  `sexuality` varchar(8) DEFAULT 'male' COMMENT 'sexuality：male - 男性  female - 女性',
  `age` int(11) DEFAULT 0 COMMENT 'age',
  `height` double(11,2) DEFAULT 0 COMMENT 'height of a person, 身高',
  `bool_flag` int(11) DEFAULT 1 COMMENT 'flag',
  `remark` varchar(11) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='userinfo';
```

## Start ycdatabase
- new Swoole\Coroutine\MySQL();

```php
$mysql = new Swoole\Coroutine\MySQL();
$options = array();
$options['host'] = '127.0.0.1';
$options['port'] = 3306;
$options['user'] = 'root';
$options['password'] = 'hao123123';
$options['database'] = 'user';
$ret = $mysql->connect($options);
```

## Native SQL query
- insert data
```php
$ret = $mysql->query("insert into user_info_test(username, sexuality, age, height) 
			values('smallhow', 'male', 29, 180)");

if ($ret === false) {
  echo $mysql->errno . "\n";
  echo $mysql->error . "\n";
} else {
  echo $mysql->insert_id . "\n";
}
```

- update data

```php
$ret = $mysql->query("update user_info_test set remark='test' where height>=180");

if ($ret === false) {
  echo $mysql->errno . "\n";
  echo $mysql->error . "\n";
}
```

- select data
```php
$ret = $mysql->query("select * from user_info_test where bool_flag=1");
		
if ($ret === false) {
  echo $mysql->errno . "\n";
  echo $mysql->error . "\n";
} else {
  var_dump($ret);
}
```

## Error Info

Error codes and error messages can be obtained through the errno and error params<br>

```php
$code = $mysql->errno;
$info = $mysql->error;
```

## Where statement
- Basic usage
```php
//sql_stat is an array, 
//sql_stat['sql'] : SELECT * FROM `user_info_test` WHERE `sexuality` = ?
//sql_stat['bind_value'] : array("male")

$sql_stat = $mysql->select("user_info_test", "*", ["sexuality" => "male"]);
if ($sql_stat !== false) {
  $stmt = $mysql->prepare($sql_stat['sql']);
  $ret = $stmt->execute($sql_stat['bind_value']);
}


$mysql->select("user_info_test", "*", ["age" => 29]);  // WHERE age = 29

$mysql->select("user_info_test", "*", ["age[>]" => 29]); // WHERE age > 29

$mysql->select("user_info_test", "*", ["age[>=]" => 29]); // WHERE age >= 29

$mysql->select("user_info_test", "*", ["age[!]" => 29]); // WHERE age != 29

$mysql->select("user_info_test", "*", ["age[<>]" => [28, 29]]); // WHERE age  BETWEEN 28 AND 29

$mysql->select("user_info_test", "*", ["age[><]" => [28, 29]]); // WHERE age NOT BETWEEN 28 AND 29

$mysql->select("user_info_test", "*", ["username" => ["Tom", "Red", "carlo"]]); // WHERE username in ('Tom', 'Red', 'carlo')

//Multiple conditional query
$mysql->select("user_info_test", "*", [
    "uid[!]" => 10,
    "username[!]" => "James",
    "height[!]" => [165, 168, 172],
    "bool_flag" => true,
    "remark[!]" => null
]);
// WHERE uid != 10 AND username != "James" AND height NOT IN ( 165, 168, 172) AND bool_flag = 1 AND remark IS NOT NULL
```

- Conditional Query

You can use "AND" or "OR" to make up very complex SQL statements.
```php
$mysql->select("user_info_test", "*", [
  "OR" => [
    "uid[>]" => 3,
    "age[<>]" => [28, 29],
    "sexuality" => "female"
  ]
]);
// WHERE uid > 3 OR age BETWEEN 29 AND 29 OR sexuality = 'female'

$mysql->select("user_info_test", "*", [
  "AND" => [
    "OR" => [
      "age" => 29,
      "sexuality" => "female"
    ],
    "height" => 177
  ]
]);
// WHERE (age = 29 OR sexuality='female') AND height = 177

//Attention： Because mysql uses array arguments, the first OR is overwritten, the following usage is wrong, 
$mysql->select("user_info_test", "*", [
  "AND" => [
    "OR" => [
      "age" => 29,
      "sexuality" => "female"
    ],
    "OR" => [
      "uid[!]" => 3,
      "height[>=]" => 170
    ],
  ]
]);
// [X] SELECT * FROM user_info_test WHERE (uid != 3 OR height >= 170)

//We can use # and comments to distinguish between two diffrents OR
$mysql->select("user_info_test", "*", [
  "AND" => [
    "OR #1" => [
      "age" => 29,
      "sexuality" => "female"
    ],
    "OR #2" => [
      "uid[!]" => 3,
      "height[>=]" => 170
    ],
  ]
]);
// [√] SELECT * FROM user_info_test WHERE (age = 29 OR sexuality = 'female') AND (uid != 3 OR height >= 170)
```
- Fuzzy Matching _Like_

LIKE USAGE [~].
```php
$mysql->select("user_info_test", "*", [ "username[~]" => "%ide%" ]);
// WHERE username LIKE '%ide%'

$mysql->select("user_info_test", "*", ["username[~]" => ["%ide%", "Jam%", "%ace"]]);
// WHERE username LIKE '%ide%' OR username LIKE 'Jam%' OR username LIKE '%ace'

$mysql->select("user_info_test", "*", [ "username[!~]" => "%ide%" ]);
// WHERE username NOT LIKE '%ide%'
```

- Use of wildcards 
```php
$mysql->select("user_info_test", "*", [ "username[~]" => "Londo_" ]); // London, Londox, Londos...

$mysql->select("user_info_test", "id", [ "username[~]" => "[BCR]at" ]); // Bat, Cat, Rat

$mysql->select("user_info_test", "id", [	"username[~]" => "[!BCR]at" ]); // Eat, Fat, Hat...
```

- ORDER BY And LIMIT
```php
$mysql->select("user_info_test", "*", [
  'sexuality' => 'male',
  'ORDER' => [
    "age",
    "height" => "DESC",
    "uid" => "ASC"
  ],
  'LIMIT' => 100,  //Get the first 100 of rows (overwritten by next LIMIT)
  'LIMIT' => [20, 100]  //Started from the top 20 rows, and get the next 100
]);
//SELECT * FROM `user_info_test` WHERE `sexuality` = 'male' ORDER BY `age`, `height` DESC, `uid` ASC LIMIT 100 OFFSET 20
```

- GROUP And HAVING
```php
$mysql->select("user_info_test", "sexuality,age,height", [
  'GROUP' => 'sexuality',
 
  // GROUP by array of values
  'GROUP' => [
    'sexuality',
    'age',
    'height'
  ],
 
  // Must have to use it with GROUP together
  'HAVING' => [
    'age[>]' => 30
  ]
]);
//SELECT uid FROM `user_info_test` GROUP BY sexuality,age,height HAVING `age` > 30
```

## Select statement
- usage

```php
select($table, $columns, $where) 
```

#### table [string]
> table name

#### columns [string/array]
> Columns to be queried.

#### where (optional) [array]
> The conditions of the query.

```php
select($table, $join, $columns, $where) 
```
#### table [string]
> table name

#### join [array]
> Multi-table query, can be ignored if not used.

#### columns [string/array]
> Columns to be queried.

#### where (optional) [array]
> The conditions of the query.

#### return: [array]
>Fail if false is returned, otherwise an array with select sql and bind value.
<br>

- example

You can use * to match all fields, but if you specify columns you can improve performance.<br>
```php
$sql_stat = $mysql->select("user_info_test", ["uid", "username"], ["age[>]" => 31]);

var_dump($sql_stat);

if ($sql_stat !== false) {
  $stmt = $mysql->prepare($sql_stat['sql']);
  $ret = $stmt->execute($sql_stat['bind_value']);
}

// $ret = array(
//  [0] => array(
//      "uid" => 6,
//      "username" => "Aiden"
//  ),
//  [1] => array(
//      "uid" => 11,
//      "username" => "smallhow"
//  )
// )

// Select all columns
$mysql->select("user_info_test", "*");
```
<br>

- Table join

Multi-table query SQL is more complicated, and it can be easily solved with mysql.<br>

```php
// [>] == RIGH JOIN
// [<] == LEFT JOIN
// [<>] == FULL JOIN
// [><] == INNER JOIN

$mysql->select("user_info_test",
[ // Table Join Info
  "[>]account" => ["uid" => "userid"], // RIGHT JOIN `account` ON `user_info_test`.`uid`= `account`.`userid`
 
  // This is a shortcut to declare the relativity if the row name are the same in both table.
  "[>]album" => "uid", //RIGHT JOIN `album` USING (`uid`) 
  
  // Like above, there are two row or more are the same in both table.
  "[<]detail" => ["uid", "age"], // LEFT JOIN `detail` USING (`uid`,`age`)
 
  // You have to assign the table with alias.
  "[<]address(addr_alias)" => ["uid" => "userid"], //LEFT JOIN `address` AS `addr_alias` ON `user_info_test`.`uid`=`addr_alias`.`userid`
 
  // You can refer the previous joined table by adding the table name before the column.
  "[<>]album" => ["account.userid" => "userid"], //FULL JOIN `album` ON  `account`.`userid` = `album`.`userid`
 
  // Multiple condition
  "[><]account" => [
    "uid" => "userid",
    "album.userid" => "userid"
  ]
], [ // columns
  "user_info_test.uid",
  "user_info_test.age",
  "addr_alias.country",
  "addr_alias.city"
], [ // where condition
  "user_info_test.uid[>]" => 3,
  "ORDER" => ["user_info_test.uid" => "DESC"],
  "LIMIT" => 50
]);


// SELECT 
//   user_info_test.uid,
//   user_info_test.age,
//   addr_alias.country,
//   addr_alias.city 
// FROM `user_info_test` 
// RIGHT JOIN `account` ON `user_info_test`.`uid`= `account`.`userid`  
// RIGHT JOIN `album` USING (`uid`) 
// LEFT JOIN `detail` USING (`uid`,`age`) 
// LEFT JOIN `address` AS `addr_alias` ON `user_info_test`.`uid`=`addr_alias`.`userid` 
// FULL JOIN `album` ON  `account`.`userid` = `album`.`userid` 
// INNER JOIN `account` ON `user_info_test`.`uid`= `account`.`userid` 
//   AND `album`.`userid` = `account`.`userid`  
// WHERE `user_info_test`.`uid` > 3 
// ORDER BY  `user_info_test`.`uid` DESC 
// LIMIT 50
```

- alias

You can use aliases to prevent field conflicts<br>

```php
$data = $mysql->select("user_info_test(uinfo)", [
  "[<]account(A)" => "userid",
], [
  "uinfo.uid(uid)",
  "A.userid"
]);

// SELECT uinfo.uid AS `uid`, A.userid 
// FROM `user_info_test` AS `uinfo` 
// LEFT JOIN `account` AS `A` USING (`userid`)
```

## Insert statement

```php
insert($table, $data)
```
#### table [string]
> table name

#### data [array]
> insert data

#### return [int]
>Fail if false is returned, otherwise an array with select sql.<br>
 
```php
$data = array('username' => 'smallhow','sexuality' => 'male','age' => 35, 'height' => '168');
$sql_stat = $mysql->insert("user_info_test", $data);
		
if ($sql_stat !== false) {
  $ret = $mysql->query($sql_stat['sql']);
  if($ret === false) {
    echo $mysql->errno . "\n";
    echo $mysql->error . "\n";
  } else {
    echo $mysql->insert_id . "\n";
  }
}

```

## Replace statement

```php
replace($table, $data)
```
#### table [string]
> table name

#### data [array]
> replace data

#### return [int]
>Fail if false is returned, otherwise an array with select sql.<br>
 
```php
$data = array('uid' => 35, 'username' => 'smallhow','sexuality' => 'male','age' => 35, 'height' => '168');
$sql_stat = $mysql->replace("user_info_test", $data);

if ($sql_stat !== false) {
  $ret = $mysql->query($sql_stat['sql']);
  if($ret === false) {
    echo $mysql->errno . "\n";
    echo $mysql->error . "\n";
  }
}

```

## Update statement

```php
update($table, $data, $where)
```
#### table [string]
> table name

#### data [array]
> update data

#### where (optional) [array]
> where condition [可选]

#### return [int]
>Fail if false is returned, otherwise an array with select sql and bind value.<br>

```php
$data = array('height' => 185,'age' => 32);
$where = array('username' => 'smallhow');
$sql_stat = $mysql->update("user_info_test", $data, $where);

if ($sql_stat !== false) {
  $stmt = $mysql->prepare($sql_stat['sql']);
  if($stmt === false) {
    echo $mysql->errno . "\n";
    echo $mysql->error . "\n";
  } else {
    $ret = $stmt->execute($sql_stat['bind_value']);
  }
}
```

## Delete statement

```php
delete($table, $where)
```
#### table [string]
> table name

#### where (optional) [array]
> where condition [可选]

#### return [int]
>Fail if false is returned, otherwise an array with select sql and bind value.<br>

```php
$where = array('username' => 'smallhow');
$sql_stat = $mysql->delete("user_info_test", $where);

if ($sql_stat !== false) {
  $stmt = $mysql->prepare($sql_stat['sql']);
  if($stmt === false) {
    echo $mysql->errno . "\n";
    echo $mysql->error . "\n";
  } else {
    $ret = $stmt->execute($sql_stat['bind_value']);
  }
}
```

## Whole Example

```php
$table = "table_a(a)";

$join = [
  "[>]AAAA(a1)" => "id",
  "[<]BBBB" => ["E1", "E2", "E3"],
  "[>]CCCC(c1)" => [ "GG" => "HH", "II.KK" => "LL"]
];

$columns = ["name(a)", "avatar(b)", "age"];

$where =  [
  "user.email[!]" => ["foo@bar.com", "cat@dog.com", "admin@mysql.in"],
  "user.uid[<]" => 11111,
  "uid[>=]" => 222,
  "uid[!]" => null,
  "count[!]" => [36, 57, 89],
  "id[!]" => true,
  "int_num[!]" => 3,
  "double_num[!]" => 3.76,
  "AA[~]" => "%saa%",
  "BB[!~]" => "%sbb",
  "CC[~]" => ["11%", "22_", "33%"],
  "DD[!~]" => ["%44%", "55%", "66%"],
  "EE[~]" => ["AND" => ["%E11", "E22"]],
  "FF[~]" => ["OR" => ["%F33", "F44"]],
  "GG[!~]" => ["AND" => ["%G55", "G66"]],
  "HH[!~]" => ["OR" => ["H77", "H88"]],
  "II[<>]" => ["1", "12"],
  "LL[><]" => ["1", "12"],
    "AND #1" => [
        "OR #1" => [
          "user_name" => null,
          "email" => "foo@bar.com",
        ],
        "OR #2" => [
          "user_name" => "bar",
          "email" => "bar@foo.com"
        ]
    ],
    "OR" => [
        "user_name[!]" => "foo",
        "promoted[!]" => true
    ],
    'GROUP' => 'userid',
    'GROUP' => ['type', 'age', 'gender'],
    'HAVING' => [
        "uid.num[>]" => 111,
        "type[>]" => "smart",
        "id[!]" => false,
        "god3[!]" => 9.86,
        "uid[!]" => null,
        "AA[~]" => "SSA%",
        "CC[~]" => ["11%", "22%", "%33"],
    ],
    'ORDER' => [
        "user.score",
        "user.uid" => "ASC",
        "time" => "DESC",
    ],
    "LIMIT" => 33,
];

$mysql->select($table, $join, $columns, $where);
```

## Database transaction

```php
$mysql->begin();

$ret1 = $mysql->exec("insert into user_info_test(username, sexuality, age, height) values('smallhow', 'male', 29, 180)");
$ret2 = $mysql->exec("insert into user_info_test(username, sexuality, age, height) values('jesson', 'female', 28, 175)");

if($ret1 == -1 || $ret2 == -1 ) {
  $mysql->rollback();
} else {
  $mysql->commit()
}
```

## PHP Database Connection Pool

Short connection performance is generally not available. CPU resources are consumed by the system. Once the network is jittered, there will be a large number of TIME_WAIT generated. The service has to be restarted periodically or the machine is restarted periodically. The server is unstable, QPS is high and low, and the connection is stable and efficient. The pool can effectively solve the above problems, it is the basis of high concurrency. mysql uses a special way to establish a stable connection pool with MySQL. performance can be increased by at least 30%, According to PHP's operating mechanism, long connections can only reside on top of the worker process after establishment, that is, how many work processes are there. How many long connections, for example, we have 10 PHP servers, each launching 1000 PHP-FPM worker processes, they connect to the same MySQL instance, then there will be a maximum of 10,000 long connections on this MySQL instance, the number is completely Out of control! And PHP's connection pool heartbeat mechanism is not perfect<br><br>


### How ?
Let's focus on Nginx, its stream module implements load balancing of TCP/UDP services, and with the stream-lua module, we can implement programmable stream services, that is, custom TCP/N with Nginx. UDP service! Of course, you can write TCP/UDP services from scratch, but standing on Nginx's shoulder is a more time-saving and labor-saving choice. We can choose the OpenResty library to complete the MySQL connection pool function. OpenResty is a very powerful and well-functioning Nginx Lua framework. It encapsulates Socket, MySQL, Redis, Memcache, etc. But what is the relationship between Nginx and PHP connection pool? And listen to me slowly: Usually most PHP is used with Nginx, and PHP and Nginx are mostly on the same server. With this objective condition, we can use Nginx to implement a connection pool, connect to services such as MySQL on Nginx, and then connect to Nginx through a local Unix Domain Socket, thus avoiding all kinds of short links. Disadvantages, but also enjoy the benefits of the connection pool.

### OpenResty Install
OpenResty Document: https://moonbingbing.gitbooks.io/openresty-best-practices/content/openresty/install_on_centos.html
OpenResty Official Website : http://www.openresty.org/

CentOS 6.8 Install :
```
###### Install the necessary libraries ######
$yum install readline-devel pcre-devel openssl-devel perl

###### Install OpenResty ######
$cd ~/ycdatabase/openresty
$tar -xzvf openresty-1.13.6.1.tar.gz
$cd openresty-1.13.6.1
$./configure --prefix=/usr/local/openresty.1.13 --with-luajit --without-http_redis2_module --with-http_iconv_module
$gmake 
$gmake install

###### open mysql pool ######
$cp -rf ~/ycdatabase/openresty/openresty-pool ~/
$mkdir ~/openresty-pool/logs
$/usr/local/openresty.1.13/nginx/sbin/nginx -p ~/openresty-pool
```

### MySQL Database Connection Pool Config
~/openresty-pool/conf/nginx.conf  :

```lua
worker_processes  1;        #nginx worker process num

error_log logs/error.log;   #nginx error log path

events {
    worker_connections 1024;
}

stream {
  lua_code_cache on;

  lua_check_client_abort on;
  
  server {
    listen unix:/tmp/mysql_pool.sock;
		
    content_by_lua_block {
      local mysql_pool = require "mysql_pool"
			
      local config = {host = "127.0.0.1", 
                      user = "root", 
                      password = "test", 
                      database = "collect", 
                      timeout = 2000, 
                      max_idle_timeout = 10000, 
                      pool_size = 200}
						   
      pool = mysql_pool:new(config)
			
      pool:run()
    }
  }
}
```
If you have more than a MySQL Server, you can start another server and add a new listener to unix domain socket.<br>


### PHP Code
Except the option is array("unix_socket" => "/tmp/mysql_pool.sock") , Php mysql connection pool usage is exactly the same as before,But, MySQL does not support transactions in unix domain socket mode.<br>


```php
$option = array("unix_socket" => "/tmp/mysql_pool.sock");
$mysql = new mysql($option);
$ret = $mysql->select("user_info_test", "*", ["sexuality" => "male"]);

if($ret == -1) {
  $code = $mysql->errorCode();
  $info = $mysql->errorInfo();
  echo "code:" . $code . "\n";
  echo "info:" . $info[2] . "\n";
} else {
  print_r($ret);
}
```
