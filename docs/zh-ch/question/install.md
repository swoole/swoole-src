# 安装问题

## 升级Swoole版本

可以使用pecl进行安装和升级

```shell
pecl upgrade swoole
```

也可以直接从github/gitee/pecl下载一个新版本，重新安装编译。

* 更新Swoole版本，不需要卸载或者删除旧版本Swoole，安装过程会覆盖旧版本
* Swoole编译安装后没有额外的文件，仅有一个swoole.so，如果是在其他机器编译好的二进制版本。直接互相覆盖swoole.so，即可实现版本切换  
* git clone拉取的代码，执行git pull更新代码后，务必要再次执行`phpize`、`./configure`、`make clean`、`make install`
* 也可以使用对应的docker去升级对应的Swoole版本

## 在phpinfo中有在php -m中没有

先确认CLI模式下是否有，命令行输入`php --ri swoole`

如果输出了Swoole的扩展信息就说明你安装成功了!

**99.999%的人在此步成功就可以直接使用swoole了**

不需要管`php -m`或者`phpinfo`网页打印出来是否有swoole

因为Swoole是运行在cli模式下的，在传统的fpm模式下功能十分有限

fpm模式下任何异步/协程等主要功能都**不可以使用**，99.999%的人都不能在fpm模式下得到想要的东西，却纠结为什么fpm模式下没有扩展信息

**先确定你是否真正理解了Swoole的运行模式，再继续追究安装信息问题！**

### 原因

编译安装完Swoole后，在`php-fpm/apache`的`phpinfo`页面中有，在命令行的`php -m`中没有，原因可能是`cli/php-fpm/apache`使用不同的php.ini配置

### 解决办法

1. 确认php.ini的位置 

在`cli`命令行下执行`php -i | grep php.ini`或者`php --ini`找到php.ini的绝对路径

`php-fpm/apache`则是查看`phpinfo`页面找到php.ini的绝对路径

2. 查看对应php.ini是否有`extension=swoole.so`

```shell
cat /path/to/php.ini | grep swoole.so
```

## pcre.h: No such file or directory

编译Swoole扩展出现

```bash
fatal error: pcre.h: No such file or directory
```

原因是缺少pcre，需要安装libpcre

### ubuntu/debian

```shell
sudo apt-get install libpcre3 libpcre3-dev
```
### centos/redhat

```shell
sudo yum install pcre-devel
```

### 其他Linux

到[PCRE官方网站](http://www.pcre.org/)下载源码包，编译安装`pcre`库。

安装好`PCRE`库后需要重新编译安装`swoole`，然后使用`php --ri swoole`查看`swoole`扩展相关信息中是否有`pcre => enabled`

## '__builtin_saddl_overflow' was not declared in this scope

 ```
error: '__builtin_saddl_overflow' was not declared in this scope
  if (UNEXPECTED(__builtin_saddl_overflow(Z_LVAL_P(op1), 1, &lresult))) {

note: in definition of macro 'UNEXPECTED'
 # define UNEXPECTED(condition) __builtin_expect(!!(condition), 0)
```

这是一个已知的问题。问题是CentOS上的默认gcc缺少必需的定义，即使在升级gcc之后，PECL也会找到旧的编译器。

要安装驱动程序，必须首先通过安装devtoolset集合来升级gcc，如下所示：

```shell
sudo yum install centos-release-scl
sudo yum install devtoolset-7
scl enable devtoolset-7 bash
```

## fatal error: 'openssl/ssl.h' file not found

请在编译时增加[--with-openssl-dir](/environment?id=通用参数)参数指定 openssl 库的路径

!> 使用[pecl](/environment?id=pecl)安装Swoole时，如果要开启openssl也可以增加[--with-openssl-dir](/environment?id=通用参数)参数，如：`enable openssl support? [no] : yes --with-openssl-dir=/opt/openssl/`

## make或make install无法执行或编译错误

NOTICE: PHP message: PHP Warning:  PHP Startup: swoole: Unable to initialize module  
Module compiled with module API=20090626  
PHP    compiled with module API=20121212  
These options need to match  
in Unknown on line 0  
   
PHP版本和编译时使用的`phpize`和`php-config`不对应，需要使用绝对路径来进行编译，以及使用绝对路径来执行PHP。

```shell
/usr/local/php-5.4.17/bin/phpize
./configure --with-php-config=/usr/local/php-5.4.17/bin/php-config

/usr/local/php-5.4.17/bin/php server.php
```

## 安装xdebug

```shell
git clone git@github.com:swoole/sdebug.git -b sdebug_2_9 --depth=1

cd sdebug

phpize
./configure
make clean
make
make install

#如果你的phpize、php-config等配置文件都是默认的，那么可以直接执行
./rebuild.sh
```

修改php.ini加载扩展，加入以下信息

```ini
zend_extension=xdebug.so

xdebug.remote_enable=1
xdebug.remote_autostart=1
xdebug.remote_host=localhost
xdebug.remote_port=8000
xdebug.idekey="xdebug"
```

查看是否加载成功

```shell
php --ri sdebug
```

## configure: error: C preprocessor "/lib/cpp" fails sanity check

安装时如果报错

```shell
configure: error: C preprocessor "/lib/cpp" fails sanity check
```

表示缺少必要的依赖库，可使用如下命令安装

```shell
yum install glibc-headers
yum install gcc-c++
```

## PHP7.4.11+编译新版本的Swoole时报错asm goto :id=asm_goto

在 MacOS 中使用PHP7.4.11+编译新版本的Swoole时，发现形如以下报错：

```shell
/usr/local/Cellar/php/7.4.12/include/php/Zend/zend_operators.h:523:10: error: 'asm goto' constructs are not supported yet
        __asm__ goto(
                ^
/usr/local/Cellar/php/7.4.12/include/php/Zend/zend_operators.h:586:10: error: 'asm goto' constructs are not supported yet
        __asm__ goto(
                ^
/usr/local/Cellar/php/7.4.12/include/php/Zend/zend_operators.h:656:10: error: 'asm goto' constructs are not supported yet
        __asm__ goto(
                ^
/usr/local/Cellar/php/7.4.12/include/php/Zend/zend_operators.h:766:10: error: 'asm goto' constructs are not supported yet
        __asm__ goto(
                ^
4 errors generated.
make: *** [ext-src/php_swoole.lo] Error 1
ERROR: `make' failed
```

解决方法：修改`/usr/local/Cellar/php/7.4.12/include/php/Zend/zend_operators.h`源码，注意修改为自己对应的头文件路径；

将`ZEND_USE_ASM_ARITHMETIC`修改成恒定为`0`，即保留下述代码中`else`的内容

```c
#if defined(HAVE_ASM_GOTO) && !__has_feature(memory_sanitizer)
# define ZEND_USE_ASM_ARITHMETIC 1
#else
# define ZEND_USE_ASM_ARITHMETIC 0
#endif
```

## fatal error: curl/curl.h: No such file or directory :id=libcurl

打开`--enable-swoole-curl`选项后，编译Swoole扩展出现

```bash
fatal error: curl/curl.h: No such file or directory
```

原因是缺少curl依赖，需要安装libcurl

### ubuntu/debian

```shell
sudo apt-get install libcurl4-openssl-dev
```
### centos/redhat

```shell
sudo yum install libcurl-devel
```

### alpine

```shell
apk add curl-dev
```

## fatal error: ares.h: No such file or directory :id=libcares

打开`--enable-cares`选项后，编译Swoole扩展出现

```bash
fatal error: ares.h: No such file or directory
```

原因是缺少 c-ares 依赖，需要安装 libcares

### ubuntu/debian

```shell
sudo apt-get install libc-ares-dev
```

### centos/redhat

```shell
sudo yum install c-ares-devel
```

### alpine

```shell
apk add c-ares-dev
```

### MacOs

```shell
brew install c-ares
```