This code was copied from php-8.3.28. Starting from PHP 8.4,
this extension has been removed and migrated to https://pecl.php.net/package/pdo_oci.

However, the latest version available on PECL is 1.1.0,
which was released on August 21, 2024, whereas on May 6, 2025,
php-8.3.28 made modifications to pdo_oci
(see commit: https://github.com/php/php-src/commit/dcf9d8f812abb3854c802e4b831d82f9d7e5c26f).

- PECL Package: https://pecl.php.net/package/pdo_oci
- GitHub Repository: https://github.com/php/pecl-database-pdo_oci


## Merge pdo_oci into Swoole

```shell
git clone https://github.com/php/pecl-database-pdo_oci.git
meld soft/php/pecl-database-pdo_oci swoole-src/thirdparty/pdo_oci
```
