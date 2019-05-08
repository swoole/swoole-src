/*
 Navicat Premium Data Transfer

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 80011
 Source Host           : localhost:3306
 Source Schema         : test

 Target Server Type    : MySQL
 Target Server Version : 80011
 File Encoding         : 65001

 Date: 14/09/2018 16:13:17
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for ckl
-- ----------------------------
DROP TABLE IF EXISTS `ckl`;
CREATE TABLE `ckl` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain` varchar(128) NOT NULL,
  `path` varchar(128) NOT NULL,
  `name` varchar(32) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of ckl
-- ----------------------------
BEGIN;
INSERT INTO `ckl` VALUES (1, 'www.baidu.com', '/search', 'baidu');
INSERT INTO `ckl` VALUES (2, 'www.taobao.com', '/search', 'taobao');
INSERT INTO `ckl` VALUES (3, 'www.qq.com', '/search', 'qq');
COMMIT;

-- ----------------------------
-- Table structure for custom
-- ----------------------------
DROP TABLE IF EXISTS `custom`;
CREATE TABLE `custom` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `content` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for numbers
-- ----------------------------
DROP TABLE IF EXISTS `numbers`;
CREATE TABLE `numbers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tinyint` tinyint(4) NOT NULL,
  `utinyint` tinyint(255) unsigned NOT NULL,
  `smallint` smallint(6) NOT NULL,
  `usmallint` smallint(5) unsigned NOT NULL,
  `mediumint` mediumint(9) NOT NULL,
  `umediumint` mediumint(8) unsigned NOT NULL,
  `int` int(11) NOT NULL,
  `uint` int(10) unsigned NOT NULL,
  `bigint` bigint(20) NOT NULL,
  `ubigint` bigint(20) unsigned NOT NULL,
  `float` float NOT NULL,
  `double` double NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Records of numbers
-- ----------------------------
BEGIN;
INSERT INTO `numbers` VALUES (1, 127, 255, 32767, 65535, 8388607, 16777215, 2147483647, 4294967294, 9223372036854775807, 18446744073709551615, 1.23457, 1.2345678901234567);
INSERT INTO `numbers` VALUES (2, -128, 123, -32768, 12345, -8388608, 123456, -2147483648, 123456, -9223372036854775808, 123456, -1.23457, -1.2345678901234567);
INSERT INTO `numbers` VALUES (3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1.23, 1.23);
COMMIT;

-- ----------------------------
-- Table structure for userinfo
-- ----------------------------
DROP TABLE IF EXISTS `userinfo`;
CREATE TABLE `userinfo` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(40) NOT NULL,
  `level` int(11) NOT NULL,
  `passwd` varchar(40),
  `regtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `big_n` bigint(20) NOT NULL,
  `data` json NOT NULL,
  `lastlogin_ip` int(11) NOT NULL,
  `price` double NOT NULL,
  `mdate` date NOT NULL,
  `mtime` time NOT NULL,
  `mdatetime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `year` year(4) NOT NULL DEFAULT '1970',
  `int8_t` tinyint(11) NOT NULL,
  `mshort` smallint(6) NOT NULL,
  `mtext` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=144 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of userinfo
-- ----------------------------
BEGIN;
INSERT INTO `userinfo` VALUES (1, 'jack', 199, 'xuyou', '2015-01-02 02:00:00', 999000, 'null', 1270, 0.22, '1970-01-01', '21:52:33', '2018-04-17 04:16:20', 1989, 127, 32767, '');
INSERT INTO `userinfo` VALUES (2, 'jack', 0, 'xuyou', '2016-05-20 00:00:00', 0, '{\"a\": 123}', 0, 0, '1970-01-01', '00:00:00', '1970-01-01 01:03:00', 1999, 0, 0, NULL);
INSERT INTO `userinfo` VALUES (3, '韩天峰', 0, 'xuyou', '2016-05-20 19:08:47', 0, 'null', 0, 0, '1970-01-01', '00:00:00', '1970-01-01 00:00:00', 0000, 0, 0, '');
INSERT INTO `userinfo` VALUES (4, 'jack', 11, 'xuyou', '2016-05-20 19:17:33', 0, 'null', 0, 0, '1970-01-01', '00:00:00', '1970-01-01 00:00:00', 0000, 0, 0, NULL);
INSERT INTO `userinfo` VALUES (5, 'rango22', 0, '123456', '2016-07-19 13:31:37', 0, 'null', 0, 0, '1970-01-01', '00:00:00', '1970-01-01 00:00:00', 0000, 0, 0, '');
INSERT INTO `userinfo` VALUES (6, 'hello', 99, NULL, '2017-07-03 19:37:37', 19999991, 'null', 7775533, 256.33, '2017-12-13', '09:51:29', '1970-01-01 00:00:00', 2015, 127, 32321, '我们都是中国人，你很好吗？');
INSERT INTO `userinfo` VALUES (7, 'twosee', 0, NULL, '2017-07-03 19:37:49', 99999999, '{}', 0, 0, '1997-06-04', '01:02:03', '1997-06-04 04:05:06.0708', 0000, 0, 0, '');
INSERT INTO `userinfo` VALUES (8, 'hello', 99, '123456', '2018-04-09 15:48:00', 99999999, 'null', 0, 0, '1970-01-01', '00:00:00', '1970-01-01 00:00:00', 0000, 0, 0, NULL);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
