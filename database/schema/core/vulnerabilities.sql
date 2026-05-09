/*
 Navicat Premium Data Transfer

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 50744 (5.7.44)
 Source Host           : localhost:3306
 Source Schema         : avd

 Target Server Type    : MySQL
 Target Server Version : 50744 (5.7.44)
 File Encoding         : 65001

 Date: 09/05/2026 16:28:48
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for vulnerabilities
-- ----------------------------
DROP TABLE IF EXISTS `vulnerabilities`;
CREATE TABLE `vulnerabilities`  (
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'CVE identifier',
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'Official vulnerability description',
  `base_score` decimal(3, 1) NULL DEFAULT NULL COMMENT 'Original CVSS base score',
  `severity` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Original severity level',
  `vendors` json NULL COMMENT 'Affected vendor names',
  `product_names` json NULL COMMENT 'Affected product names',
  `cwe_ids` json NULL COMMENT 'Associated CWE identifiers',
  `published_date` datetime NULL DEFAULT NULL COMMENT 'Original publish date',
  `last_modified_date` datetime NULL DEFAULT NULL COMMENT 'Last modified date',
  PRIMARY KEY (`cve_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = 'Base vulnerability records from public vulnerability sources' ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
