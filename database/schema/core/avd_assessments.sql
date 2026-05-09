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

 Date: 09/05/2026 16:28:40
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for avd_assessments
-- ----------------------------
DROP TABLE IF EXISTS `avd_assessments`;
CREATE TABLE `avd_assessments`  (
  `assessment_id` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'Assessment ID',
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'CVE ID',
  `base_score` decimal(3, 1) NULL DEFAULT NULL COMMENT 'CVSS base score',
  `base_severity` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'CVSS severity',
  `exploitation_risk_score` decimal(4, 2) NULL DEFAULT 0.00 COMMENT 'Exploit risk score (KEV=2, else EPSS)',
  `exploitation_risk_source` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Exploit source (e.g. KEV, EPSS)',
  `exploitation_risk_external_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Exploit source ID',
  `exploitation_risk_source_url` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Exploit source URL',
  `kev_status` tinyint(1) NULL DEFAULT 0 COMMENT 'In KEV (1=yes, 0=no)',
  `epss_score` decimal(6, 5) NULL DEFAULT NULL COMMENT 'EPSS score',
  `epss_percentile` decimal(6, 5) NULL DEFAULT NULL COMMENT 'EPSS percentile',
  `au_signal_score` decimal(3, 1) NULL DEFAULT 0.0 COMMENT 'AU signal score',
  `au_signal_source` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'AU signal source',
  `au_signal_external_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'AU signal ID',
  `au_signal_source_url` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'AU signal URL',
  `au_signal_label` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'AU signal label',
  `final_score` decimal(4, 2) NULL DEFAULT NULL COMMENT 'Final score',
  `priority_level` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Priority (low/med/high/critical)',
  `assessed_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Created time',
  PRIMARY KEY (`assessment_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = 'AVD scoring records' ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
