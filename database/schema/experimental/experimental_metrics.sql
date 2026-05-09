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

 Date: 09/05/2026 16:30:09
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for experimental_metrics
-- ----------------------------
DROP TABLE IF EXISTS `experimental_metrics`;
CREATE TABLE `experimental_metrics`  (
  `metric_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `scenario_year` int(11) NOT NULL,
  `subject_source` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `comparison_source` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `metric_name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `metric_value` decimal(18, 6) NOT NULL,
  `numerator_value` decimal(18, 6) NULL DEFAULT NULL,
  `denominator_value` decimal(18, 6) NULL DEFAULT NULL,
  `unit` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'ratio',
  `note` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL,
  `calculated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`metric_id`) USING BTREE,
  INDEX `idx_em_scenario_subject`(`scenario_year`, `subject_source`) USING BTREE,
  INDEX `idx_em_metric_name`(`metric_name`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3185 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
