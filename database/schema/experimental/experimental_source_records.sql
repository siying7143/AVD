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

 Date: 09/05/2026 16:30:16
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for experimental_source_records
-- ----------------------------
DROP TABLE IF EXISTS `experimental_source_records`;
CREATE TABLE `experimental_source_records`  (
  `source_name` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `source_record_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `cve_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `cve_year` int(11) NOT NULL,
  `published_date` datetime NULL DEFAULT NULL,
  `last_modified_date` datetime NULL DEFAULT NULL,
  `severity` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `base_score` decimal(5, 2) NULL DEFAULT NULL,
  `vendor_names` json NULL,
  `product_names` json NULL,
  `references_json` json NULL,
  `source_url` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `raw_payload_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL,
  `inserted_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`source_name`, `source_record_id`) USING BTREE,
  INDEX `idx_esr_source_cve`(`source_name`, `cve_id`) USING BTREE,
  INDEX `idx_esr_cve_year`(`cve_year`) USING BTREE,
  INDEX `idx_esr_published_date`(`published_date`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
