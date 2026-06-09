-- VulnScope 数据库初始化脚本
-- 兼容 MySQL 8.0+
-- 使用方法: mysql -u root -p < schema.sql

-- 创建数据库和用户
CREATE DATABASE IF NOT EXISTS scanner CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'scanner'@'localhost' IDENTIFIED BY 'scanner123';
GRANT ALL PRIVILEGES ON scanner.* TO 'scanner'@'localhost';
FLUSH PRIVILEGES;

USE scanner;

-- 扫描目标
CREATE TABLE IF NOT EXISTS `targets` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `target` varchar(255) NOT NULL COMMENT 'IP / 域名 / 网段',
  `type` varchar(32) NOT NULL COMMENT 'ip / domain / cidr',
  `group` varchar(255) DEFAULT NULL COMMENT '分组',
  `tags` varchar(1024) DEFAULT NULL COMMENT '标签, 逗号分隔',
  `memo` varchar(1024) DEFAULT NULL COMMENT '备注',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 扫描任务
CREATE TABLE IF NOT EXISTS `tasks` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL COMMENT '任务名称',
  `target_ids` text NOT NULL COMMENT '关联的目标ID, 逗号分隔',
  `type` int DEFAULT 0 COMMENT '0:常规, 1:复测',
  `status` varchar(32) DEFAULT 'pending' COMMENT 'pending/running/completed/failed',
  `progress` varchar(32) DEFAULT '' COMMENT '当前阶段: domain/alive/port/finger/vuln',
  `error` text COMMENT '错误信息',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 扫描产出的资产
CREATE TABLE IF NOT EXISTS `assets` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `task_id` bigint unsigned NOT NULL COMMENT '关联任务ID',
  `ip` varchar(64) DEFAULT NULL COMMENT 'IP地址',
  `domain` varchar(255) DEFAULT NULL COMMENT '域名',
  `alive` tinyint(1) DEFAULT 0 COMMENT '是否存活',
  `status_code` int DEFAULT NULL COMMENT 'HTTP状态码',
  `response_time` int DEFAULT NULL COMMENT '响应时间(ms)',
  `redirect_url` varchar(1024) DEFAULT NULL COMMENT '跳转URL',
  `title` varchar(512) DEFAULT NULL COMMENT '网页标题',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_assets_task_id` (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 端口信息
CREATE TABLE IF NOT EXISTS `ports` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` bigint unsigned NOT NULL COMMENT '关联资产ID',
  `port` int NOT NULL COMMENT '端口号',
  `protocol` varchar(16) DEFAULT NULL COMMENT 'tcp/udp',
  `service` varchar(64) DEFAULT NULL COMMENT 'http/ssh/mysql 等',
  `version` varchar(255) DEFAULT NULL COMMENT '服务版本',
  `cpe` varchar(255) DEFAULT NULL COMMENT 'CPE标识 (如 cpe:2.3:a:redis:redis:*:*)',
  `banner` text COMMENT '服务Banner',
  `state` varchar(16) DEFAULT NULL COMMENT 'open/filtered/closed',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_ports_asset_id` (`asset_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 指纹信息
CREATE TABLE IF NOT EXISTS `fingers` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` bigint unsigned NOT NULL COMMENT '关联资产ID',
  `name` varchar(255) DEFAULT NULL COMMENT '指纹名称',
  `category` varchar(64) DEFAULT NULL COMMENT 'CMS/框架/中间件/OS',
  `version` varchar(64) DEFAULT NULL COMMENT '版本',
  `detail` varchar(1024) DEFAULT NULL COMMENT '详细信息',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_fingers_asset_id` (`asset_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 漏洞信息
CREATE TABLE IF NOT EXISTS `vulns` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` bigint unsigned DEFAULT NULL COMMENT '关联资产ID',
  `task_id` bigint unsigned NOT NULL COMMENT '关联任务ID',
  `name` varchar(255) NOT NULL COMMENT '漏洞名称',
  `severity` varchar(32) DEFAULT NULL COMMENT 'critical/high/medium/low/info',
  `type` varchar(64) DEFAULT NULL COMMENT '漏洞类型',
  `template_id` varchar(255) DEFAULT NULL COMMENT 'Nuclei模板ID',
  `request` text COMMENT '请求证据',
  `response` text COMMENT '响应证据',
  `evidence` text COMMENT '其他证据',
  `remediation` text COMMENT '修复建议',
  `status` int DEFAULT 0 COMMENT '0:未确认, 1:误报, 2:确认, 3:忽略',
  `url` varchar(1024) DEFAULT NULL COMMENT '漏洞URL',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_vulns_asset_id` (`asset_id`),
  KEY `idx_vulns_task_id` (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Nuclei模板
CREATE TABLE IF NOT EXISTS `templates` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `template_id` varchar(255) NOT NULL COMMENT 'Nuclei模板ID',
  `name` varchar(255) NOT NULL COMMENT '模板名称',
  `content` text COMMENT '模板内容(YAML)',
  `type` varchar(32) DEFAULT NULL COMMENT 'official/custom/thirdparty',
  `category` varchar(32) DEFAULT NULL COMMENT 'finger/vuln',
  `protocol` varchar(32) DEFAULT NULL COMMENT 'http/tcp/dns/ssl 等',
  `cpe` varchar(255) DEFAULT NULL COMMENT 'CPE标识',
  `tags` varchar(1024) DEFAULT NULL COMMENT '标签',
  `severity` varchar(32) DEFAULT NULL COMMENT '严重级别',
  `file_path` varchar(512) DEFAULT NULL COMMENT '模板文件路径(相对路径)',
  `enabled` tinyint(1) DEFAULT 1 COMMENT '是否启用',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_templates_template_id` (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 系统配置
CREATE TABLE IF NOT EXISTS `configs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `key` varchar(255) NOT NULL COMMENT '配置键',
  `value` text COMMENT '配置值',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_configs_key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 任务执行日志
CREATE TABLE IF NOT EXISTS `task_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `task_id` bigint unsigned NOT NULL COMMENT '关联任务ID',
  `stage` varchar(32) DEFAULT NULL COMMENT '当前阶段: domain/alive/port/finger/vuln',
  `message` text COMMENT '日志消息',
  `level` varchar(16) DEFAULT 'info' COMMENT 'info/warn/error',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_task_logs_task_id` (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
