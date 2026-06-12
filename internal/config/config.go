package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode     string        `yaml:"mode"`
	Server   ServerConfig  `yaml:"server"`
	Database DBConfig      `yaml:"database"`
	Redis    RedisConfig   `yaml:"redis"`
	Worker   WorkerConfig  `yaml:"worker"`
	Scanner  ScannerConfig `yaml:"scanner"`
}

type ServerConfig struct {
	Addr           string `yaml:"addr"`
	APIKey         string `yaml:"api_key"`          // API Key 认证，为空则不启用
	AllowedOrigins string `yaml:"allowed_origins"`  // CORS 允许的来源，必须显式配置
}

type DBConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type WorkerConfig struct {
	Concurrency       int            `yaml:"concurrency"`
	ScannerConcurrent map[string]int `yaml:"scanner_concurrency"`
	MaxRetry          int            `yaml:"max_retry"`
	RetryDelaySec     int            `yaml:"retry_delay_sec"`
	AllowScanStart    string         `yaml:"allow_scan_start"` // 允许扫描的开始时间，如 "08:00"
	AllowScanEnd      string         `yaml:"allow_scan_end"`   // 允许扫描的结束时间，如 "20:00"
	ExcludeTargets    []string       `yaml:"exclude_targets"`  // 全局排除目标（IP/域名/网段）
	ExcludePorts      []int          `yaml:"exclude_ports"`    // 全局排除端口
	IPScanCooldownMin int            `yaml:"ip_scan_cooldown_min"` // IP 扫描冷却时间（分钟），0 表示不限制
}

type ScannerConfig struct {
	NmapPath            string `yaml:"nmap_path"`
	NucleiPath          string `yaml:"nuclei_path"`
	NucleiTemplates     string `yaml:"nuclei_templates"`
	NucleiConcurrency   int    `yaml:"nuclei_concurrency"`   // nuclei 模板并发数
	NucleiBulkSize      int    `yaml:"nuclei_bulk_size"`     // nuclei 批量大小
	NucleiTimeout       int    `yaml:"nuclei_timeout"`       // nuclei 单个请求超时（秒）
	SubdomainWordlist   string `yaml:"subdomain_wordlist"`   // 子域名爆破字典文件路径
	ChromePath          string `yaml:"chrome_path"`          // Chrome/Chromium 可执行文件路径（为空则自动查找）
	InteractshServer    string `yaml:"interactsh_server"`    // OAST 反连服务器地址（如 interact.sh，为空则使用默认）
	InteractshToken     string `yaml:"interactsh_token"`     // OAST 反连服务器认证 token
	AliveTimeout        int    `yaml:"alive_timeout"`
	FingerTimeout       int    `yaml:"finger_timeout"`
	VulnTimeout         int    `yaml:"vuln_timeout"`
	InsecureTLS         bool   `yaml:"insecure_tls"` // 仅在明确配置时跳过 TLS 验证
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// 敏感配置优先从环境变量获取，避免明文存储在配置文件中
	if v := os.Getenv("SCANNER_API_KEY"); v != "" {
		cfg.Server.APIKey = v
	}
	if v := os.Getenv("SCANNER_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("SCANNER_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}

	// 默认值
	if cfg.Mode == "" {
		cfg.Mode = "all"
	}
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":8080"
	}
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "mysql"
	}
	if cfg.Database.DSN == "" {
		return nil, fmt.Errorf("database.dsn 必须在配置文件或环境变量 SCANNER_DB_DSN 中设置，不再提供默认弱密码")
	}
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "127.0.0.1:6379"
	}
	if cfg.Worker.Concurrency == 0 {
		cfg.Worker.Concurrency = 10
	}
	if cfg.Worker.MaxRetry == 0 {
		cfg.Worker.MaxRetry = 3
	}
	if cfg.Worker.RetryDelaySec == 0 {
		cfg.Worker.RetryDelaySec = 60
	}
	if cfg.Scanner.AliveTimeout == 0 {
		cfg.Scanner.AliveTimeout = 60
	}
	if cfg.Scanner.FingerTimeout == 0 {
		cfg.Scanner.FingerTimeout = 1200
	}
	if cfg.Scanner.VulnTimeout == 0 {
		cfg.Scanner.VulnTimeout = 1200
	}
	if cfg.Scanner.NucleiConcurrency == 0 {
		cfg.Scanner.NucleiConcurrency = 25
	}
	if cfg.Scanner.NucleiBulkSize == 0 {
		cfg.Scanner.NucleiBulkSize = 25
	}
	if cfg.Scanner.NucleiTimeout == 0 {
		cfg.Scanner.NucleiTimeout = 10
	}
	return cfg, nil
}
