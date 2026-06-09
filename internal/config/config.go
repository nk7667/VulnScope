package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode     string       `yaml:"mode"`
	Server   ServerConfig `yaml:"server"`
	Database DBConfig     `yaml:"database"`
	Redis    RedisConfig  `yaml:"redis"`
	Worker   WorkerConfig `yaml:"worker"`
	Scanner  ScannerConfig `yaml:"scanner"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
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
	Concurrency       int               `yaml:"concurrency"`
	ScannerConcurrent map[string]int    `yaml:"scanner_concurrency"`
	MaxRetry          int               `yaml:"max_retry"`
	RetryDelaySec     int               `yaml:"retry_delay_sec"`
}

type ScannerConfig struct {
	NmapPath         string `yaml:"nmap_path"`
	NucleiPath       string `yaml:"nuclei_path"`
	NucleiTemplates  string `yaml:"nuclei_templates"`
	AliveTimeout     int    `yaml:"alive_timeout"`
	FingerTimeout    int    `yaml:"finger_timeout"`
	VulnTimeout      int    `yaml:"vuln_timeout"`
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
		cfg.Database.DSN = "scanner:scanner123@tcp(127.0.0.1:3306)/scanner?charset=utf8mb4&parseTime=True&loc=Local"
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
	return cfg, nil
}
