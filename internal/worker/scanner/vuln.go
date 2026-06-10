package scanner

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TargetServiceInfo 目标服务信息
type TargetServiceInfo struct {
	Target  string
	CPE     string
	Service string
}

// VulnScan 使用 Nuclei 进行漏洞扫描（全量模板，仅作兜底）
func VulnScan(ctx context.Context, targets []string, cfg *config.Config) ([]model.Vuln, error) {
	return VulnScanWithTemplates(ctx, targets, nil, cfg)
}

// VulnScanWithTemplates 使用指定模板进行漏洞扫描
func VulnScanWithTemplates(ctx context.Context, targets []string, templatePaths []string, cfg *config.Config) ([]model.Vuln, error) {
	nucleiPath, err := exec.LookPath(cfg.Scanner.NucleiPath)
	if err != nil {
		return nil, fmt.Errorf("nuclei 未安装 (%s)", cfg.Scanner.NucleiPath)
	}

	var vulns []model.Vuln

	// 写入临时目标文件，用 -l 参数传递（避免 -u 逗号拼接导致混合协议格式解析混乱）
	targetFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("创建临时目标文件失败: %v", err)
	}
	defer os.Remove(targetFile.Name())
	for _, t := range targets {
		fmt.Fprintln(targetFile, t)
	}
	targetFile.Close()

	args := []string{
		"-l", targetFile.Name(),
		"-j",
		"-silent",
		"-timeout", "10",
		"-c", "25",
		"-bs", "25",
		"-rl", "150",
	}

	if len(templatePaths) > 0 {
		// 直接传递多个 -t 参数（目录路径），nuclei 不支持从文件读取路径列表
		for _, p := range templatePaths {
			args = append(args, "-t", p)
		}
	} else if cfg.Scanner.NucleiTemplates != "" {
		args = append(args, "-t", cfg.Scanner.NucleiTemplates)
	}

	log.Printf("[VulnScan] Running nuclei with %d template directories", len(templatePaths))
	log.Printf("[VulnScan] nuclei targets: %v", targets)

	cmd := exec.CommandContext(ctx, nucleiPath, args...)
	log.Printf("[VulnScan] nuclei command: %s %v", nucleiPath, args)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err == nil {
		go func() {
			sc := bufio.NewScanner(stderr)
			for sc.Scan() {
				log.Printf("[VulnScan] nuclei stderr: %s", sc.Text())
			}
		}()
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei 启动失败: %v", err)
	}

	scanner := bufio.NewScanner(output)
	// nuclei JSON 输出可能包含很长的行（如 response body），增大 buffer 到 10MB
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("[VulnScan] Failed to parse nuclei JSON (len=%d): %v, first 200 chars: %s", len(line), err, truncate(line, 200))
			continue
		}
		if result.Info.Name == "" {
			log.Printf("[VulnScan] Skipping nuclei result with empty name, template-id=%s", result.TemplateID)
			continue
		}
		vuln := model.Vuln{
			Name:        result.Info.Name,
			Severity:    result.Info.Severity,
			Type:        result.Type,
			TemplateID:  result.TemplateID,
			URL:         firstNonEmpty(result.MatchedAt, result.URL, result.Host),
			Request:     result.Request,
			Response:    result.Response,
			Evidence:    strings.Join(result.ExtractedResults, ", "),
			Remediation: result.Info.Remediation,
			Status:      0,
		}
		vulns = append(vulns, vuln)
		log.Printf("[VulnScan] Found vuln: %s [%s] %s", vuln.Name, vuln.Severity, vuln.URL)
	}

	cmd.Wait()
	log.Printf("[VulnScan] nuclei finished, found %d vulnerabilities", len(vulns))
	return vulns, nil
}

// VulnScanByService 按服务协议筛选漏洞模板目录进行扫描
func VulnScanByService(ctx context.Context, targets []string, targetInfos []TargetServiceInfo, cfg *config.Config) ([]model.Vuln, error) {
	templateDir := cfg.Scanner.NucleiTemplates
	if templateDir == "" {
		homeDir, _ := os.UserHomeDir()
		templateDir = filepath.Join(homeDir, "nuclei-templates")
	}

	// 按协议分组目标：HTTP 目标和 Network 目标分开扫描
	type scanGroup struct {
		targets []string
		dirs    map[string]bool
	}
	httpGroup := &scanGroup{dirs: make(map[string]bool)}
	networkGroup := &scanGroup{dirs: make(map[string]bool)}

	for i, info := range targets {
		if i >= len(targetInfos) {
			break
		}
		service := strings.ToLower(targetInfos[i].Service)
		target := info

		if isHTTPTarget(target, service) {
			httpGroup.targets = append(httpGroup.targets, target)
			// HTTP 模板目录
			httpGroup.dirs[filepath.Join(templateDir, "http", "cves")] = true
			httpGroup.dirs[filepath.Join(templateDir, "http", "vulnerabilities")] = true
			httpGroup.dirs[filepath.Join(templateDir, "http", "misconfiguration")] = true
			httpGroup.dirs[filepath.Join(templateDir, "http", "exposures")] = true
			httpGroup.dirs[filepath.Join(templateDir, "http", "default-login")] = true
		} else {
			networkGroup.targets = append(networkGroup.targets, target)
			// Network 模板目录根据服务类型选择
			switch {
			case service == "ssh":
				networkGroup.dirs[filepath.Join(templateDir, "network", "cves")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "exposures")] = true
				networkGroup.dirs[filepath.Join(templateDir, "ssl")] = true
			case service == "mysql" || service == "redis" || service == "mongodb":
				networkGroup.dirs[filepath.Join(templateDir, "network", "cves")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "misconfiguration")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "default-login")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "exposures")] = true
			case service == "ftp" || service == "smtp" || service == "pop3" || service == "imap":
				networkGroup.dirs[filepath.Join(templateDir, "network", "cves")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
			case service == "mssql" || service == "postgresql" || service == "oracle":
				networkGroup.dirs[filepath.Join(templateDir, "network", "cves")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "default-login")] = true
			case service == "dns":
				networkGroup.dirs[filepath.Join(templateDir, "dns")] = true
			default:
				networkGroup.dirs[filepath.Join(templateDir, "network", "cves")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
				networkGroup.dirs[filepath.Join(templateDir, "network", "exposures")] = true
			}
		}
	}

	// 分组执行扫描
	var allVulns []model.Vuln
	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	for _, group := range []*scanGroup{httpGroup, networkGroup} {
		if len(group.targets) == 0 {
			continue
		}
		var existingDirs []string
		for dir := range group.dirs {
			if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
				existingDirs = append(existingDirs, dir)
			}
		}
		if len(existingDirs) == 0 {
			log.Printf("[VulnScan] No valid template directories for group, skipping")
			continue
		}
		log.Printf("[VulnScan] Scanning group with %d targets, %d template dirs: %v", len(group.targets), len(existingDirs), existingDirs)
		vulns, err := VulnScanWithTemplates(scanCtx, group.targets, existingDirs, cfg)
		if err != nil {
			log.Printf("[VulnScan] Group scan failed: %v", err)
			continue
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

// isHTTPTarget 判断目标是否为 HTTP 协议目标
func isHTTPTarget(target string, service string) bool {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return true
	}
	httpServices := map[string]bool{
		"http": true, "http-alt": true, "http-proxy": true, "https": true,
		"https-alt": true, "www": true, "web": true, "gunicorn": true,
		"nginx": true, "apache": true, "tomcat": true, "iis": true,
		"jetty": true, "lighttpd": true, "caddy": true,
	}
	return httpServices[service]
}

// nucleiResult Nuclei JSON 输出结构
type nucleiResult struct {
	TemplateID       string   `json:"template-id"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	URL              string   `json:"url"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	ExtractedResults []string `json:"extracted-results"`
	Info             struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Remediation string `json:"remediation"`
	} `json:"info"`
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
