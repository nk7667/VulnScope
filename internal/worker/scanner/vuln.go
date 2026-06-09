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

	args := []string{
		"-u", strings.Join(targets, ","),
		"-j",
		"-silent",
		"-timeout", "10",
		"-c", "25",
		"-bs", "25",
		"-rl", "150",
	}

	if len(templatePaths) > 0 {
		// 使用模板列表文件避免命令行过长
		listFile, err := writeTemplateList(templatePaths)
		if err != nil {
			return nil, fmt.Errorf("写入模板列表失败: %v", err)
		}
		defer os.Remove(listFile)
		args = append(args, "-t", listFile)
	} else if cfg.Scanner.NucleiTemplates != "" {
		args = append(args, "-t", cfg.Scanner.NucleiTemplates)
	}

	log.Printf("[VulnScan] Running nuclei with %d templates", len(templatePaths))

	cmd := exec.CommandContext(ctx, nucleiPath, args...)
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
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		vuln := model.Vuln{
			Name:        result.Info.Name,
			Severity:    result.Info.Severity,
			Type:        result.Type,
			TemplateID:  result.TemplateID,
			URL:         result.Host,
			Request:     result.Request,
			Response:    result.Response,
			Evidence:    result.ExtractedResults,
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

	// 收集需要扫描的模板目录
	templateDirs := make(map[string]bool)
	for _, info := range targetInfos {
		switch info.Service {
		case "http":
			templateDirs[filepath.Join(templateDir, "http", "cves")] = true
			templateDirs[filepath.Join(templateDir, "http", "vulnerabilities")] = true
			templateDirs[filepath.Join(templateDir, "http", "misconfiguration")] = true
			templateDirs[filepath.Join(templateDir, "http", "exposures")] = true
		case "ssh":
			templateDirs[filepath.Join(templateDir, "network", "cves")] = true
			templateDirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
		case "mysql", "redis", "mongodb":
			templateDirs[filepath.Join(templateDir, "network", "cves")] = true
			templateDirs[filepath.Join(templateDir, "network", "vulnerabilities")] = true
			templateDirs[filepath.Join(templateDir, "network", "misconfiguration")] = true
		default:
			// 未知服务，只跑 HTTP 漏洞模板（最常见的场景）
			templateDirs[filepath.Join(templateDir, "http", "cves")] = true
			templateDirs[filepath.Join(templateDir, "http", "vulnerabilities")] = true
		}
	}

	// 过滤出存在的目录
	var existingDirs []string
	for dir := range templateDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			existingDirs = append(existingDirs, dir)
		}
	}

	if len(existingDirs) == 0 {
		log.Printf("[VulnScan] No valid template directories found, skipping vuln scan")
		return nil, nil
	}

	log.Printf("[VulnScan] Using %d template directories: %v", len(existingDirs), existingDirs)

	// 设置30分钟全局超时
	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	return VulnScanWithTemplates(scanCtx, targets, existingDirs, cfg)
}

// writeTemplateList 将模板路径列表写入临时文件，避免命令行过长
func writeTemplateList(paths []string) (string, error) {
	tmpFile, err := os.CreateTemp("", "nuclei-templates-*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	for _, p := range paths {
		if _, err := tmpFile.WriteString(p + "\n"); err != nil {
			os.Remove(tmpFile.Name())
			return "", err
		}
	}
	return tmpFile.Name(), nil
}

// nucleiResult Nuclei JSON 输出结构
type nucleiResult struct {
	TemplateID       string `json:"template-id"`
	Type             string `json:"type"`
	Host             string `json:"host"`
	Request          string `json:"request"`
	Response         string `json:"response"`
	ExtractedResults string `json:"extracted-results"`
	Info             struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Remediation string `json:"remediation"`
	} `json:"info"`
}
