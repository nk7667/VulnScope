package scanner

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"unicode/utf8"
)

// sanitizeField 检查字符串是否为有效 UTF-8，非 UTF-8 数据用 base64 编码
func sanitizeField(s string) string {
	if s == "" {
		return ""
	}
	if utf8.ValidString(s) {
		return s
	}
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(s))
}

// TargetServiceInfo 目标服务信息
type TargetServiceInfo struct {
	Target  string
	CPE     string
	Service string
}

// nucleiJSONResult nuclei JSON 输出结构
// nuclei 实际输出格式: {"template-id":"...", "info":{"name":"...", "severity":"..."}, ...}
type nucleiJSONResult struct {
	TemplateID       string   `json:"template-id"`
	TemplatePath     string   `json:"template-path"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Matched          string   `json:"matched-at"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	ExtractedResults []string `json:"extracted-results"`
	CURLCommand      string   `json:"curl-command"`
	Info             struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Remediation string `json:"remediation"`
	} `json:"info"`
}

// VulnScan 使用 Nuclei 进行漏洞扫描（全量模板，仅作兜底）
func VulnScan(ctx context.Context, targets []string, cfg *config.Config) ([]model.Vuln, error) {
	return VulnScanWithTemplates(ctx, targets, nil, cfg)
}

// VulnScanWithTemplates 使用指定模板进行漏洞扫描（优化的子进程调用方式）
// 改进点：
//   - 支持指定模板列表/目录，避免全量扫描
//   - 精确控制并发参数（-c, -bs）
//   - 超时控制（-timeout）
//   - 上下文取消支持（进程级 Kill）
//   - 结构化 JSON 输出解析
func VulnScanWithTemplates(ctx context.Context, targets []string, templatePaths []string, cfg *config.Config) ([]model.Vuln, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	nucleiPath := cfg.Scanner.NucleiPath
	if nucleiPath == "" {
		nucleiPath = "nuclei"
	}

	// 创建临时目标文件
	tmpFile, err := os.CreateTemp("", "vulnscope-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("创建临时目标文件失败: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	// 构建命令参数
	args := []string{
		"-l", tmpFile.Name(),
		"-j",
		"-silent",
		"-c", fmt.Sprintf("%d", cfg.Scanner.NucleiConcurrency),
		"-bs", fmt.Sprintf("%d", cfg.Scanner.NucleiBulkSize),
		"-timeout", fmt.Sprintf("%d", cfg.Scanner.NucleiTimeout),
		"-retries", "1",
		"-no-color",
	}

	// OAST/反连验证配置
	// 如果配置了 interactsh 服务器，启用 OAST 反连验证（支持 SSRF、Log4j 等无回显漏洞检测）
	if cfg.Scanner.InteractshServer != "" {
		args = append(args, "-interactsh-server", cfg.Scanner.InteractshServer)
		if cfg.Scanner.InteractshToken != "" {
			args = append(args, "-interactsh-token", cfg.Scanner.InteractshToken)
		}
	}
	// 未配置 interactsh 服务器时，使用 nuclei 默认的公共 interactsh 实例
	// 不添加 -no-interactsh，让 nuclei 自动使用 OAST

	// 配置模板
	if len(templatePaths) > 0 {
		for _, tp := range templatePaths {
			args = append(args, "-t", tp)
		}
	} else if cfg.Scanner.NucleiTemplates != "" {
		args = append(args, "-t", cfg.Scanner.NucleiTemplates)
	}

	// 禁用 TLS 验证
	if cfg.Scanner.InsecureTLS {
		args = append(args, "-insecure-skip-tls-verify")
	}

	// 扫描超时由 Go context 控制（exec.CommandContext 会自动 kill 进程）
	// 注意：nuclei v3 已移除 -scan-timeout flag，不再使用
	// 如需限制单个模板执行时间，可通过 -timeout 控制单请求超时（默认10秒）

	log.Printf("[VulnScan] Running nuclei: %s %v", nucleiPath, args)

	// 创建带上下文取消的命令
	cmd := exec.CommandContext(ctx, nucleiPath, args...)
	cmd.Env = append(os.Environ(), "NUCLEI_LOG_LEVEL=error")

	// 获取 stdout pipe 用于流式读取
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("nuclei stdout pipe 失败: %v", err)
	}

	// stderr 用于错误日志和兼容性检测
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("nuclei stderr pipe 失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei 启动失败: %v", err)
	}

	// 流式读取 stderr，检测 unknown flag 错误
	var stderrBuf strings.Builder
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line + "\n")
			if strings.Contains(line, "error") || strings.Contains(line, "fatal") {
				log.Printf("[VulnScan] nuclei stderr: %s", line)
			}
		}
	}()

	// 流式读取 stdout，实时解析 JSON 结果
	var vulns []model.Vuln
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var result nucleiJSONResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// 非 JSON 行，可能是 nuclei 的进度输出，跳过
			continue
		}

		// 跳过空名称的结果
		templateName := result.Info.Name
		severity := result.Info.Severity
		if templateName == "" && result.TemplateID == "" {
			continue
		}

		name := templateName
		if name == "" {
			name = result.TemplateID
		}

		matchedURL := firstNonEmpty(result.Matched, result.Host)
		evidence := ""
		if len(result.ExtractedResults) > 0 {
			evidence = strings.Join(result.ExtractedResults, ", ")
		}

		vuln := model.Vuln{
			Name:        name,
			Severity:    severity,
			Type:        result.Type,
			TemplateID:  result.TemplateID,
			URL:         matchedURL,
			Request:     sanitizeField(result.Request),
			Response:    sanitizeField(result.Response),
			Evidence:    evidence,
			Remediation: result.Info.Remediation,
			Status:      0,
		}
		vulns = append(vulns, vuln)
		log.Printf("[VulnScan] Found vuln: %s [%s] %s", vuln.Name, vuln.Severity, vuln.URL)
	}

	// 等待进程结束
	if err := cmd.Wait(); err != nil {
		// 等待 stderr goroutine 完成，确保错误信息完整
		<-stderrDone
		// 上下文取消导致的退出不算错误
		if ctx.Err() != nil {
			log.Printf("[VulnScan] nuclei scan cancelled by context")
			return vulns, nil
		}

		// nuclei 退出码 1 可能表示有发现但无致命错误，只记录警告
		log.Printf("[VulnScan] nuclei exited with error: %v (found %d vulns before exit)", err, len(vulns))
	} else {
		// 正常退出，等待 stderr goroutine 完成
		<-stderrDone
	}

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

	for i := range targetInfos {
		service := strings.ToLower(targetInfos[i].Service)
		target := targetInfos[i].Target

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
