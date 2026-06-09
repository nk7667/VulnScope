package scanner

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// FingerResult 指纹识别结果（包含 CPE 和 Service 信息）
type FingerResult struct {
	Target  string
	Fingers []model.Finger
	CPE     string   // 识别出的 CPE
	Service string   // 识别出的服务类型 (http/ssh/mysql 等)
	Banner  string   // 服务 Banner
}

// FingerScan 指纹识别扫描：先 HTTP 指纹识别（秒级），再 nuclei 精确匹配
func FingerScan(ctx context.Context, targets []string, cfg *config.Config) (map[string]*FingerResult, error) {
	results := make(map[string]*FingerResult)

	// 分离 HTTP 目标和非 HTTP 目标
	var httpTargets, nonHTTPTargets []string
	for _, t := range targets {
		service := inferServiceByPort(t)
		if service == "http" {
			httpTargets = append(httpTargets, t)
		} else {
			nonHTTPTargets = append(nonHTTPTargets, t)
		}
	}

	log.Printf("[FingerScan] Targets: %d HTTP, %d non-HTTP", len(httpTargets), len(nonHTTPTargets))

	// 第一步：对所有目标做 HTTP 指纹识别（秒级）
	for _, target := range targets {
		result := &FingerResult{Target: target}
		result.Service = inferServiceByPort(target)

		// HTTP 指纹识别
		fingers := identifyFingers(ctx, nil, target)
		result.Fingers = fingers

		// 从指纹推断 CPE
		result.CPE = inferCPE(target, fingers)
		if result.Service == "" {
			result.Service = inferServiceByFingers(target, fingers)
		}

		results[target] = result
		log.Printf("[FingerScan] HTTP finger: %s -> service=%s cpe=%s fingers=%d", target, result.Service, result.CPE, len(fingers))
	}

	// 第二步：用 nuclei 对 HTTP 目标做精确指纹识别（限时3分钟）
	if len(httpTargets) > 0 {
		nucleiCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()

		nucleiResults, err := nucleiFingerScan(nucleiCtx, httpTargets, cfg)
		if err != nil {
			log.Printf("[FingerScan] nuclei finger scan failed: %v (using HTTP finger results)", err)
		} else {
			// 合并 nuclei 结果（补充 CPE 和更精确的指纹）
			for host, nr := range nucleiResults {
				if existing, ok := results[host]; ok {
					// 补充 CPE
					if nr.CPE != "" && existing.CPE == "" {
						existing.CPE = nr.CPE
					}
					// 补充指纹
					existing.Fingers = append(existing.Fingers, nr.Fingers...)
					// 补充 Service
					if nr.Service != "" && existing.Service == "" {
						existing.Service = nr.Service
					}
				} else {
					results[host] = nr
				}
			}
		}
	}

	// 第三步：用 nuclei 对非 HTTP 目标做网络服务指纹识别（限时2分钟）
	if len(nonHTTPTargets) > 0 {
		networkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		nucleiResults, err := nucleiNetworkFingerScan(networkCtx, nonHTTPTargets, cfg)
		if err != nil {
			log.Printf("[FingerScan] nuclei network finger scan failed: %v", err)
		} else {
			for host, nr := range nucleiResults {
				if existing, ok := results[host]; ok {
					if nr.CPE != "" && existing.CPE == "" {
						existing.CPE = nr.CPE
					}
					existing.Fingers = append(existing.Fingers, nr.Fingers...)
					if nr.Service != "" && existing.Service == "" {
						existing.Service = nr.Service
					}
				} else {
					results[host] = nr
				}
			}
		}
	}

	log.Printf("[FingerScan] Finished, found %d results", len(results))
	return results, nil
}

// inferServiceByPort 根据端口推断服务类型
func inferServiceByPort(target string) string {
	_, port, _ := net.SplitHostPort(target)
	switch port {
	case "80", "8080", "8000", "8888", "443", "8443", "3000", "5000", "7001":
		return "http"
	case "22":
		return "ssh"
	case "3306":
		return "mysql"
	case "6379", "6380":
		return "redis"
	case "27017":
		return "mongodb"
	case "21":
		return "ftp"
	case "25":
		return "smtp"
	}
	return ""
}

// inferCPE 从指纹推断 CPE（基础版本，仅处理 Server 头中的常见技术栈）
// 更全面的 CPE 推断由 worker.go 中的数据库模板查询完成
func inferCPE(target string, fingers []model.Finger) string {
	for _, f := range fingers {
		lower := strings.ToLower(f.Name)
		// 只处理 Server 头信息（如 "Apache/2.4.38"、"nginx/1.18"）
		// 这些信息在 HTTP 指纹识别阶段产出，nuclei 可能不会再次识别
		switch {
		case strings.Contains(lower, "apache") && !strings.Contains(lower, "tomcat"):
			return "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
		case strings.Contains(lower, "nginx"):
			return "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
		case strings.Contains(lower, "iis"):
			return "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*"
		}
	}
	return ""
}

// inferServiceByFingers 从指纹推断服务类型
func inferServiceByFingers(target string, fingers []model.Finger) string {
	for _, f := range fingers {
		switch strings.ToLower(f.Category) {
		case "webserver", "framework", "cms", "frontend":
			return "http"
		}
	}
	return ""
}

// isInvalidCPE 检查 CPE 是否为无效的产品标识（如 WAF、防火墙等非产品类指纹）
func isInvalidCPE(cpe string) bool {
	lower := strings.ToLower(cpe)
	invalidProducts := []string{"waf", "firewall", "proxy", "cdn", "load-balancer", "ids", "ips"}
	for _, p := range invalidProducts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// nucleiFingerScan 使用 nuclei HTTP 指纹模板进行识别（仅对 HTTP 目标）
func nucleiFingerScan(ctx context.Context, targets []string, cfg *config.Config) (map[string]*FingerResult, error) {
	results := make(map[string]*FingerResult)

	nucleiPath, err := exec.LookPath(cfg.Scanner.NucleiPath)
	if err != nil {
		return nil, fmt.Errorf("nuclei not found")
	}

	templateDir := cfg.Scanner.NucleiTemplates
	if templateDir == "" {
		homeDir, _ := os.UserHomeDir()
		templateDir = filepath.Join(homeDir, "nuclei-templates")
	}

	// 只使用 technologies 目录下的常见子目录
	fingerPaths := findHTTPFingerTemplates(templateDir)
	if len(fingerPaths) == 0 {
		return nil, fmt.Errorf("no HTTP finger templates found")
	}

	log.Printf("[FingerScan] Found %d HTTP finger template paths", len(fingerPaths))

	args := []string{
		"-u", strings.Join(targets, ","),
		"-j",
		"-silent",
		"-timeout", "10",  // 每个请求超时10秒
		"-c", "25",
		"-bs", "25",
		"-rl", "150",
	}
	for _, p := range fingerPaths {
		args = append(args, "-t", p)
	}

	log.Printf("[FingerScan] Running nuclei HTTP finger scan: %s %v", nucleiPath, args)

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
				log.Printf("[FingerScan] nuclei stderr: %s", sc.Text())
			}
		}()
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei start failed: %v", err)
	}

	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result nucleiFingerResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		host := result.Host
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			if u, e := parseURL(host); e == nil {
				host = u
			}
		}

		fr, ok := results[host]
		if !ok {
			fr = &FingerResult{Target: host}
			results[host] = fr
		}

		fr.Fingers = append(fr.Fingers, model.Finger{
			Name:     result.Info.Name,
			Category: "Service",
		})

		if result.Info.Classification.CPE != "" && fr.CPE == "" {
			if !isInvalidCPE(result.Info.Classification.CPE) {
				fr.CPE = result.Info.Classification.CPE
			}
		}
		// 如果没有 CPE 但有 vendor/product，构造 CPE
		if fr.CPE == "" && result.Info.Metadata.Vendor != "" && result.Info.Metadata.Product != "" {
			cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", result.Info.Metadata.Vendor, result.Info.Metadata.Product)
			if !isInvalidCPE(cpe) {
				fr.CPE = cpe
			}
		}
		if result.Type != "" {
			fr.Service = result.Type
		}

		log.Printf("[FingerScan] nuclei found: %s [%s] CPE=%s on %s", result.Info.Name, result.Type, fr.CPE, host)
	}

	cmd.Wait()
	log.Printf("[FingerScan] nuclei HTTP finger scan finished, found %d results", len(results))
	return results, nil
}

// nucleiNetworkFingerScan 使用 nuclei 网络指纹模板进行识别（仅对非 HTTP 目标）
func nucleiNetworkFingerScan(ctx context.Context, targets []string, cfg *config.Config) (map[string]*FingerResult, error) {
	results := make(map[string]*FingerResult)

	nucleiPath, err := exec.LookPath(cfg.Scanner.NucleiPath)
	if err != nil {
		return nil, fmt.Errorf("nuclei not found")
	}

	templateDir := cfg.Scanner.NucleiTemplates
	if templateDir == "" {
		homeDir, _ := os.UserHomeDir()
		templateDir = filepath.Join(homeDir, "nuclei-templates")
	}

	// 只使用 network/detection 目录
	detectDir := filepath.Join(templateDir, "network", "detection")
	if _, err := os.Stat(detectDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("network detection templates not found: %s", detectDir)
	}

	args := []string{
		"-u", strings.Join(targets, ","),
		"-j",
		"-silent",
		"-timeout", "10",
		"-c", "25",
		"-bs", "25",
		"-rl", "150",
		"-t", detectDir,
	}

	log.Printf("[FingerScan] Running nuclei network finger scan: %s %v", nucleiPath, args)

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
				log.Printf("[FingerScan] nuclei stderr: %s", sc.Text())
			}
		}()
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei start failed: %v", err)
	}

	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result nucleiFingerResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		host := result.Host
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			if u, e := parseURL(host); e == nil {
				host = u
			}
		}

		fr, ok := results[host]
		if !ok {
			fr = &FingerResult{Target: host}
			results[host] = fr
		}

		fr.Fingers = append(fr.Fingers, model.Finger{
			Name:     result.Info.Name,
			Category: "Service",
		})

		if result.Info.Classification.CPE != "" && fr.CPE == "" {
			if !isInvalidCPE(result.Info.Classification.CPE) {
				fr.CPE = result.Info.Classification.CPE
			}
		}
		// 如果没有 CPE 但有 vendor/product，构造 CPE
		if fr.CPE == "" && result.Info.Metadata.Vendor != "" && result.Info.Metadata.Product != "" {
			cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", result.Info.Metadata.Vendor, result.Info.Metadata.Product)
			if !isInvalidCPE(cpe) {
				fr.CPE = cpe
			}
		}
		if result.Type != "" {
			fr.Service = result.Type
		}

		log.Printf("[FingerScan] nuclei network found: %s [%s] CPE=%s on %s", result.Info.Name, result.Type, fr.CPE, host)
	}

	cmd.Wait()
	log.Printf("[FingerScan] nuclei network finger scan finished, found %d results", len(results))
	return results, nil
}

// nucleiFingerResult nuclei 指纹识别 JSON 输出结构
type nucleiFingerResult struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CPE string `json:"cpe"`
		} `json:"classification"`
		Metadata struct {
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
		} `json:"metadata"`
	} `json:"info"`
	ExtractedResults []string `json:"extracted-results"`
}

// findHTTPFingerTemplates 查找 HTTP 指纹模板（只返回存在的常见技术子目录）
func findHTTPFingerTemplates(templateDir string) []string {
	var paths []string
	techDir := filepath.Join(templateDir, "http", "technologies")

	// 直接使用整个 technologies 目录（含根目录393个+子目录348个模板）
	if fi, err := os.Stat(techDir); err == nil && fi.IsDir() {
		paths = append(paths, techDir)
	}

	return paths
}

// parseURL 简单解析 URL 提取 host:port
func parseURL(rawURL string) (string, error) {
	s := rawURL
	if strings.HasPrefix(s, "https://") {
		s = s[8:]
	} else if strings.HasPrefix(s, "http://") {
		s = s[7:]
	}
	if idx := strings.Index(s, "/"); idx > 0 {
		s = s[:idx]
	}
	return s, nil
}

// ========== 以下为 HTTP 指纹识别逻辑 ==========

// identifyFingers HTTP 指纹识别：先用 HEAD 探测存活，再用 GET 获取指纹
func identifyFingers(ctx context.Context, client *http.Client, target string) []model.Finger {
	var fingers []model.Finger

	host := target
	hasPort := false
	if h, p, err := net.SplitHostPort(target); err == nil && p != "" {
		host = h
		hasPort = true
	}

	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}

	schemes := []string{"https", "http"}
	if hasPort {
		_, port, _ := net.SplitHostPort(target)
		if port == "443" || port == "8443" {
			schemes = []string{"https"}
		} else if port == "80" || port == "8080" {
			schemes = []string{"http"}
		}
	}

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, target)

		// 先用 HEAD 探测存活
		headReq, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		headReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackboxScanner/1.0)")

		resp, err := client.Do(headReq)
		if err != nil {
			continue // HTTPS 失败，尝试 HTTP
		}
		resp.Body.Close()

		// HEAD 成功，从响应头提取指纹
		fingers = append(fingers, checkHeaders(resp, host)...)

		// 如果 HEAD 没有足够信息，用 GET 获取响应体
		if len(fingers) == 0 {
			getReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}
			getReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackboxScanner/1.0)")

			getResp, err := client.Do(getReq)
			if err != nil {
				continue
			}
			defer getResp.Body.Close()

			// 从响应头提取指纹
			fingers = append(fingers, checkHeaders(getResp, host)...)

			// 从响应体提取指纹
			buf := make([]byte, 8192)
			n, _ := getResp.Body.Read(buf)
			if n > 0 {
				body := string(buf[:n])
				fingers = append(fingers, checkBody(body)...)
			}
		}

		if len(fingers) > 0 {
			break
		}
	}

	return fingers
}

func checkHeaders(resp *http.Response, target string) []model.Finger {
	var fingers []model.Finger

	server := resp.Header.Get("Server")
	if server != "" {
		fingers = append(fingers, model.Finger{
			Name:     server,
			Category: "WebServer",
			Detail:   fmt.Sprintf("Server: %s", server),
		})
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		fingers = append(fingers, model.Finger{
			Name:     poweredBy,
			Category: "Framework",
			Detail:   fmt.Sprintf("X-Powered-By: %s", poweredBy),
		})
	}

	return fingers
}

func checkBody(body string) []model.Finger {
	var fingers []model.Finger
	lower := strings.ToLower(body)

	fingerprints := map[string]struct {
		name     string
		category string
		keyword  string
	}{
		"wordpress": {"WordPress", "CMS", "wp-content"},
		"laravel":   {"Laravel", "Framework", "laravel"},
		"django":    {"Django", "Framework", "csrfmiddlewaretoken"},
		"spring":    {"Spring", "Framework", "whitelabel error page"},
		"thinkphp":  {"ThinkPHP", "Framework", "thinkphp"},
		"vue":       {"Vue.js", "Frontend", "vue."},
		"react":     {"React", "Frontend", "react"},
		"jquery":    {"jQuery", "Frontend", "jquery"},
		"bootstrap": {"Bootstrap", "Frontend", "bootstrap"},
	}

	for _, fp := range fingerprints {
		if strings.Contains(lower, fp.keyword) {
			fingers = append(fingers, model.Finger{
				Name:     fp.name,
				Category: fp.category,
			})
		}
	}

	return fingers
}
