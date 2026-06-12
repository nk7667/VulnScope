package scanner

import (
	"vulnscope/internal/config"
	"vulnscope/internal/model"
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

	// 第四步：对 HTTP 指纹识别结果不足的目标，使用浏览器渲染获取更多指纹
	// 浏览器渲染可以执行 JS，检测前端框架全局变量，获取更详细的技术栈信息
	var browserTargets []string
	for _, target := range httpTargets {
		if fr, ok := results[target]; ok {
			// CPE 和指纹都为空，或只有 WebServer 指纹没有框架/CMS 指纹
			hasDetailFinger := false
			for _, f := range fr.Fingers {
				if f.Category != "WebServer" {
					hasDetailFinger = true
					break
				}
			}
			if fr.CPE == "" || !hasDetailFinger {
				browserTargets = append(browserTargets, target)
			}
		}
	}
	if len(browserTargets) > 0 && IsBrowserAvailable(cfg) {
		log.Printf("[FingerScan] Using browser rendering for %d targets with insufficient fingerprints", len(browserTargets))
		browserResults, err := BrowserFingerScan(ctx, browserTargets, cfg)
		if err != nil {
			log.Printf("[FingerScan] Browser finger scan failed: %v", err)
		} else {
			for _, br := range browserResults {
				// 从浏览器结果中提取 host:port
				host := br.URL
				if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
					if u, e := parseURL(host); e == nil {
						host = u
					}
				}
				if existing, ok := results[host]; ok {
					// 补充浏览器检测到的技术栈指纹
					for _, tech := range br.Technologies {
						// 检查是否已有该指纹
						duplicate := false
						for _, f := range existing.Fingers {
							if f.Name == tech {
								duplicate = true
								break
							}
						}
						if !duplicate {
							category := "Frontend"
							if isCMS(tech) {
								category = "CMS"
							} else if isFramework(tech) {
								category = "Framework"
							}
							existing.Fingers = append(existing.Fingers, model.Finger{
								Name:     tech,
								Category: category,
								Detail:   "Browser detected",
							})
						}
					}
					// 补充 CPE
					if existing.CPE == "" {
						existing.CPE = inferCPEFromTechs(br.Technologies)
					}
				}
			}
		}
	} else if len(browserTargets) > 0 {
		log.Printf("[FingerScan] Browser not available, skipping browser-based fingerprinting for %d targets", len(browserTargets))
	}

	log.Printf("[FingerScan] Finished, found %d results", len(results))
	return results, nil
}

// InferServiceByPort 根据端口推断服务类型（导出供 worker 使用）
func InferServiceByPort(target string) string {
	return inferServiceByPort(target)
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
		// 从 Server 头信息提取版本号（如 "Apache/2.4.38"、"nginx/1.18.0"、"PHP/7.4.3"）
		switch {
		case strings.Contains(lower, "apache") && !strings.Contains(lower, "tomcat"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "nginx"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:nginx:nginx:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "iis"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:microsoft:iis:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "php"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:php:php:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "tomcat"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:apache:tomcat:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "openssl"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:openssl:openssl:%s:*:*:*:*:*:*:*", version)
		case strings.Contains(lower, "gunicorn"):
			version := extractVersion(f.Name)
			return fmt.Sprintf("cpe:2.3:a:gunicorn:gunicorn:%s:*:*:*:*:*:*:*", version)
		}
	}
	return ""
}

// extractVersion 从 Server 头提取版本号（如 "Apache/2.4.38" → "2.4.38"）
func extractVersion(serverHeader string) string {
	// 查找 / 后的版本号
	idx := strings.Index(serverHeader, "/")
	if idx == -1 {
		return "*"
	}
	version := strings.TrimSpace(serverHeader[idx+1:])
	// 只取第一个空格前的部分（处理 "Apache/2.4.38 (Ubuntu)" 这类格式）
	if spaceIdx := strings.Index(version, " "); spaceIdx != -1 {
		version = version[:spaceIdx]
	}
	if version == "" {
		return "*"
	}
	return version
}

// ProbeHTTPService 尝试 HTTP 探测目标是否为 HTTP 服务
func ProbeHTTPService(ctx context.Context, target string, insecureTLS bool) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, target)
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VulnScope/1.0)")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
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

	// 写入临时目标文件
	targetFile, err := os.CreateTemp("", "nuclei-finger-http-*.txt")
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

	// 写入临时目标文件
	targetFile, err := os.CreateTemp("", "nuclei-finger-net-*.txt")
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

// isCMS 判断技术是否为 CMS
func isCMS(tech string) bool {
	cmsList := []string{"WordPress", "Drupal", "Joomla"}
	for _, c := range cmsList {
		if tech == c {
			return true
		}
	}
	return false
}

// isFramework 判断技术是否为 Framework
func isFramework(tech string) bool {
	fwList := []string{"React", "Vue", "Angular", "AngularJS", "Next.js", "Nuxt.js", "Svelte", "Ember.js", "Backbone.js", "Meteor", "Laravel", "Django", "Spring"}
	for _, f := range fwList {
		if tech == f {
			return true
		}
	}
	return false
}

// inferCPEFromTechs 从浏览器检测到的技术栈推断 CPE
func inferCPEFromTechs(techs []string) string {
	for _, tech := range techs {
		switch tech {
		case "jQuery":
			return "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*"
		case "React":
			return "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*"
		case "Vue":
			return "cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*"
		case "Angular", "AngularJS":
			return "cpe:2.3:a:angular:angular:*:*:*:*:*:*:*:*"
		case "WordPress":
			return "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
		case "Drupal":
			return "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*"
		case "Joomla":
			return "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*"
		case "Bootstrap":
			return "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*"
		case "Lodash":
			return "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*"
		}
	}
	return ""
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
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
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
