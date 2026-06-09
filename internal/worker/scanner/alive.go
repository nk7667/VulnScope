package scanner

import (
	"blackbox-scanner/internal/config"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// AliveResult 存活探测结果
type AliveResult struct {
	Target       string
	Alive        bool
	StatusCode   int
	ResponseTime int // 毫秒
	Title        string
	RedirectURL  string
}

// AliveScan 存活探测
func AliveScan(ctx context.Context, targets []string, cfg *config.Config) ([]AliveResult, error) {
	var results []AliveResult
	client := &http.Client{
		Timeout: time.Duration(cfg.Scanner.AliveTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, target := range targets {
		result := AliveResult{Target: target}

		// 解析目标，分离主机和端口
		host, port, err := net.SplitHostPort(target)
		fmt.Printf("[AliveScan] target=%s, host=%s, port=%s, err=%v\n", target, host, port, err)
		if host == "" {
			host = target
		}

		// 如果目标带端口，尝试 TCP 连接验证
		if port != "" {
			conn, err := net.DialTimeout("tcp", target, 3*time.Second)
			fmt.Printf("[AliveScan] TCP dial %s: err=%v\n", target, err)
			if err == nil {
				result.Alive = true
				conn.Close()
			}
		} else {
			// 先尝试 ICMP ping
			if ping(host) {
				result.Alive = true
			}
		}

		// 如果已经确认存活，跳过 HTTP 探测
		if result.Alive {
			fmt.Printf("[AliveScan] Target %s is alive (TCP), skipping HTTP\n", target)
			results = append(results, result)
			continue
		}

		// HTTP/HTTPS 探测
		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s", scheme, target)
			start := time.Now()
			resp, err := client.Get(url)
			elapsed := time.Since(start).Milliseconds()

			if err == nil {
				result.Alive = true
				result.StatusCode = resp.StatusCode
				result.ResponseTime = int(elapsed)
				result.Title = extractTitle(resp)
				if resp.Request != nil {
					result.RedirectURL = resp.Request.URL.String()
				}
				resp.Body.Close()
				break
			}
		}

		if result.Alive {
			results = append(results, result)
		}
	}

	return results, nil
}

func ping(host string) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func extractTitle(resp *http.Response) string {
	// 简单提取 title, 生产环境可用 goquery
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return ""
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if n > 0 {
		body := string(buf[:n])
		start := strings.Index(strings.ToLower(body), "<title>")
		end := strings.Index(strings.ToLower(body), "</title>")
		if start != -1 && end != -1 && end > start {
			return body[start+7 : end]
		}
	}
	return ""
}
