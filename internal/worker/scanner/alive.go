package scanner

import (
	"blackbox-scanner/internal/config"
	"context"
	"crypto/tls"
	"fmt"
	"log"
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

// 常见端口列表，用于 TCP 存活探测
var commonAlivePorts = []string{
	"80", "443", "8080", "8443", "22", "21", "25", "3389",
	"3306", "5432", "6379", "27017", "8000", "8888", "3000",
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
		host, port, _ := net.SplitHostPort(target)
		if host == "" {
			host = target
		}

		// 如果目标带端口，尝试 TCP 连接验证
		if port != "" {
			conn, err := net.DialTimeout("tcp", target, 3*time.Second)
			if err == nil {
				result.Alive = true
				conn.Close()
			}
		} else {
			// 先尝试 ICMP ping
			if ping(host) {
				result.Alive = true
			}
			// ICMP 失败，尝试常见端口 TCP 探测
			if !result.Alive {
				result.Alive = tcpProbe(host)
			}
		}

		// 如果已经确认存活，跳过 HTTP 探测
		if result.Alive {
			log.Printf("[AliveScan] Target %s is alive (TCP/ICMP), skipping HTTP", target)
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

// ping 尝试 ICMP 探测（需要管理员/root 权限）
func ping(host string) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// tcpProbe 尝试常见端口的 TCP 连接探测
func tcpProbe(host string) bool {
	for _, port := range commonAlivePorts {
		addr := net.JoinHostPort(host, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			log.Printf("[AliveScan] TCP probe %s:%s succeeded", host, port)
			return true
		}
	}
	return false
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
