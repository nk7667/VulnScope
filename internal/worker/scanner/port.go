package scanner

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortScan 端口扫描：优先使用 nmap，不可用时回退到 Go 原生 TCP 扫描
func PortScan(ctx context.Context, targets []string, cfg *config.Config) (map[string][]model.Port, error) {
	results := make(map[string][]model.Port)

	// 常见端口列表
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 2049, 2181, 2375, 3306, 3389, 4443, 5432, 5900, 5984,
		6379, 6380, 6443, 7001, 7002, 8000, 8009, 8080, 8081, 8443, 8888, 9000,
		9090, 9200, 9300, 10000, 10443, 11211, 11434, 27017, 50000, 50070,
	}

	// 检查 nmap 是否可用
	nmapPath, err := exec.LookPath(cfg.Scanner.NmapPath)
	if err == nil {
		// nmap 可用
		for _, target := range targets {
			ports, err := nmapScan(ctx, target, nmapPath)
			if err != nil {
				log.Printf("[PortScan] nmap scan %s failed: %v, fallback to TCP scan", target, err)
				ports = tcpScan(ctx, target, commonPorts)
			}
			if len(ports) > 0 {
				results[target] = ports
			}
		}
	} else {
		log.Printf("[PortScan] nmap not found (%v), using Go TCP scan", err)
		for _, target := range targets {
			ports := tcpScan(ctx, target, commonPorts)
			if len(ports) > 0 {
				results[target] = ports
			}
		}
	}

	return results, nil
}

// nmapScan 使用 nmap 扫描
func nmapScan(ctx context.Context, target, nmapPath string) ([]model.Port, error) {
	// 使用 -Pn 跳过主机发现，-sT 使用 TCP connect 扫描（Windows 兼容性更好）
	// 扫描 top-ports 1000 + 常见 Web/数据库端口范围
	cmd := exec.CommandContext(ctx, nmapPath, "-Pn", "-sT", "-T4",
		"-p", "1-10000,1433,1521,2181,2375,3306,3389,5432,5900,5984,6379,6380,6443,7001,8000,8080,8443,8888,9000,9090,9200,10000,11211,27017,50000",
		"-oG", "-", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	ports := parseNmapGrepable(string(output))

	// 对 filtered 端口进行 TCP 验证（解决 Windows 扫描 WSL 的兼容性问题）
	var verifiedPorts []model.Port
	for _, port := range ports {
		if port.State == "open" {
			verifiedPorts = append(verifiedPorts, port)
		} else if port.State == "filtered" {
			// TCP 连接验证 + Banner 读取
			addr := fmt.Sprintf("%s:%d", target, port.Port)
			dialer := net.Dialer{Timeout: 2 * time.Second}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				// 尝试读取 Banner 确认端口真正可用
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				conn.Close()

				port.State = "open"
				if n > 0 {
					port.Banner = strings.TrimSpace(string(buf[:n]))
					// 从 Banner 推断 service
					if port.Service == "" || port.Service == "unknown" {
						port.Service = guessService(port.Port)
					}
				}
				verifiedPorts = append(verifiedPorts, port)
			}
		}
	}
	return verifiedPorts, nil
}

// parseNmapGrepable 解析 nmap -oG 格式输出
func parseNmapGrepable(output string) []model.Port {
	var ports []model.Port
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "Ports:") {
			continue
		}
		idx := strings.Index(line, "Ports:")
		if idx == -1 {
			continue
		}
		portsStr := line[idx+6:]
		for _, pStr := range strings.Split(portsStr, ",") {
			pStr = strings.TrimSpace(pStr)
			parts := strings.Split(pStr, "/")
			if len(parts) < 5 {
				continue
			}
			portNum, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				continue
			}
			state := strings.TrimSpace(parts[1])
			// 只处理 open 或 filtered 状态（filtered 可能是防火墙过滤，需要 TCP 验证）
			if state != "open" && state != "filtered" {
				continue
			}
			protocol := strings.TrimSpace(parts[2])
			service := strings.TrimSpace(parts[4])
			version := ""
			if len(parts) > 6 {
				version = strings.TrimSpace(parts[6])
			}
			ports = append(ports, model.Port{
				Port:     portNum,
				Protocol: protocol,
				Service:  service,
				Version:  version,
				State:    state,
			})
		}
	}
	return ports
}

// tcpScan Go 原生 TCP 连接扫描
func tcpScan(ctx context.Context, target string, ports []int) []model.Port {
	var result []model.Port
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 并发控制：最多 100 个 goroutine
	sem := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			addr := fmt.Sprintf("%s:%d", target, p)
			dialer := net.Dialer{Timeout: 2 * time.Second}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return // 端口未开放
			}
			conn.Close()

			service := guessService(p)
			mu.Lock()
			result = append(result, model.Port{
				Port:     p,
				Protocol: "tcp",
				Service:  service,
				State:    "open",
			})
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	return result
}

// guessService 根据端口号猜测服务
func guessService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
		139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
		993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
		2049: "nfs", 2181: "zookeeper", 2375: "docker", 3306: "mysql",
		3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
		5984: "couchdb", 6379: "redis", 6380: "redis", 6443: "k8s-api",
		7001: "weblogic", 7002: "weblogic-ssl", 8000: "http-alt",
		8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
		8888: "http-alt", 9000: "php-fpm", 9090: "zeus-admin",
		9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
		11211: "memcached", 11434: "ollama", 27017: "mongodb",
		50000: "sap", 50070: "hdfs",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}
