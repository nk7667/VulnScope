package scanner

import (
	"vulnscope/internal/config"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Scanner.InsecureTLS},
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
			log.Printf("[AliveScan] Target %s is alive", target)
		} else {
			log.Printf("[AliveScan] Target %s is not alive", target)
		}
		results = append(results, result)
	}

	return results, nil
}

// icmpSupported 标记当前系统是否支持 raw ICMP（需要管理员/root 权限）
var icmpSupported = true

// icmpOnce 确保 ICMP 支持检测只执行一次
var icmpOnce sync.Once

// ping 尝试 ICMP 探测（需要管理员/root 权限）
// 构造正确的 ICMP Echo Request 包，并在权限不足时自动降级
func ping(host string) bool {
	// 首次调用时检测 ICMP 是否可用
	icmpOnce.Do(func() {
		// 非 Windows 系统检查是否 root，Windows 检查是否管理员
		if runtime.GOOS != "windows" && os.Getuid() != 0 {
			log.Printf("[AliveScan] ICMP: 非 root 权限，ICMP 探测将跳过")
			icmpSupported = false
		} else if runtime.GOOS == "windows" && !isWindowsAdmin() {
			log.Printf("[AliveScan] ICMP: 非管理员权限，ICMP 探测将跳过")
			icmpSupported = false
		}
	})

	if !icmpSupported {
		return false
	}

	// 解析主机地址
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		// 尝试 DNS 解析
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		dstIP = ips[0]
	}

	// 构造 ICMP Echo Request 包
	// ICMP 规范: Type(1字节) + Code(1字节) + Checksum(2字节) + Identifier(2字节) + Sequence(2字节) + Data
	const icmpEchoRequest uint8 = 8
	const icmpCode uint8 = 0

	// ICMP 头部 + 8 字节时间戳数据
	packet := make([]byte, 8+8)

	// 按 ICMP 规范逐字节写入头部
	packet[0] = icmpEchoRequest  // Type
	packet[1] = icmpCode         // Code
	// Checksum 先填 0，后面计算
	packet[2] = 0
	packet[3] = 0
	// Identifier: 使用进程 ID（大端序）
	id := uint16(os.Getpid() & 0xffff)
	packet[4] = byte(id >> 8)
	packet[5] = byte(id)
	// Sequence
	packet[6] = 0
	packet[7] = 1

	// 填充时间戳作为数据
	now := time.Now().UnixNano()
	binary.BigEndian.PutUint64(packet[8:16], uint64(now))

	// 计算校验和
	checksum := calcICMPChecksum(packet)
	packet[2] = byte(checksum >> 8)
	packet[3] = byte(checksum)

	// 使用 ListenIP 发送 ICMP 包（无连接协议的正确用法）
	conn, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		// 权限不足或系统不支持 raw socket
		icmpSupported = false
		return false
	}
	defer conn.Close()

	// 发送到目标
	dstAddr := &net.IPAddr{IP: dstIP}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.WriteToIP(packet, dstAddr); err != nil {
		return false
	}

	// 读取响应
	resp := make([]byte, 128)
	n, _, err := conn.ReadFromIP(resp)
	if err != nil {
		return false
	}

	// 验证响应是 ICMP Echo Reply (Type = 0)
	if n < 8 {
		return false
	}
	// IP 头部长度（低4位 * 4）
	ipHeaderLen := int(resp[0]&0x0f) * 4
	if n < ipHeaderLen+8 {
		return false
	}
	icmpType := resp[ipHeaderLen]
	return icmpType == 0 // Echo Reply
}

// calcICMPChecksum 计算 ICMP 校验和
func calcICMPChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// isWindowsAdmin 检测当前进程是否以 Windows 管理员权限运行
func isWindowsAdmin() bool {
	// 简单检测：尝试打开 raw socket
	conn, err := net.DialIP("ip4:icmp", nil, nil)
	if err == nil {
		conn.Close()
		return true
	}
	return false
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
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return ""
	}
	// 限制最大读取 1MB，避免读取超大响应体
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil || len(body) == 0 {
		return ""
	}
	lower := strings.ToLower(string(body))
	start := strings.Index(lower, "<title>")
	end := strings.Index(lower, "</title>")
	if start != -1 && end != -1 && end > start {
		return lower[start+7 : end]
	}
	return ""
}
