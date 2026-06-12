package scanner

import (
	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DomainResult 域名扫描结果
type DomainResult struct {
	IP     string
	Port   int
	Domain string
	CNAME  string
}

func (r *DomainResult) ToAsset(taskID uint) *model.Asset {
	return &model.Asset{
		TaskID: taskID,
		IP:     r.IP,
		Domain: r.Domain,
	}
}

// parseTarget 解析目标，分离主机和端口
func parseTarget(target string) (host string, port int) {
	// 尝试解析为 host:port 格式
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, parsePort(p)
	}
	// 没有端口，直接返回
	return target, 0
}

// parsePort 解析端口号
func parsePort(p string) int {
	port := 0
	for _, c := range p {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return port
}

// DomainScan 域名解析扫描
func DomainScan(ctx context.Context, targets []string, cfg *config.Config) ([]DomainResult, error) {
	var results []DomainResult
	discovered := make(map[string]bool) // 去重

	for _, target := range targets {
		host, port := parseTarget(target)

		// 判断是域名还是IP
		if net.ParseIP(host) != nil {
			// 已经是IP，直接添加
			key := host
			if !discovered[key] {
				discovered[key] = true
				results = append(results, DomainResult{IP: host, Port: port})
			}
			continue
		}

		// DNS解析
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			key := ip.IP.String() + ":" + host
			if !discovered[key] {
				discovered[key] = true
				results = append(results, DomainResult{
					IP:     ip.IP.String(),
					Port:   port,
					Domain: host,
				})
			}
		}

		// CNAME查询
		cname, _ := net.DefaultResolver.LookupCNAME(ctx, host)
		if cname != "" && cname != host+"." {
			// 更新最后一条结果的CNAME
			if len(results) > 0 {
				results[len(results)-1].CNAME = cname
			}
		}

		// 子域名发现：证书透明度日志查询
		subdomains := discoverSubdomains(ctx, host, cfg)
		for _, sub := range subdomains {
			subIps, err := net.DefaultResolver.LookupIPAddr(ctx, sub)
			if err != nil {
				continue
			}
			for _, ip := range subIps {
				key := ip.IP.String() + ":" + sub
				if !discovered[key] {
					discovered[key] = true
					results = append(results, DomainResult{
						IP:     ip.IP.String(),
						Port:   port,
						Domain: sub,
					})
				}
			}
		}
	}

	return results, nil
}

// ========== 子域名发现 ==========

// ctLogEntry 证书透明度日志条目
type ctLogEntry struct {
	NameValue string `json:"name_value"`
}

// discoverSubdomains 通过证书透明度日志和子域名爆破发现子域名
func discoverSubdomains(ctx context.Context, domain string, cfg *config.Config) []string {
	var subdomains []string
	seen := make(map[string]bool)

	// 1. 证书透明度日志查询（crt.sh）
	ctResults := queryCTLog(ctx, domain)
	for _, sub := range ctResults {
		if !seen[sub] {
			seen[sub] = true
			subdomains = append(subdomains, sub)
		}
	}

	// 2. DNS 区域传输尝试
	zoneResults := tryZoneTransfer(ctx, domain)
	for _, sub := range zoneResults {
		if !seen[sub] {
			seen[sub] = true
			subdomains = append(subdomains, sub)
		}
	}

	// 3. 子域名爆破（如果配置了字典文件）
	if cfg.Scanner.SubdomainWordlist != "" {
		bruteResults := bruteSubdomains(ctx, domain, cfg.Scanner.SubdomainWordlist, cfg)
		for _, sub := range bruteResults {
			if !seen[sub] {
				seen[sub] = true
				subdomains = append(subdomains, sub)
			}
		}
	}

	if len(subdomains) > 0 {
		log.Printf("[DomainScan] Discovered %d subdomains for %s", len(subdomains), domain)
	}
	return subdomains
}

// queryCTLog 通过 crt.sh 证书透明度日志查询子域名
func queryCTLog(ctx context.Context, domain string) []string {
	var subdomains []string

	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return subdomains
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DomainScan] CT log query failed for %s: %v", domain, err)
		return subdomains
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return subdomains
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return subdomains
	}

	var entries []ctLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return subdomains
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		// name_value 可能包含多个域名（换行分隔）
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.ToLower(name)
			// 去掉通配符前缀
			name = strings.TrimPrefix(name, "*.")

			if name == "" || seen[name] {
				continue
			}
			// 只保留当前域名及其子域名
			if name == domain || strings.HasSuffix(name, "."+domain) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains
}

// tryZoneTransfer 尝试 DNS 区域传输获取子域名
func tryZoneTransfer(ctx context.Context, domain string) []string {
	var subdomains []string

	// 查询 NS 记录
	nsRecords, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil || len(nsRecords) == 0 {
		return subdomains
	}

	seen := make(map[string]bool)
	for _, ns := range nsRecords {
		// 尝试对每个 NS 服务器进行区域传输
		zoneResults, err := attemptZoneTransfer(domain, ns.Host)
		if err != nil {
			continue
		}
		for _, sub := range zoneResults {
			if !seen[sub] {
				seen[sub] = true
				subdomains = append(subdomains, sub)
			}
		}
	}

	return subdomains
}

// attemptZoneTransfer 尝试对指定 NS 服务器进行区域传输
func attemptZoneTransfer(domain, nsServer string) ([]string, error) {
	// 使用自定义 DNS 客户端尝试 AXFR
	// 注意：大多数 DNS 服务器已禁止区域传输，这里作为补充发现手段
	client := &dnsClient{timeout: 5 * time.Second}
	return client.Transfer(domain, nsServer)
}

// dnsClient 简易 DNS 客户端，支持区域传输
type dnsClient struct {
	timeout time.Duration
}

// Transfer 尝试 DNS 区域传输
func (c *dnsClient) Transfer(domain, nsServer string) ([]string, error) {
	// 构造 DNS AXFR 请求包
	// AXFR type = 252, class = 1 (IN)
	// 由于标准库不支持 AXFR，这里使用 TCP 连接手动构造
	nsAddr, err := net.ResolveIPAddr("ip", nsServer)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(nsAddr.String(), "53"), c.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(c.timeout))

	// 构造 DNS 查询：AXFR
	// Header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2)
	// Question: QNAME + QTYPE(2) + QCLASS(2)
	query := buildAXFRQuery(domain)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// 读取响应（TCP DNS 消息前有2字节长度前缀）
	var subdomains []string
	seen := make(map[string]bool)

	for {
		// 读取长度前缀
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			break
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen == 0 || msgLen > 65535 {
			break
		}

		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			break
		}

		// 解析响应中的域名记录
		names := parseDNSResponseNames(msgBuf, domain)
		for _, name := range names {
			name = strings.ToLower(name)
			if !seen[name] && (name == domain || strings.HasSuffix(name, "."+domain)) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

// buildAXFRQuery 构造 DNS AXFR 查询包
func buildAXFRQuery(domain string) []byte {
	// TCP DNS 消息格式：2字节长度 + DNS 消息
	// DNS Header
	header := []byte{
		0x00, 0x01, // ID
		0x00, 0x00, // Flags: 标准查询
		0x00, 0x01, // QDCount: 1
		0x00, 0x00, // ANCount: 0
		0x00, 0x00, // NSCount: 0
		0x00, 0x00, // ARCount: 0
	}

	// QNAME: 域名编码
	qname := encodeDNSName(domain)

	// QTYPE: AXFR (252) + QCLASS: IN (1)
	qtype := []byte{0x00, 0xfc} // AXFR = 252
	qclass := []byte{0x00, 0x01} // IN = 1

	// 组合 DNS 消息
	dnsMsg := append(header, qname...)
	dnsMsg = append(dnsMsg, qtype...)
	dnsMsg = append(dnsMsg, qclass...)

	// TCP 长度前缀
	msgLen := len(dnsMsg)
	result := []byte{byte(msgLen >> 8), byte(msgLen)}
	result = append(result, dnsMsg...)

	return result
}

// encodeDNSName 将域名编码为 DNS 格式
func encodeDNSName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // 根标签
	return buf
}

// parseDNSResponseNames 从 DNS 响应中提取域名
func parseDNSResponseNames(msg []byte, originalDomain string) []string {
	var names []string
	if len(msg) < 12 {
		return names
	}

	// 跳过 header (12 bytes)
	offset := 12

	// 跳过 Question 部分
	qdCount := int(msg[4])<<8 | int(msg[5])
	for i := 0; i < qdCount && offset < len(msg); i++ {
		_, offset = readDNSName(msg, offset)
		offset += 4 // QTYPE + QCLASS
	}

	// 解析 Answer 部分
	anCount := int(msg[6])<<8 | int(msg[7])
	for i := 0; i < anCount && offset < len(msg); i++ {
		name, newOffset := readDNSName(msg, offset)
		offset = newOffset
		if offset+10 > len(msg) {
			break
		}
		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
		rdLength := int(msg[offset+8])<<8 | int(msg[offset+9])
		offset += 10 + rdLength

		if name != "" {
			names = append(names, name)
		}
	}

	return names
}

// readDNSName 从 DNS 消息中读取域名（处理压缩指针）
func readDNSName(msg []byte, offset int) (string, int) {
	var parts []string
	visited := make(map[int]bool)
	maxJumps := 10

	for {
		if offset >= len(msg) {
			break
		}
		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 == 0xc0 {
			// 压缩指针
			if offset+1 >= len(msg) {
				break
			}
			pointer := int(msg[offset]&0x3f)<<8 | int(msg[offset+1])
			if visited[pointer] {
				break // 防止循环
			}
			visited[pointer] = true
			if len(parts) == 0 {
				// 从指针位置读取名称
				name, _ := readDNSName(msg, pointer)
				return name, offset + 2
			}
			// 追加指针处的名称
			rest, _ := readDNSName(msg, pointer)
			parts = append(parts, rest)
			offset += 2
			break
		}
		if maxJumps <= 0 {
			break
		}
		maxJumps--
		if offset+1+length > len(msg) {
			break
		}
		parts = append(parts, string(msg[offset+1:offset+1+length]))
		offset += 1 + length
	}

	return strings.Join(parts, "."), offset
}

// bruteSubdomains 子域名爆破
func bruteSubdomains(ctx context.Context, domain, wordlistPath string, cfg *config.Config) []string {
	var subdomains []string

	// 读取字典文件
	file, err := os.Open(wordlistPath)
	if err != nil {
		log.Printf("[DomainScan] Failed to open wordlist %s: %v", wordlistPath, err)
		return subdomains
	}
	defer file.Close()

	// 读取所有字典条目
	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}

	if len(words) == 0 {
		return subdomains
	}

	// 并发解析子域名
	concurrency := 20
	if len(words) < concurrency {
		concurrency = len(words)
	}

	var mu sync.Mutex
	seen := make(map[string]bool)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	resolver := &net.Resolver{}

	for _, word := range words {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			subdomain := word + "." + domain
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			ips, err := resolver.LookupIPAddr(lookupCtx, subdomain)
			if err != nil {
				return // 不存在，跳过
			}
			if len(ips) > 0 {
				mu.Lock()
				if !seen[subdomain] {
					seen[subdomain] = true
					subdomains = append(subdomains, subdomain)
				}
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()

	if len(subdomains) > 0 {
		log.Printf("[DomainScan] Brute force found %d subdomains for %s", len(subdomains), domain)
	}
	return subdomains
}

// tlsCertSubdomains 从 TLS 证书中提取子域名（SAN 扩展）
func tlsCertSubdomains(host string, port int) []string {
	var subdomains []string
	addr := fmt.Sprintf("%s:%d", host, port)
	if port == 0 {
		addr = fmt.Sprintf("%s:443", host)
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return subdomains
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		for _, name := range cert.DNSNames {
			name = strings.ToLower(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" {
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains
}
