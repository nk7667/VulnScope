package scanner

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"context"
	"net"
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

	for _, target := range targets {
		host, port := parseTarget(target)

		// 判断是域名还是IP
		if net.ParseIP(host) != nil {
			// 已经是IP，直接添加
			results = append(results, DomainResult{IP: host, Port: port})
			continue
		}

		// DNS解析
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			results = append(results, DomainResult{
				IP:     ip.IP.String(),
				Port:   port,
				Domain: host,
			})
		}

		// CNAME查询
		cname, _ := net.DefaultResolver.LookupCNAME(ctx, host)
		if cname != "" && cname != host+"." {
			// 更新最后一条结果的CNAME
			if len(results) > 0 {
				results[len(results)-1].CNAME = cname
			}
		}
	}

	return results, nil
}
