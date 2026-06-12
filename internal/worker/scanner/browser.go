package scanner

import (
	"vulnscope/internal/config"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

// BrowserResult 浏览器渲染结果
type BrowserResult struct {
	URL          string
	Title        string
	HTML         string
	Headers      map[string]string
	StatusCode   int
	JSErrors     []string
	Cookies      []string
	Technologies []string // 通过 JS 检测到的技术栈
}

var (
	browserInstance *rod.Browser
	browserMu       sync.Mutex // 保护浏览器初始化和重试
	browserSem      = make(chan struct{}, 3) // 最多 3 个并发浏览器操作
	browserReady    bool                     // 浏览器是否成功初始化
)

// getBrowser 获取或初始化浏览器实例（支持重试）
func getBrowser(cfg *config.Config) (*rod.Browser, error) {
	browserMu.Lock()
	defer browserMu.Unlock()

	// 已成功初始化，直接返回
	if browserReady && browserInstance != nil {
		return browserInstance, nil
	}

	// 配置 launcher
	l := launcher.New()
	l = l.Headless(true)

	// 如果配置了 Chrome 路径
	if cfg.Scanner.ChromePath != "" {
		l = l.Bin(cfg.Scanner.ChromePath)
	}

	// 沙箱参数
	l = l.NoSandbox(true)

	// 启动浏览器
	uri, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("启动 Chrome 浏览器失败: %v", err)
	}

	browserInstance = rod.New().ControlURL(uri)
	if err := browserInstance.Connect(); err != nil {
		browserInstance = nil
		return nil, fmt.Errorf("连接 Chrome 浏览器失败: %v", err)
	}

	browserReady = true
	log.Printf("[Browser] Chrome 无头浏览器已启动")
	return browserInstance, nil
}

// BrowserRender 使用 Chrome 无头浏览器渲染页面
// 用于需要 JS 执行的指纹识别和漏洞扫描
func BrowserRender(ctx context.Context, url string, cfg *config.Config) (*BrowserResult, error) {
	browserSem <- struct{}{} // 获取信号量
	defer func() { <-browserSem }()

	b, err := getBrowser(cfg)
	if err != nil {
		return nil, err
	}

	// 设置超时
	timeout := 30 * time.Second
	if cfg.Scanner.FingerTimeout > 0 {
		timeout = time.Duration(cfg.Scanner.FingerTimeout) * time.Second
	}

	page, err := b.Page(proto.TargetCreateTarget{URL: url})
	if err != nil {
		return nil, fmt.Errorf("打开页面失败: %v", err)
	}
	defer page.Close()

	// 设置页面超时
	page = page.Timeout(timeout)

	// 等待网络空闲
	page.WaitIdle(5 * time.Second)

	result := &BrowserResult{URL: url}

	// 获取页面标题
	info, _ := page.Info()
	if info != nil {
		result.Title = info.Title
	}

	// 获取 HTML
	html, err := page.HTML()
	if err == nil {
		result.HTML = html
	}

	// 收集 JS 错误
	jsErrorsVal, _ := page.Eval(`() => window.__jsErrors || []`)
	if jsErrorsVal != nil {
		arr := jsErrorsVal.Value.Arr()
		for _, e := range arr {
			result.JSErrors = append(result.JSErrors, fmt.Sprintf("%v", e))
		}
	}

	// 获取 Cookies
	cookies, err := page.Cookies([]string{url})
	if err == nil {
		for _, c := range cookies {
			result.Cookies = append(result.Cookies, c.Name+"="+c.Value)
		}
	}

	// 检测技术栈（通过 JS 全局变量）
	technologies := detectTechnologies(page)
	result.Technologies = technologies

	return result, nil
}

// detectTechnologies 通过 JS 全局变量检测技术栈
func detectTechnologies(page *rod.Page) []string {
	// 常见前端框架/库的全局变量检测
	detectScript := `() => {
		var techs = [];
		if (window.jQuery) techs.push('jQuery');
		if (window.React) techs.push('React');
		if (window.Vue) techs.push('Vue');
		if (window.angular) techs.push('AngularJS');
		if (window.ng && window.ng.coreTokens) techs.push('Angular');
		if (window.__NEXT_DATA__) techs.push('Next.js');
		if (window.__NUXT__) techs.push('Nuxt.js');
		if (window.__SVELTE__) techs.push('Svelte');
		if (window.Ember) techs.push('Ember.js');
		if (window.Backbone) techs.push('Backbone.js');
		if (window.Meteor) techs.push('Meteor');
		if (window.Zepto) techs.push('Zepto');
		if (window.Lodash) techs.push('Lodash');
		if (window._ && window._.VERSION) techs.push('Underscore.js');
		if (window.bootstrap) techs.push('Bootstrap');
		if (window.Foundation) techs.push('Foundation');
		if (window.Axios) techs.push('Axios');
		if (window.SwaggerUIBundle) techs.push('Swagger');
		if (window.Drupal) techs.push('Drupal');
		if (window.wp) techs.push('WordPress');
		if (window.joomla) techs.push('Joomla');
		return techs;
	}`

	result, err := page.Eval(detectScript)
	if err != nil {
		return nil
	}

	var techs []string
	arr := result.Value.Arr()
	for _, t := range arr {
		techs = append(techs, fmt.Sprintf("%v", t))
	}
	return techs
}

// BrowserFingerScan 使用浏览器进行指纹扫描
// 对 HTTP 探测无法识别的服务，使用浏览器渲染获取更详细的指纹
func BrowserFingerScan(ctx context.Context, targets []string, cfg *config.Config) ([]BrowserResult, error) {
	var results []BrowserResult

	for _, target := range targets {
		// 确保有协议前缀
		url := target
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}

		result, err := BrowserRender(ctx, url, cfg)
		if err != nil {
			log.Printf("[BrowserFinger] Failed to render %s: %v", url, err)
			continue
		}

		if result != nil {
			results = append(results, *result)
		}
	}

	return results, nil
}

// IsBrowserAvailable 检查浏览器是否可用
func IsBrowserAvailable(cfg *config.Config) bool {
	_, err := getBrowser(cfg)
	return err == nil
}

// CloseBrowser 关闭浏览器实例
func CloseBrowser() {
	browserMu.Lock()
	defer browserMu.Unlock()
	if browserInstance != nil {
		browserInstance.Close()
		browserInstance = nil
		browserReady = false
	}
}

// GetPageDOM 获取页面的 DOM 信息（用于深度指纹识别）
func GetPageDOM(ctx context.Context, url string, cfg *config.Config) (map[string]string, error) {
	browserSem <- struct{}{} // 获取信号量
	defer func() { <-browserSem }()

	b, err := getBrowser(cfg)
	if err != nil {
		return nil, err
	}

	page, err := b.Page(proto.TargetCreateTarget{URL: url})
	if err != nil {
		return nil, fmt.Errorf("打开页面失败: %v", err)
	}
	defer page.Close()

	page = page.Timeout(30 * time.Second)
	page.WaitIdle(5 * time.Second)

	// 提取页面元信息
	domScript := `() => {
		var info = {};
		var metas = document.querySelectorAll('meta');
		metas.forEach(function(m) {
			var name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
			var content = m.getAttribute('content');
			if (name && content) info[name] = content;
		});
		var gen = document.querySelector('meta[name="generator"]');
		if (gen) info['generator'] = gen.getAttribute('content');
		return info;
	}`

	result, err := page.Eval(domScript)
	if err != nil {
		return nil, err
	}

	domInfo := make(map[string]string)
	m := result.Value.Map()
	for k, v := range m {
		domInfo[k] = fmt.Sprintf("%v", v)
	}

	return domInfo, nil
}

// NavigateWithHeaders 使用自定义 Headers 导航
func NavigateWithHeaders(ctx context.Context, url string, headers map[string]string, cfg *config.Config) (*BrowserResult, error) {
	browserSem <- struct{}{} // 获取信号量
	defer func() { <-browserSem }()

	b, err := getBrowser(cfg)
	if err != nil {
		return nil, err
	}

	page, err := b.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, fmt.Errorf("创建页面失败: %v", err)
	}
	defer page.Close()

	page = page.Timeout(30 * time.Second)

	// 设置自定义 Headers
	if len(headers) > 0 {
		h := proto.NetworkHeaders{}
		for k, v := range headers {
			h[k] = gson.New(v)
		}
		proto.NetworkSetExtraHTTPHeaders{Headers: h}.Call(page)
	}

	// 导航到目标
	if err := page.Navigate(url); err != nil {
		return nil, err
	}

	page.WaitIdle(5 * time.Second)

	result := &BrowserResult{URL: url}

	info, _ := page.Info()
	if info != nil {
		result.Title = info.Title
	}

	html, err := page.HTML()
	if err == nil {
		result.HTML = html
	}

	technologies := detectTechnologies(page)
	result.Technologies = technologies

	return result, nil
}
