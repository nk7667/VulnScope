package handler

import (
	"vulnscope/internal/model"
	"vulnscope/internal/store"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type TemplateHandler struct {
	store *store.Store
	// 同步进度状态
	syncMu     sync.Mutex
	syncStatus *SyncStatus
}

type SyncStatus struct {
	Running     bool   `json:"running"`
	TotalFiles  int    `json:"total_files"`
	Processed   int    `json:"processed"`
	Synced      int    `json:"synced"`
	Skipped     int    `json:"skipped"`
	Failed      int    `json:"failed"`
	Phase       string `json:"phase"`       // downloading / scanning / done / error
	Message     string `json:"message"`
	StartTime   string `json:"start_time"`
	TemplateDir string `json:"template_dir"`
}

func NewTemplateHandler(s *store.Store) *TemplateHandler {
	return &TemplateHandler{store: s}
}

func (h *TemplateHandler) Create(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Content  string `json:"content" binding:"required"`
		Type     string `json:"type"`
		Tags     string `json:"tags"`
		Severity string `json:"severity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = "custom"
	}
	t := &model.Template{
		Name:     req.Name,
		Content:  req.Content,
		Type:     req.Type,
		Tags:     req.Tags,
		Severity: req.Severity,
		Enabled:  true,
	}
	if err := h.store.CreateTemplate(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (h *TemplateHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	keyword := c.Query("keyword")
	severity := c.Query("severity")
	templateType := c.Query("type")
	offset := (page - 1) * pageSize

	templates, total, err := h.store.ListTemplates(keyword, severity, templateType, offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": templates, "total": total, "page": page, "page_size": pageSize})
}

func (h *TemplateHandler) Delete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := h.store.DeleteTemplate(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// ClearAll 清空所有模板（用于重新同步）
func (h *TemplateHandler) ClearAll(c *gin.Context) {
	if err := h.store.ClearTemplates(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "all templates cleared"})
}

// SyncProgress 返回当前同步进度
func (h *TemplateHandler) SyncProgress(c *gin.Context) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()

	if h.syncStatus == nil {
		c.JSON(http.StatusOK, gin.H{"running": false})
		return
	}
	c.JSON(http.StatusOK, h.syncStatus)
}

// Sync 异步同步官方模板：1) nuclei -update-templates 下载  2) 扫描目录入库
func (h *TemplateHandler) Sync(c *gin.Context) {
	h.syncMu.Lock()
	if h.syncStatus != nil && h.syncStatus.Running {
		h.syncMu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "同步正在进行中，请等待完成"})
		return
	}
	h.syncStatus = &SyncStatus{
		Running:   true,
		Phase:     "downloading",
		Message:   "正在下载 nuclei 官方模板...",
		StartTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	h.syncMu.Unlock()

	// 异步执行
	go h.doSync()

	c.JSON(http.StatusOK, gin.H{"message": "同步已开始", "status_url": "/api/templates/sync/progress"})
}

func (h *TemplateHandler) doSync() {
	defer func() {
		h.syncMu.Lock()
		h.syncStatus.Running = false
		if h.syncStatus.Phase != "error" {
			h.syncStatus.Phase = "done"
			h.syncStatus.Message = fmt.Sprintf("同步完成！共处理 %d 个文件，入库 %d 个模板，跳过 %d 个，失败 %d 个",
				h.syncStatus.Processed, h.syncStatus.Synced, h.syncStatus.Skipped, h.syncStatus.Failed)
		}
		h.syncMu.Unlock()
	}()

	// 1. 执行 nuclei -update-templates 下载官方模板
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		h.setSyncError("nuclei 未安装，请先安装: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		return
	}

	h.updateSyncStatus(func(s *SyncStatus) {
		s.Phase = "downloading"
		s.Message = "正在执行 nuclei -update-templates 下载官方模板..."
	})

	cmd := exec.Command(nucleiPath, "-update-templates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.setSyncError(fmt.Sprintf("下载模板失败: %v, output: %s", err, string(output)))
		return
	}

	// 2. 找到 nuclei 模板目录
	templateDir, err := findNucleiTemplateDir(nucleiPath)
	if err != nil {
		h.setSyncError(fmt.Sprintf("找不到模板目录: %v", err))
		return
	}

	h.updateSyncStatus(func(s *SyncStatus) {
		s.TemplateDir = templateDir
		s.Phase = "scanning"
		s.Message = "正在扫描模板文件..."
	})

	// 3. 先统计文件总数
	var yamlFiles []string
	filepath.WalkDir(templateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})

	h.updateSyncStatus(func(s *SyncStatus) {
		s.TotalFiles = len(yamlFiles)
		s.Message = fmt.Sprintf("发现 %d 个 YAML 文件，正在解析入库...", len(yamlFiles))
	})

	// 4. 逐个解析入库
	for i, path := range yamlFiles {
		h.syncTemplatesFromFile(path, templateDir)

		// 每处理 50 个文件更新一次进度
		if (i+1)%50 == 0 || i+1 == len(yamlFiles) {
			h.updateSyncStatus(func(s *SyncStatus) {
				s.Processed = i + 1
				s.Message = fmt.Sprintf("正在解析: %d / %d", i+1, s.TotalFiles)
			})
		}
	}
}

func (h *TemplateHandler) syncTemplatesFromFile(path, baseDir string) {
	data, err := os.ReadFile(path)
	if err != nil {
		h.updateSyncStatus(func(s *SyncStatus) { s.Failed++ })
		return
	}

	relPath, _ := filepath.Rel(baseDir, path)
	category := filepath.Dir(relPath)
	if category == "." {
		category = ""
	}

	// 处理多文档 YAML（--- 分隔）
	docs := splitYAMLDocs(string(data))
	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}

		var tpl nucleiTemplateYAML
		if err := yaml.Unmarshal([]byte(doc), &tpl); err != nil {
			h.updateSyncStatus(func(s *SyncStatus) { s.Skipped++ })
			continue
		}

		// 跳过没有 id 和 name 的
		if tpl.ID == "" {
			h.updateSyncStatus(func(s *SyncStatus) { s.Skipped++ })
			continue
		}

		severity := tpl.Info.Severity
		tags := ""
		if tpl.Info.Tags != "" {
			tags = tpl.Info.Tags
		}
		if category != "" {
			if tags != "" {
				tags = category + "," + tags
			} else {
				tags = category
			}
		}

		name := tpl.Info.Name
		if name == "" {
			name = tpl.ID
		}

		cpe := tpl.Info.Classification.CPE
		if cpe == "" {
			cpe = tpl.inferCPEFromTags()
		}

		template := &model.Template{
			TemplateID: tpl.ID,
			Name:       name,
			Content:    doc,
			Type:       "official",
			Category:   tpl.getCategory(relPath),
			Protocol:   tpl.getProtocol(),
			CPE:        cpe,
			Tags:       tags,
			Severity:   severity,
			FilePath:   relPath,
			Enabled:    true,
		}

		if err := h.store.UpsertTemplate(template); err != nil {
			h.updateSyncStatus(func(s *SyncStatus) { s.Failed++ })
			continue
		}
		h.updateSyncStatus(func(s *SyncStatus) { s.Synced++ })
	}
}

// splitYAMLDocs 按 --- 分隔多文档 YAML
func splitYAMLDocs(content string) []string {
	var docs []string
	parts := strings.Split(content, "\n---")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			docs = append(docs, part)
		}
	}
	return docs
}

func (h *TemplateHandler) updateSyncStatus(fn func(*SyncStatus)) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	if h.syncStatus != nil {
		fn(h.syncStatus)
	}
}

func (h *TemplateHandler) setSyncError(msg string) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	if h.syncStatus != nil {
		h.syncStatus.Running = false
		h.syncStatus.Phase = "error"
		h.syncStatus.Message = msg
	}
}

// findNucleiTemplateDir 获取 nuclei 模板目录
func findNucleiTemplateDir(nucleiPath string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	defaultDir := filepath.Join(homeDir, "nuclei-templates")
	if _, err := os.Stat(defaultDir); err == nil {
		return defaultDir, nil
	}
	return "", fmt.Errorf("模板目录不存在: %s", defaultDir)
}

// ImportRepo 从第三方 Git 仓库导入模板
func (h *TemplateHandler) ImportRepo(c *gin.Context) {
	var req struct {
		RepoURL string `json:"repo_url" binding:"required"`
		Name    string `json:"name"` // 自定义库名称，用于标记来源
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 安全校验：只允许 https:// 开头的 Git 仓库 URL
	if !strings.HasPrefix(req.RepoURL, "https://") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "仓库 URL 必须以 https:// 开头，不支持 file://、git:// 或 SSH 协议"})
		return
	}
	// 防止 URL 中包含命令注入字符
	if strings.ContainsAny(req.RepoURL, "|&;$`\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "仓库 URL 包含非法字符"})
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "git 未安装，请先安装 git"})
		return
	}

	// 克隆到临时目录
	homeDir, _ := os.UserHomeDir()
	repoDir := filepath.Join(homeDir, ".nuclei-custom-templates")
	if req.Name != "" {
		repoDir = filepath.Join(repoDir, req.Name)
	} else {
		// 从 URL 提取仓库名
		parts := strings.Split(strings.TrimSuffix(req.RepoURL, "/"), "/")
		repoName := parts[len(parts)-1]
		repoName = strings.TrimSuffix(repoName, ".git")
		repoDir = filepath.Join(repoDir, repoName)
	}

	// 如果目录已存在，先删除
	os.RemoveAll(repoDir)

	cmd := exec.Command("git", "clone", "--depth", "1", req.RepoURL, repoDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("克隆仓库失败: %v, %s", err, string(output))})
		return
	}

	// 扫描目录中的 YAML 文件入库
	synced, skipped, failed := h.importFromDir(repoDir, "thirdparty")

	c.JSON(http.StatusOK, gin.H{
		"message":  fmt.Sprintf("导入完成！入库 %d 个模板，跳过 %d 个，失败 %d 个", synced, skipped, failed),
		"synced":   synced,
		"skipped":  skipped,
		"failed":   failed,
		"repo_dir": repoDir,
	})
}

// ImportDir 从本地目录导入模板
func (h *TemplateHandler) ImportDir(c *gin.Context) {
	var req struct {
		DirPath string `json:"dir_path" binding:"required"`
		Name    string `json:"name"` // 自定义来源标记
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 安全校验：限制可导入的目录范围，防止路径遍历读取敏感文件
	absPath, err := filepath.Abs(req.DirPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "路径格式无效"})
		return
	}
	// 禁止导入系统敏感目录
	blockedPrefixes := []string{"/etc", "/root", "/home", "/var", "/usr", "/boot", "/proc", "/sys", "/dev",
		`C:\Windows`, `C:\Users`, `C:\Program Files`}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(absPath, prefix) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("不允许导入系统目录: %s", req.DirPath)})
			return
		}
	}

	// 检查目录是否存在
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("目录不存在: %s", req.DirPath)})
		return
	}

	templateType := "thirdparty"
	if req.Name != "" {
		templateType = req.Name
	}

	synced, skipped, failed := h.importFromDir(absPath, templateType)

	c.JSON(http.StatusOK, gin.H{
		"message":  fmt.Sprintf("导入完成！入库 %d 个模板，跳过 %d 个，失败 %d 个", synced, skipped, failed),
		"synced":   synced,
		"skipped":  skipped,
		"failed":   failed,
		"dir_path": req.DirPath,
	})
}

// importFromDir 从指定目录扫描 YAML 文件并入库
func (h *TemplateHandler) importFromDir(dir, templateType string) (synced, skipped, failed int) {
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			failed++
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		category := filepath.Dir(relPath)
		if category == "." {
			category = ""
		}

		docs := splitYAMLDocs(string(data))
		for _, doc := range docs {
			if strings.TrimSpace(doc) == "" {
				continue
			}

			var tpl nucleiTemplateYAML
			if err := yaml.Unmarshal([]byte(doc), &tpl); err != nil {
				skipped++
				continue
			}
			if tpl.ID == "" {
				skipped++
				continue
			}

			tags := tpl.Info.Tags
			if category != "" {
				if tags != "" {
					tags = category + "," + tags
				} else {
					tags = category
				}
			}

			templateName := tpl.Info.Name
			if templateName == "" {
				templateName = tpl.ID
			}

			cpe := tpl.Info.Classification.CPE
			if cpe == "" {
				cpe = tpl.inferCPEFromTags()
			}

			template := &model.Template{
				TemplateID: tpl.ID,
				Name:       templateName,
				Content:    doc,
				Type:       templateType,
				Category:   tpl.getCategory(relPath),
				Protocol:   tpl.getProtocol(),
				CPE:        cpe,
				Tags:       tags,
				Severity:   tpl.Info.Severity,
				FilePath:   relPath,
				Enabled:    true,
			}

			if err := h.store.UpsertTemplate(template); err != nil {
				failed++
				continue
			}
			synced++
		}
		return nil
	})
	return
}

// nucleiTemplateYAML nuclei 模板 YAML 结构
type nucleiTemplateYAML struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Severity       string `yaml:"severity"`
		Tags           string `yaml:"tags"`
		Remediation    string `yaml:"remediation"`
		Classification struct {
			CPE string `yaml:"cpe"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP   interface{} `yaml:"http"`
	TCP    interface{} `yaml:"tcp"`
	DNS    interface{} `yaml:"dns"`
	SSL    interface{} `yaml:"ssl"`
	UDP    interface{} `yaml:"udp"`
}

// getProtocol 从模板 YAML 结构推断协议类型
func (t *nucleiTemplateYAML) getProtocol() string {
	if t.TCP != nil {
		return "tcp"
	}
	if t.DNS != nil {
		return "dns"
	}
	if t.SSL != nil {
		return "ssl"
	}
	if t.UDP != nil {
		return "udp"
	}
	if t.HTTP != nil {
		return "http"
	}
	return ""
}

// getCategory 从模板路径和内容推断分类（finger/vuln）
func (t *nucleiTemplateYAML) getCategory(relPath string) string {
	lower := strings.ToLower(relPath)
	// 指纹模板：technologies、detection 目录
	if strings.Contains(lower, "technologies") ||
		strings.Contains(lower, "/detection/") ||
		strings.Contains(lower, "\\detection\\") ||
		strings.Contains(lower, "/enumerate") ||
		strings.Contains(lower, "\\enumerate") {
		return "finger"
	}
	// 漏洞模板：cves、vulnerabilities、misconfig、exposures、default-login 等
	if strings.Contains(lower, "cves") ||
		strings.Contains(lower, "vulnerabilities") ||
		strings.Contains(lower, "misconfig") ||
		strings.Contains(lower, "exposures") ||
		strings.Contains(lower, "default-login") ||
		strings.Contains(lower, "backdoor") ||
		strings.Contains(lower, "c2") ||
		strings.Contains(lower, "token-spray") {
		return "vuln"
	}
	// 根据 severity 判断：info 级别且无 CPE 的可能是指纹
	if t.Info.Severity == "info" && t.Info.Classification.CPE == "" {
		return "finger"
	}
	return "vuln"
}

// inferCPEFromTags 从模板 tags 推断 CPE（用于模板本身没有 CPE 的情况）
// tags 格式如 "accellion,tech,detect" → 提取 "accellion" → cpe:2.3:a:accellion:accellion:*
func (t *nucleiTemplateYAML) inferCPEFromTags() string {
	if t.Info.Tags == "" {
		return ""
	}

	// 通用标签，不是产品名
	genericTags := map[string]bool{
		"tech": true, "detect": true, "detection": true, "fingerprint": true,
		"login": true, "panel": true, "exposure": true, "misconfig": true,
		"enum": true, "bruteforce": true, "redirect": true, "xss": true,
		"sqli": true, "rce": true, "lfi": true, "rfi": true, "ssrf": true,
		"csrf": true, "xxe": true, "injection": true, "overflow": true,
		"traversal": true, "bypass": true, "disclosure": true, "cve": true,
		"info": true, "unauth": true, "default": true, "backup": true,
		"upload": true, "download": true, "fileupload": true, "token": true,
		"api": true, "debug": true, "error": true, "config": true,
		"install": true, "setup": true, "wizard": true, "console": true,
		"manager": true, "admin": true, "dashboard": true, "monitor": true,
		"status": true, "health": true, "version": true, "swagger": true, "wp": true, "joomla": true, "drupal": true, "magento": true,
		"wordpress": true, "shopify": true, "prestashop": true,
		"http": true, "network": true, "ssl": true, "dns": true,
		"headless": true, "interactive": true,
		"waf": true, "firewall": true, "proxy": true, // 非产品标签，不应生成CPE
	}

	parts := strings.Split(t.Info.Tags, ",")
	for _, part := range parts {
		tag := strings.TrimSpace(strings.ToLower(part))
		if tag == "" || genericTags[tag] || len(tag) < 2 {
			continue
		}
		// 第一个非通用标签作为产品名
		return fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", tag, tag)
	}
	return ""
}
