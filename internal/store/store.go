package store

import (
	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"log"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Store struct {
	DB *gorm.DB
}

func New(cfg *config.DBConfig) (*Store, error) {
	var db *gorm.DB
	var err error

	switch cfg.Driver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	case "mysql":
		db, err = gorm.Open(mysql.Open(cfg.DSN), &gorm.Config{})
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.DSN), &gorm.Config{})
	default:
		db, err = gorm.Open(mysql.Open(cfg.DSN), &gorm.Config{})
	}

	if err != nil {
		return nil, err
	}

	// 配置连接池参数，防止高并发下连接耗尽
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxIdleConns(10)           // 空闲连接池最大连接数
	sqlDB.SetMaxOpenConns(100)          // 数据库最大打开连接数
	sqlDB.SetConnMaxLifetime(time.Hour) // 连接最大存活时间，避免长时间复用导致的问题

	// 自动迁移
	if err := db.AutoMigrate(
		&model.Target{},
		&model.Task{},
		&model.Asset{},
		&model.Port{},
		&model.Finger{},
		&model.Vuln{},
		&model.Template{},
		&model.Config{},
		&model.TaskLog{},
	); err != nil {
		return nil, err
	}

	return &Store{DB: db}, nil
}

// ========== Target ==========

func (s *Store) CreateTarget(t *model.Target) error {
	// 去重：如果 target 字符串已存在，返回已有记录
	var existing model.Target
	if err := s.DB.Where("target = ?", t.Target).First(&existing).Error; err == nil {
		// 已存在，更新 ID 指向已有记录
		t.ID = existing.ID
		t.CreatedAt = existing.CreatedAt
		t.UpdatedAt = existing.UpdatedAt
		return nil
	}
	return s.DB.Create(t).Error
}

func (s *Store) ListTargets(offset, limit int) ([]model.Target, int64, error) {
	var targets []model.Target
	var total int64
	s.DB.Model(&model.Target{}).Count(&total)
	err := s.DB.Offset(offset).Limit(limit).Order("id DESC").Find(&targets).Error
	return targets, total, err
}

func (s *Store) GetTarget(id uint) (*model.Target, error) {
	var t model.Target
	err := s.DB.First(&t, id).Error
	return &t, err
}

func (s *Store) DeleteTarget(id uint) error {
	return s.DB.Delete(&model.Target{}, id).Error
}

func (s *Store) GetTargetsByIDs(ids []uint) ([]model.Target, error) {
	var targets []model.Target
	err := s.DB.Where("id IN ?", ids).Find(&targets).Error
	return targets, err
}

// ========== Task ==========

func (s *Store) CreateTask(t *model.Task) error {
	return s.DB.Create(t).Error
}

func (s *Store) ListTasks(offset, limit int) ([]model.Task, int64, error) {
	var tasks []model.Task
	var total int64
	s.DB.Model(&model.Task{}).Count(&total)
	err := s.DB.Offset(offset).Limit(limit).Order("id DESC").Find(&tasks).Error
	return tasks, total, err
}

func (s *Store) GetTask(id uint) (*model.Task, error) {
	var t model.Task
	err := s.DB.First(&t, id).Error
	return &t, err
}

func (s *Store) UpdateTask(t *model.Task) error {
	return s.DB.Save(t).Error
}

func (s *Store) DeleteTask(id uint) error {
	return s.DB.Delete(&model.Task{}, id).Error
}

// ========== Asset ==========

func (s *Store) CreateAsset(a *model.Asset) error {
	// 同一任务内按 IP+域名 去重，已存在则更新
	var existing model.Asset
	q := s.DB.Where("task_id = ?", a.TaskID)
	if a.IP != "" && a.Domain != "" {
		q = q.Where("ip = ? AND domain = ?", a.IP, a.Domain)
	} else if a.IP != "" {
		q = q.Where("ip = ? AND (domain = '' OR domain IS NULL)", a.IP)
	} else if a.Domain != "" {
		q = q.Where("domain = ? AND (ip = '' OR ip IS NULL)", a.Domain)
	} else {
		return s.DB.Create(a).Error
	}

	err := q.First(&existing).Error
	if err == gorm.ErrRecordNotFound {
		return s.DB.Create(a).Error
	}
	if err != nil {
		return err
	}
	// 更新已有记录
	if a.Alive {
		existing.Alive = true
	}
	if a.StatusCode > 0 {
		existing.StatusCode = a.StatusCode
	}
	if a.ResponseTime > 0 {
		existing.ResponseTime = a.ResponseTime
	}
	if a.Title != "" {
		existing.Title = a.Title
	}
	if a.RedirectURL != "" {
		existing.RedirectURL = a.RedirectURL
	}
	return s.DB.Save(&existing).Error
}

func (s *Store) ListAssets(taskID uint, offset, limit int) ([]model.Asset, int64, error) {
	var assets []model.Asset
	var total int64
	q := s.DB.Model(&model.Asset{})
	if taskID > 0 {
		q = q.Where("task_id = ?", taskID)
	}
	q.Count(&total)
	err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&assets).Error
	return assets, total, err
}

// ListAssetsDedup 去重资产列表（跨任务合并相同 IP/域名）
func (s *Store) ListAssetsDedup(offset, limit int) ([]model.AssetDedup, int64, error) {
	var results []model.AssetDedup
	var total int64

	// 使用 GORM 子查询构建，避免 Raw SQL 注入风险
	dedupKey := "COALESCE(NULLIF(ip,''), domain)"

	// 统计去重后的总数
	countSub := s.DB.Model(&model.Asset{}).
		Select(dedupKey+" AS key_val").
		Where("ip != '' OR domain != ''").
		Group(dedupKey)
	s.DB.Table("(?) AS sub", countSub).Count(&total)

	// 主查询：使用 GORM 子查询构建
	// 内层子查询：按 dedup_key 分组聚合
	innerSub := s.DB.Model(&model.Asset{}).
		Select(
			"MAX(id) AS id",
			dedupKey+" AS dedup_key",
			"MAX(ip) AS ip",
			"MAX(domain) AS domain",
			"MAX(CASE WHEN alive THEN 1 ELSE 0 END) AS alive",
			"MAX(status_code) AS status_code",
			"MIN(response_time) AS response_time",
			"MAX(title) AS title",
			"COUNT(DISTINCT id) AS task_count",
		).
		Where("ip != '' OR domain != ''").
		Group(dedupKey).
		Order("MAX(id) DESC").
		Limit(limit).
		Offset(offset)

	// 端口计数子查询
	portSub := s.DB.Table("assets").
		Select(dedupKey+" AS dedup_key, COUNT(DISTINCT ports.id) AS port_count").
		Joins("JOIN ports ON ports.asset_id = assets.id").
		Where("ip != '' OR domain != ''").
		Group(dedupKey)

	// 指纹计数子查询
	fingerSub := s.DB.Table("assets").
		Select(dedupKey+" AS dedup_key, COUNT(DISTINCT fingers.id) AS finger_count").
		Joins("JOIN fingers ON fingers.asset_id = assets.id").
		Where("ip != '' OR domain != ''").
		Group(dedupKey)

	// 组合查询
	err := s.DB.Table("(?) AS sub", innerSub).
		Select("sub.id, sub.ip, sub.domain, sub.alive, sub.status_code, sub.response_time, sub.title, sub.task_count, "+
			"COALESCE(p.port_count, 0) AS port_count, COALESCE(f.finger_count, 0) AS finger_count").
		Joins("LEFT JOIN (?) AS p ON p.dedup_key = sub.dedup_key", portSub).
		Joins("LEFT JOIN (?) AS f ON f.dedup_key = sub.dedup_key", fingerSub).
		Scan(&results).Error

	return results, total, err
}

func (s *Store) GetAsset(id uint) (*model.Asset, error) {
	var a model.Asset
	err := s.DB.First(&a, id).Error
	return &a, err
}

// ========== Port ==========

func (s *Store) CreatePort(p *model.Port) error {
	// 同一资产内按 端口+协议 去重
	var existing model.Port
	err := s.DB.Where("asset_id = ? AND port = ? AND protocol = ?", p.AssetID, p.Port, p.Protocol).First(&existing).Error
	if err == nil {
		// 已存在，更新服务信息
		if p.Service != "" && p.Service != "unknown" {
			existing.Service = p.Service
		}
		if p.Version != "" {
			existing.Version = p.Version
		}
		if p.State != "" {
			existing.State = p.State
		}
		return s.DB.Save(&existing).Error
	}
	return s.DB.Create(p).Error
}

func (s *Store) CreatePorts(ports []model.Port) error {
	return s.DB.Create(&ports).Error
}

func (s *Store) ListPorts(assetID uint) ([]model.Port, error) {
	var ports []model.Port
	err := s.DB.Where("asset_id = ?", assetID).Find(&ports).Error
	return ports, err
}

// ========== Finger ==========

func (s *Store) CreateFinger(f *model.Finger) error {
	// 同一资产内按 名称+分类 去重
	var existing model.Finger
	err := s.DB.Where("asset_id = ? AND name = ? AND category = ?", f.AssetID, f.Name, f.Category).First(&existing).Error
	if err == nil {
		if f.Version != "" {
			existing.Version = f.Version
		}
		if f.Detail != "" {
			existing.Detail = f.Detail
		}
		return s.DB.Save(&existing).Error
	}
	return s.DB.Create(f).Error
}

func (s *Store) CreateFingers(fingers []model.Finger) error {
	return s.DB.Create(&fingers).Error
}

func (s *Store) ListFingers(assetID uint) ([]model.Finger, error) {
	var fingers []model.Finger
	err := s.DB.Where("asset_id = ?", assetID).Find(&fingers).Error
	return fingers, err
}

// ========== Vuln ==========

func (s *Store) CreateVuln(v *model.Vuln) error {
	// 去重：同一任务+同一模板+同一URL 不重复插入
	var existing model.Vuln
	err := s.DB.Where("task_id = ? AND template_id = ? AND url = ?", v.TaskID, v.TemplateID, v.URL).First(&existing).Error
	if err == nil {
		// 已存在，更新严重级别和证据
		if v.Severity != "" {
			existing.Severity = v.Severity
		}
		if v.Evidence != "" {
			existing.Evidence = v.Evidence
		}
		return s.DB.Save(&existing).Error
	}
	return s.DB.Create(v).Error
}

func (s *Store) CreateVulns(vulns []model.Vuln) error {
	return s.DB.Create(&vulns).Error
}

func (s *Store) ListVulns(taskID uint, severity, status string, offset, limit int) ([]model.Vuln, int64, error) {
	var vulns []model.Vuln
	var total int64
	q := s.DB.Model(&model.Vuln{})
	if taskID > 0 {
		q = q.Where("task_id = ?", taskID)
	}
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	q.Count(&total)
	err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&vulns).Error
	return vulns, total, err
}

func (s *Store) GetVuln(id uint) (*model.Vuln, error) {
	var v model.Vuln
	err := s.DB.First(&v, id).Error
	return &v, err
}

func (s *Store) UpdateVuln(v *model.Vuln) error {
	return s.DB.Save(v).Error
}

// CountVulnsByTask 统计任务的漏洞数量
func (s *Store) CountVulnsByTask(taskID uint) (int, error) {
	var count int64
	err := s.DB.Model(&model.Vuln{}).Where("task_id = ?", taskID).Count(&count).Error
	return int(count), err
}

// CountFingersByTask 统计任务的指纹数量
func (s *Store) CountFingersByTask(taskID uint) (int, error) {
	var count int64
	// 通过 assets 表关联查询
	err := s.DB.Model(&model.Finger{}).
		Joins("JOIN assets ON assets.id = fingers.asset_id").
		Where("assets.task_id = ?", taskID).
		Count(&count).Error
	return int(count), err
}

// ========== Template ==========

func (s *Store) CreateTemplate(t *model.Template) error {
	return s.DB.Create(t).Error
}

func (s *Store) ListTemplates(keyword, severity, templateType string, offset, limit int) ([]model.Template, int64, error) {
	var templates []model.Template
	var total int64
	q := s.DB.Model(&model.Template{})
	if keyword != "" {
		q = q.Where("name LIKE ? OR tags LIKE ? OR template_id LIKE ?", "%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if templateType != "" {
		q = q.Where("type = ? OR category = ?", templateType, templateType)
	}
	q.Count(&total)
	err := q.Offset(offset).Limit(limit).Order("CASE WHEN severity = '' THEN 1 ELSE 0 END, severity DESC, id DESC").Find(&templates).Error
	return templates, total, err
}

func (s *Store) DeleteTemplate(id uint) error {
	return s.DB.Delete(&model.Template{}, id).Error
}

func (s *Store) ClearTemplates() error {
	return s.DB.Exec("DELETE FROM templates").Error
}

func (s *Store) UpsertTemplate(t *model.Template) error {
	var existing model.Template
	err := s.DB.Where("template_id = ?", t.TemplateID).First(&existing).Error
	if err == gorm.ErrRecordNotFound {
		return s.DB.Create(t).Error
	}
	if err != nil {
		return err
	}
	existing.Name = t.Name
	existing.Content = t.Content
	existing.Severity = t.Severity
	existing.Tags = t.Tags
	existing.Category = t.Category
	existing.Protocol = t.Protocol
	existing.CPE = t.CPE
	existing.FilePath = t.FilePath
	existing.Enabled = true
	return s.DB.Save(&existing).Error
}

func (s *Store) CountTemplatesByType(templateType string) int64 {
	var count int64
	s.DB.Model(&model.Template{}).Where("type = ?", templateType).Count(&count)
	return count
}

// GetEnabledFingerTemplates 获取已启用的指纹模板
func (s *Store) GetEnabledFingerTemplates(protocol string) ([]model.Template, error) {
	var templates []model.Template
	q := s.DB.Where("enabled = ? AND category = ?", true, "finger")
	if protocol != "" {
		q = q.Where("protocol = ?", protocol)
	}
	err := q.Find(&templates).Error
	return templates, err
}

// GetMatchedVulnTemplates 根据资产的 CPE 和 Service 匹配漏洞模板
func (s *Store) GetMatchedVulnTemplates(cpe, service string) ([]model.Template, error) {
	var templates []model.Template
	// 获取所有已启用的漏洞模板
	var allVulnTemplates []model.Template
	if err := s.DB.Where("enabled = ? AND category = ?", true, "vuln").Find(&allVulnTemplates).Error; err != nil {
		return nil, err
	}

	for _, tpl := range allVulnTemplates {
		if matchTemplate(tpl, cpe, service) {
			templates = append(templates, tpl)
		}
	}
	return templates, nil
}

// matchTemplate 模板匹配逻辑
// 匹配策略：
// 1. 模板有CPE且资产有CPE → CPE精确匹配（vendor:product一致）
// 2. 模板没有CPE → 按service/protocol匹配（兜底，确保不漏掉通用漏洞模板）
// 3. 模板有CPE但资产没有CPE → 不匹配（无法确定关联性）
func matchTemplate(tpl model.Template, assetCPE, assetService string) bool {
	tplCPE := tpl.CPE
	tplProtocol := tpl.Protocol

	// 模板有 CPE 且资产有 CPE → CPE 精确匹配
	if tplCPE != "" && assetCPE != "" {
		return cpeMatch(tplCPE, assetCPE)
	}

	// 模板有 CPE 但资产没有 CPE → 不匹配
	if tplCPE != "" && assetCPE == "" {
		return false
	}

	// 模板没有 CPE → 按 service/protocol 匹配（兜底）
	// 即使资产有 CPE，无 CPE 的通用漏洞模板也应按协议匹配
	return protocolMatch(tplProtocol, assetService)
}

// cpeMatch CPE 匹配（使用 go-cpe 库进行正规 WFN 匹配）
// 支持通配符、版本范围等复杂场景
func cpeMatch(tplCPE, assetCPE string) bool {
	// 尝试解析 CPE 为 WFN 格式
	// CPE 2.3 格式: cpe:2.3:a:vendor:product:version:...
	// URI 格式: cpe:/a:vendor:product:version:...
	tplWFN, err := parseCPE(tplCPE)
	if err != nil {
		log.Printf("[CPE] Failed to parse template CPE %q: %v, falling back to string compare", tplCPE, err)
		return cpeMatchFallback(tplCPE, assetCPE)
	}

	assetWFN, err := parseCPE(assetCPE)
	if err != nil {
		log.Printf("[CPE] Failed to parse asset CPE %q: %v, falling back to string compare", assetCPE, err)
		return cpeMatchFallback(tplCPE, assetCPE)
	}

	// 使用 go-cpe 的 IsSuperset/IsSubset/IsEqual 判断匹配关系
	// IsSuperset: 模板 CPE 的范围是否覆盖资产 CPE（如通配符版本匹配具体版本）
	if matching.IsSuperset(tplWFN, assetWFN) {
		return true
	}
	// IsSubset: 资产 CPE 的范围是否覆盖模板 CPE
	if matching.IsSubset(tplWFN, assetWFN) {
		return true
	}
	// IsEqual: 完全相等
	if matching.IsEqual(tplWFN, assetWFN) {
		return true
	}

	return false
}

// parseCPE 解析 CPE 字符串为 WFN
func parseCPE(cpeStr string) (common.WellFormedName, error) {
	// 判断 CPE 格式：2.3 格式以 "cpe:2.3:" 开头，URI 格式以 "cpe:/" 开头
	if strings.HasPrefix(cpeStr, "cpe:2.3:") {
		return naming.UnbindFS(cpeStr)
	} else if strings.HasPrefix(cpeStr, "cpe:/") {
		return naming.UnbindURI(cpeStr)
	}
	// 尝试作为 2.3 格式解析
	return naming.UnbindFS(cpeStr)
}

// cpeMatchFallback CPE 匹配降级方案（简单字符串比较）
func cpeMatchFallback(tplCPE, assetCPE string) bool {
	tplParts := strings.Split(tplCPE, ":")
	assetParts := strings.Split(assetCPE, ":")

	tplVendor := ""
	tplProduct := ""
	if len(tplParts) >= 5 {
		tplVendor = tplParts[3]
		tplProduct = tplParts[4]
	}

	assetVendor := ""
	assetProduct := ""
	if len(assetParts) >= 5 {
		assetVendor = assetParts[3]
		assetProduct = assetParts[4]
	}

	if tplVendor == "" || tplProduct == "" || assetVendor == "" || assetProduct == "" {
		return false
	}

	return strings.EqualFold(tplVendor, assetVendor) && strings.EqualFold(tplProduct, assetProduct)
}

// protocolMatch 协议匹配
func protocolMatch(tplProtocol, assetService string) bool {
	if tplProtocol == "" || assetService == "" {
		return true // 无法判断时默认匹配
	}

	// 服务到协议的映射
	serviceToProtocol := map[string]string{
		"http":       "http",
		"https":      "http",
		"http-alt":   "http",
		"http-proxy": "http",
		"ssh":        "tcp",
		"mysql":      "tcp",
		"redis":      "tcp",
		"mongodb":    "tcp",
		"ftp":        "tcp",
		"smtp":       "tcp",
		"pop3":       "tcp",
		"imap":       "tcp",
		"dns":        "dns",
		"ssl":        "ssl",
		"postgresql": "tcp",
		"mssql":      "tcp",
		"weblogic":   "tcp",
	}

	serviceProtocol := assetService
	if p, ok := serviceToProtocol[assetService]; ok {
		serviceProtocol = p
	}

	return strings.EqualFold(tplProtocol, serviceProtocol)
}

// ========== TaskLog ==========

func (s *Store) CreateTaskLog(log *model.TaskLog) error {
	return s.DB.Create(log).Error
}

func (s *Store) ListTaskLogs(taskID uint, offset, limit int) ([]model.TaskLog, int64, error) {
	var logs []model.TaskLog
	var total int64
	q := s.DB.Model(&model.TaskLog{}).Where("task_id = ?", taskID)
	q.Count(&total)
	err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&logs).Error
	return logs, total, err
}
