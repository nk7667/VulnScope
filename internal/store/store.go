package store

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"strings"

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
	default:
		db, err = gorm.Open(mysql.Open(cfg.DSN), &gorm.Config{})
	}

	if err != nil {
		return nil, err
	}

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

	// 统计去重后的总数
	s.DB.Raw(`
		SELECT COUNT(*) FROM (
			SELECT COALESCE(NULLIF(ip,''), domain) AS key_val
			FROM assets
			WHERE ip != '' OR domain != ''
			GROUP BY COALESCE(NULLIF(ip,''), domain)
		) sub
	`).Scan(&total)

	// 去重查询：先按 key 分组得到去重后的 key 列表，再关联查询详情
	// 使用子查询方式避免 only_full_group_by 问题
	err := s.DB.Raw(`
		SELECT 
			sub.id,
			sub.ip,
			sub.domain,
			sub.alive,
			sub.status_code,
			sub.response_time,
			sub.title,
			sub.task_count,
			(SELECT COUNT(*) FROM ports WHERE asset_id IN (
				SELECT id FROM assets a3 WHERE COALESCE(NULLIF(a3.ip,''), a3.domain) = sub.dedup_key
			)) AS port_count,
			(SELECT COUNT(*) FROM fingers WHERE asset_id IN (
				SELECT id FROM assets a3 WHERE COALESCE(NULLIF(a3.ip,''), a3.domain) = sub.dedup_key
			)) AS finger_count
		FROM (
			SELECT 
				MAX(a.id) AS id,
				COALESCE(NULLIF(a.ip,''), a.domain) AS dedup_key,
				MAX(a.ip) AS ip,
				MAX(a.domain) AS domain,
				MAX(CASE WHEN a.alive THEN 1 ELSE 0 END) AS alive,
				MAX(a.status_code) AS status_code,
				MIN(a.response_time) AS response_time,
				MAX(a.title) AS title,
				COUNT(DISTINCT a.id) AS task_count
			FROM assets a
			WHERE a.ip != '' OR a.domain != ''
			GROUP BY COALESCE(NULLIF(a.ip,''), a.domain)
			ORDER BY MAX(a.id) DESC
			LIMIT ? OFFSET ?
		) sub
	`, limit, offset).Scan(&results).Error

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

// cpeMatch CPE 匹配（简化版：比较 vendor:product 部分）
func cpeMatch(tplCPE, assetCPE string) bool {
	// 提取 CPE 的 vendor:product 部分
	// 格式: cpe:2.3:a:vendor:product:version:...
	tplParts := strings.Split(tplCPE, ":")
	assetParts := strings.Split(assetCPE, ":")

	// 提取 vendor (index 3) 和 product (index 4)
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

	// vendor 和 product 都匹配
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
