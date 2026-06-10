package model

import "time"

// Target 扫描目标 - 用户手动添加
type Target struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Target    string    `gorm:"not null" json:"target"`    // IP / 域名 / 网段
	Type      string    `gorm:"not null" json:"type"`      // ip / domain / cidr
	Group     string    `json:"group"`                     // 分组
	Tags      string    `json:"tags"`                      // 标签, 逗号分隔
	Memo      string    `json:"memo"`                      // 备注
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Task 扫描任务
type Task struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `gorm:"not null" json:"name"`         // 任务名称
	TargetIDs       string    `gorm:"not null" json:"target_ids"`   // 关联的目标ID, 逗号分隔
	Type            int       `gorm:"default:0" json:"type"`        // 0:常规, 1:复测
	Status          string    `gorm:"default:pending" json:"status"`   // pending/running/completed/failed
	Progress        string    `gorm:"default:''" json:"progress"`  // 当前阶段: domain/alive/port/finger/vuln
	CompletedStages string    `gorm:"default:''" json:"completed_stages"` // 已完成阶段，逗号分隔（用于幂等检查）
	Error           string    `json:"error"`                        // 错误信息
	VulnCount       int       `gorm:"-" json:"vuln_count"`          // 漏洞数量（动态计算）
	FingerCount     int       `gorm:"-" json:"finger_count"`        // 指纹数量（动态计算）
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Asset 扫描产出的资产
type Asset struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	TaskID        uint      `gorm:"index;not null" json:"task_id"`
	IP            string    `json:"ip"`
	Domain        string    `json:"domain"`
	Alive         bool      `gorm:"default:false" json:"alive"`
	StatusCode    int       `json:"status_code"`
	ResponseTime  int       `json:"response_time"`  // 毫秒
	RedirectURL   string    `json:"redirect_url"`
	Title         string    `json:"title"`           // 网页标题
	CreatedAt     time.Time `json:"created_at"`
}

// AssetDedup 去重后的资产视图（跨任务合并）
type AssetDedup struct {
	ID           uint   `json:"id"`
	IP           string `json:"ip"`
	Domain       string `json:"domain"`
	Alive        bool   `json:"alive"`
	StatusCode   int    `json:"status_code"`
	ResponseTime int    `json:"response_time"`
	Title        string `json:"title"`
	TaskCount    int    `json:"task_count"`    // 关联任务数
	PortCount    int    `json:"port_count"`    // 端口数
	FingerCount  int    `json:"finger_count"`  // 指纹数
}

// Port 端口信息
type Port struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AssetID   uint      `gorm:"index;not null" json:"asset_id"`
	Port      int       `gorm:"not null" json:"port"`
	Protocol  string    `json:"protocol"`   // tcp/udp
	Service   string    `json:"service"`    // http/ssh/mysql 等
	Version   string    `json:"version"`    // 服务版本
	CPE       string    `json:"cpe"`        // CPE 标识 (如 cpe:2.3:a:redis:redis:*:*)
	Banner    string    `json:"banner"`     // 服务 Banner
	State     string    `json:"state"`      // open/filtered/closed
	CreatedAt time.Time `json:"created_at"`
}

// Finger 指纹信息
type Finger struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AssetID   uint      `gorm:"index;not null" json:"asset_id"`
	Name      string    `json:"name"`       // 指纹名称
	Category  string    `json:"category"`   // CMS/框架/中间件/OS
	Version   string    `json:"version"`    // 版本
	Detail    string    `json:"detail"`     // 详细信息
	CreatedAt time.Time `json:"created_at"`
}

// Vuln 漏洞信息
type Vuln struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	AssetID    uint      `gorm:"index" json:"asset_id"`
	TaskID     uint      `gorm:"index;not null" json:"task_id"`
	Name       string    `gorm:"not null" json:"name"`        // 漏洞名称
	Severity   string    `json:"severity"`                    // critical/high/medium/low/info
	Type       string    `json:"type"`                        // 漏洞类型
	TemplateID string    `json:"template_id"`                 // Nuclei模板ID
	Request    string    `json:"request"`                     // 请求证据
	Response   string    `json:"response"`                    // 响应证据
	Evidence   string    `json:"evidence"`                    // 其他证据
	Remediation string   `json:"remediation"`                 // 修复建议
	Status     int       `gorm:"default:0" json:"status"`     // 0:未确认, 1:误报, 2:确认, 3:忽略
	URL        string    `json:"url"`                         // 漏洞URL
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Template Nuclei模板
type Template struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	TemplateID   string    `gorm:"type:varchar(255);uniqueIndex" json:"template_id"` // nuclei 模板 ID (如 wordpress-detect)
	Name         string    `gorm:"not null" json:"name"`
	Content      string    `json:"content"`           // 模板内容 (YAML)
	Type         string    `json:"type"`              // official/custom/thirdparty
	Category     string    `json:"category"`          // finger/vuln (指纹模板/漏洞模板)
	Protocol     string    `json:"protocol"`          // http/tcp/dns/ssl 等
	CPE          string    `json:"cpe"`               // CPE 标识 (如 cpe:2.3:a:wordpress:wordpress:*:*)
	Tags         string    `json:"tags"`              // 标签
	Severity     string    `json:"severity"`          // 严重级别
	FilePath     string    `json:"file_path"`         // 模板文件路径 (相对路径)
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Config 系统配置
type Config struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Key       string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"key"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TaskLog 任务执行日志
type TaskLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	TaskID    uint      `gorm:"index;not null" json:"task_id"`
	Stage     string    `json:"stage"`           // 当前阶段: domain/alive/port/finger/vuln
	Message   string    `json:"message"`         // 日志消息
	Level     string    `gorm:"default:info" json:"level"` // info/warn/error
	CreatedAt time.Time `json:"created_at"`
}
