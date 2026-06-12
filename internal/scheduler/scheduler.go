package scheduler

import (
	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"vulnscope/internal/store"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

// 任务类型
const (
	TypeDomainScan = "scan:domain"
	TypeAliveScan  = "scan:alive"
	TypePortScan   = "scan:port"
	TypeFingerScan = "scan:finger"
	TypeVulnScan   = "scan:vuln"
)

// ScanPayload 扫描任务载荷
type ScanPayload struct {
	TaskID       uint     `json:"task_id"`
	Targets      []string `json:"targets"`
	TemplateIDs  []string `json:"template_ids,omitempty"`  // 复测任务：指定模板 ID
	IsRetest     bool     `json:"is_retest,omitempty"`     // 是否复测任务
	OriginalTaskID uint   `json:"original_task_id,omitempty"` // 复测任务：原始任务 ID
}

// Scheduler 负责任务创建与入队（唯一入队入口）
type Scheduler struct {
	client *asynq.Client
	store  *store.Store
	cfg    *config.Config
}

func New(redisCfg *config.RedisConfig, s *store.Store, cfg *config.Config) *Scheduler {
	client := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     redisCfg.Addr,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	})
	return &Scheduler{client: client, store: s, cfg: cfg}
}

// EnqueueTask 将扫描任务按流水线入队
func (s *Scheduler) EnqueueTask(taskID uint) error {
	// 获取任务
	task, err := s.store.GetTask(taskID)
	if err != nil {
		return fmt.Errorf("task not found: %w", err)
	}

	// 复测任务：直接从漏洞扫描阶段开始，使用指定模板对特定资产重新验证
	if task.Type == 1 {
		return s.enqueueRetestTask(task)
	}

	// 解析目标ID
	targetIDs := splitIDs(task.TargetIDs)

	// 获取目标内容
	targets, err := s.store.GetTargetsByIDs(targetIDs)
	if err != nil {
		return fmt.Errorf("targets not found: %w", err)
	}

	var targetList []string
	for _, t := range targets {
		targetList = append(targetList, t.Target)
	}

	// 更新任务状态为 running
	task.Status = "running"
	task.Progress = "domain"
	s.store.UpdateTask(task)

	// 记录任务启动日志
	s.logTask(taskID, "system", "info", fmt.Sprintf("任务已启动，目标数: %d", len(targetList)))

	// 按流水线顺序入队: 域名 → 存活 → 端口 → 指纹 → 漏洞
	// 每个阶段完成后由 worker 通过回调触发下一阶段
	payload := ScanPayload{
		TaskID:  taskID,
		Targets: targetList,
	}

	// 第一步: 域名扫描
	if err := s.enqueue(TypeDomainScan, payload, 3); err != nil {
		// 记录入队失败日志
		s.logTask(taskID, "system", "error", fmt.Sprintf("任务入队失败: %v", err))
		// 更新任务状态为失败
		task.Status = "failed"
		task.Error = fmt.Sprintf("任务入队失败: %v", err)
		s.store.UpdateTask(task)
		return fmt.Errorf("enqueue domain scan failed: %w", err)
	}

	log.Printf("[Scheduler] Task %d enqueued, targets: %v", taskID, targetList)
	s.logTask(taskID, "system", "info", "任务已进入队列，等待执行")
	return nil
}

// enqueueRetestTask 复测任务入队：直接从漏洞扫描阶段开始
// 复测任务使用之前发现的漏洞资产和指定模板重新验证
func (s *Scheduler) enqueueRetestTask(task *model.Task) error {
	// 解析目标ID，获取关联的资产
	targetIDs := splitIDs(task.TargetIDs)

	// 获取之前任务发现的漏洞资产 URL
	var vulns []model.Vuln
	if err := s.store.DB.Where("task_id IN ?", targetIDs).Find(&vulns).Error; err != nil {
		return fmt.Errorf("failed to get original vulns: %w", err)
	}

	var targets []string
	seen := make(map[string]bool)
	for _, v := range vulns {
		if v.URL != "" && !seen[v.URL] {
			seen[v.URL] = true
			targets = append(targets, v.URL)
		}
	}

	if len(targets) == 0 {
		// 没有历史漏洞，尝试获取资产列表
		var assets []model.Asset
		if err := s.store.DB.Where("task_id IN ?", targetIDs).Find(&assets).Error; err != nil {
			return fmt.Errorf("failed to get assets: %w", err)
		}
		for _, a := range assets {
			addr := a.IP
			if a.Domain != "" {
				addr = a.Domain
			}
			if addr != "" && !seen[addr] {
				seen[addr] = true
				targets = append(targets, addr)
			}
		}
	}

	if len(targets) == 0 {
		task.Status = "failed"
		task.Error = "复测任务无目标：未找到关联的漏洞或资产"
		s.store.UpdateTask(task)
		return fmt.Errorf("retest task %d has no targets", task.ID)
	}

	// 获取关联的模板 ID
	var templateIDs []string
	for _, v := range vulns {
		if v.TemplateID != "" {
			templateIDs = append(templateIDs, v.TemplateID)
		}
	}

	// 更新任务状态
	task.Status = "running"
	task.Progress = "vuln"
	s.store.UpdateTask(task)

	s.logTask(task.ID, "system", "info", fmt.Sprintf("复测任务已启动，目标数: %d，模板数: %d", len(targets), len(templateIDs)))

	// 直接入队漏洞扫描
	payload := ScanPayload{
		TaskID:         task.ID,
		Targets:        targets,
		TemplateIDs:    templateIDs,
		IsRetest:       true,
		OriginalTaskID: targetIDs[0],
	}

	if err := s.enqueue(TypeVulnScan, payload, 3); err != nil {
		s.logTask(task.ID, "system", "error", fmt.Sprintf("复测任务入队失败: %v", err))
		task.Status = "failed"
		task.Error = fmt.Sprintf("复测任务入队失败: %v", err)
		s.store.UpdateTask(task)
		return err
	}

	log.Printf("[Scheduler] Retest task %d enqueued, targets: %d, templates: %d", task.ID, len(targets), len(templateIDs))
	return nil
}

// EnqueueNextStage 按单个目标粒度入队下一阶段（由 Worker 回调）
func (s *Scheduler) EnqueueNextStage(currentStage string, taskID uint, targets []string) error {
	var nextType string
	var nextProgress string
	switch currentStage {
	case "domain":
		nextType = TypeAliveScan
		nextProgress = "alive"
	case "alive":
		nextType = TypePortScan
		nextProgress = "port"
	case "port":
		nextType = TypeFingerScan
		nextProgress = "finger"
	case "finger":
		nextType = TypeVulnScan
		nextProgress = "vuln"
	case "vuln":
		// 流水线完成
		task, err := s.store.GetTask(taskID)
		if err != nil {
			return err
		}
		task.Status = "completed"
		task.Progress = "done"
		return s.store.UpdateTask(task)
	default:
		return nil
	}

	// 按单个目标粒度入队，一个目标完成即可进入下一阶段
	for _, target := range targets {
		payload := ScanPayload{
			TaskID:  taskID,
			Targets: []string{target},
		}
		if err := s.enqueue(nextType, payload, 3); err != nil {
			log.Printf("[Scheduler] Failed to enqueue %s for target %s: %v", nextType, target, err)
			continue
		}
	}

	log.Printf("[Scheduler] Enqueued %d targets for stage %s, task_id=%d", len(targets), nextType, taskID)

	// 更新任务进度
	task, err := s.store.GetTask(taskID)
	if err != nil {
		return err
	}
	task.Progress = nextProgress
	return s.store.UpdateTask(task)
}

// EnqueueNextStageBatch 按批次入队下一阶段（用于 domain 阶段，所有目标一起处理）
func (s *Scheduler) EnqueueNextStageBatch(currentStage string, taskID uint, targets []string) error {
	var nextType string
	var nextProgress string
	switch currentStage {
	case "domain":
		nextType = TypeAliveScan
		nextProgress = "alive"
	default:
		return s.EnqueueNextStage(currentStage, taskID, targets)
	}

	// domain 阶段结果按单个目标粒度入队 alive
	for _, target := range targets {
		payload := ScanPayload{
			TaskID:  taskID,
			Targets: []string{target},
		}
		if err := s.enqueue(nextType, payload, 3); err != nil {
			log.Printf("[Scheduler] Failed to enqueue %s for target %s: %v", nextType, target, err)
			continue
		}
	}

	log.Printf("[Scheduler] Enqueued %d targets for stage %s, task_id=%d", len(targets), nextType, taskID)

	task, err := s.store.GetTask(taskID)
	if err != nil {
		return err
	}
	task.Progress = nextProgress
	return s.store.UpdateTask(task)
}

// CancelTask 取消任务：删除队列中待执行的任务，标记任务状态为 cancelled
func (s *Scheduler) CancelTask(taskID uint) error {
	task, err := s.store.GetTask(taskID)
	if err != nil {
		return err
	}

	// 使用 asynq.Inspector 清理 Redis 队列中的 pending 任务
	inspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     s.cfg.Redis.Addr,
		Password: s.cfg.Redis.Password,
		DB:       s.cfg.Redis.DB,
	})
	defer inspector.Close()

	// 遍历队列，删除属于该 taskID 的 pending 任务
	// asynq 的任务 ID 在 Payload 中，需要逐个检查
	pendingTasks, err := inspector.ListPendingTasks("default")
	if err == nil {
		for _, pt := range pendingTasks {
			var payload ScanPayload
			if json.Unmarshal(pt.Payload, &payload) == nil && payload.TaskID == taskID {
				if err := inspector.DeleteTask("default", pt.ID); err != nil {
					log.Printf("[Scheduler] Failed to delete pending task %s: %v", pt.ID, err)
				} else {
					log.Printf("[Scheduler] Deleted pending task %s for task_id=%d", pt.ID, taskID)
				}
			}
		}
	}

	// 同时取消正在活跃处理的任务
	activeTasks, err := inspector.ListActiveTasks("default")
	if err == nil {
		for _, at := range activeTasks {
			var payload ScanPayload
			if json.Unmarshal(at.Payload, &payload) == nil && payload.TaskID == taskID {
				if err := inspector.CancelProcessing(at.ID); err != nil {
					log.Printf("[Scheduler] Failed to cancel active task %s: %v", at.ID, err)
				}
			}
		}
	}

	task.Status = "cancelled"
	task.Error = "用户取消"
	return s.store.UpdateTask(task)
}

// PauseTask 暂停任务
func (s *Scheduler) PauseTask(taskID uint) error {
	task, err := s.store.GetTask(taskID)
	if err != nil {
		return err
	}
	if task.Status != "running" {
		return fmt.Errorf("只能暂停运行中的任务")
	}
	task.Status = "paused"
	return s.store.UpdateTask(task)
}

// ResumeTask 恢复暂停的任务
func (s *Scheduler) ResumeTask(taskID uint) error {
	task, err := s.store.GetTask(taskID)
	if err != nil {
		return err
	}
	if task.Status != "paused" {
		return fmt.Errorf("只能恢复暂停的任务")
	}
	task.Status = "running"
	return s.store.UpdateTask(task)
}

// IsAllowedScanTime 检查当前是否在允许的扫描时间段内
func (s *Scheduler) IsAllowedScanTime() bool {
	if s.cfg.Worker.AllowScanStart == "" || s.cfg.Worker.AllowScanEnd == "" {
		return true // 未配置则始终允许
	}
	now := time.Now()
	currentMin := now.Hour()*60 + now.Minute()
	startMin, endMin := parseTimeRange(s.cfg.Worker.AllowScanStart, s.cfg.Worker.AllowScanEnd)
	if startMin <= endMin {
		return currentMin >= startMin && currentMin <= endMin
	}
	// 跨午夜的时间段（如 22:00-06:00）
	return currentMin >= startMin || currentMin <= endMin
}

// parseTimeRange 解析时间范围（如 "08:00", "20:00"）
func parseTimeRange(start, end string) (int, int) {
	startMin := parseTimeToMinutes(start)
	endMin := parseTimeToMinutes(end)
	return startMin, endMin
}

func parseTimeToMinutes(t string) int {
	parts := strings.Split(t, ":")
	if len(parts) != 2 {
		return 0
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	return h*60 + m
}

// logTask 记录任务日志
func (s *Scheduler) logTask(taskID uint, stage, level, message string) {
	logEntry := &model.TaskLog{
		TaskID:  taskID,
		Stage:   stage,
		Level:   level,
		Message: message,
	}
	if err := s.store.CreateTaskLog(logEntry); err != nil {
		log.Printf("[Scheduler] Failed to write task log: %v", err)
	}
}

func (s *Scheduler) enqueue(taskType string, payload ScanPayload, priority int) error {
	// 检查是否在允许的扫描时间段内
	if !s.IsAllowedScanTime() {
		return fmt.Errorf("当前不在允许的扫描时间段内（%s-%s），任务已暂存等待下次窗口", s.cfg.Worker.AllowScanStart, s.cfg.Worker.AllowScanEnd)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	task := asynq.NewTask(taskType, data, asynq.Queue("default"), asynq.MaxRetry(s.cfg.Worker.MaxRetry))
	info, err := s.client.Enqueue(task)
	if err != nil {
		return err
	}
	log.Printf("[Scheduler] Enqueued %s, task_id=%d, asynq_id=%s", taskType, payload.TaskID, info.ID)
	return nil
}

func (s *Scheduler) Close() error {
	return s.client.Close()
}

func splitIDs(ids string) []uint {
	var result []uint
	for _, part := range strings.Split(ids, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, 64)
		if err == nil && id > 0 {
			result = append(result, uint(id))
		}
	}
	return result
}
