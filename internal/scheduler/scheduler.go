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

	// 遍历所有优先级队列
	queues := []string{"retest", "high", "default", "low"}

	for _, queue := range queues {
		// 删除 pending 任务
		pendingTasks, err := inspector.ListPendingTasks(queue)
		if err == nil {
			for _, pt := range pendingTasks {
				var payload ScanPayload
				if json.Unmarshal(pt.Payload, &payload) == nil && payload.TaskID == taskID {
					if err := inspector.DeleteTask(queue, pt.ID); err != nil {
						log.Printf("[Scheduler] Failed to delete pending task %s from %s: %v", pt.ID, queue, err)
					} else {
						log.Printf("[Scheduler] Deleted pending task %s from %s for task_id=%d", pt.ID, queue, taskID)
					}
				}
			}
		}

		// 取消正在活跃处理的任务
		activeTasks, err := inspector.ListActiveTasks(queue)
		if err == nil {
			for _, at := range activeTasks {
				var payload ScanPayload
				if json.Unmarshal(at.Payload, &payload) == nil && payload.TaskID == taskID {
					if err := inspector.CancelProcessing(at.ID); err != nil {
						log.Printf("[Scheduler] Failed to cancel active task %s from %s: %v", at.ID, queue, err)
					}
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
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// 确定目标队列
	queueName := "default"
	switch {
	case payload.IsRetest:
		queueName = "retest"
	case priority >= 8:
		queueName = "high"
	case priority <= 2:
		queueName = "low"
	}

	// 构建任务选项
	opts := []asynq.Option{
		asynq.Queue(queueName),
		asynq.MaxRetry(s.cfg.Worker.MaxRetry),
	}

	// 不在允许的扫描时间段内，设置延迟执行到下一个时间窗口
	if !s.IsAllowedScanTime() {
		delay := s.nextScanWindowDelay()
		opts = append(opts, asynq.ProcessIn(delay))
		log.Printf("[Scheduler] 当前不在扫描时间段（%s-%s），任务将在 %v 后执行, task_id=%d",
			s.cfg.Worker.AllowScanStart, s.cfg.Worker.AllowScanEnd, delay, payload.TaskID)
	}

	task := asynq.NewTask(taskType, data, opts...)
	info, err := s.client.Enqueue(task)
	if err != nil {
		return err
	}
	log.Printf("[Scheduler] Enqueued %s, task_id=%d, asynq_id=%s, queue=%s", taskType, payload.TaskID, info.ID, queueName)
	return nil
}

// nextScanWindowDelay 计算到下一个扫描时间窗口的延迟时间
func (s *Scheduler) nextScanWindowDelay() time.Duration {
	if s.cfg.Worker.AllowScanStart == "" || s.cfg.Worker.AllowScanEnd == "" {
		return 0
	}

	now := time.Now()
	currentMin := now.Hour()*60 + now.Minute()
	startMin, endMin := parseTimeRange(s.cfg.Worker.AllowScanStart, s.cfg.Worker.AllowScanEnd)

	var delayMin int
	if startMin <= endMin {
		// 不跨午夜：如 08:00-20:00
		// 当前在 20:01~23:59，等待到明天 08:00
		// 当前在 00:00~07:59，等待到今天 08:00
		if currentMin > endMin {
			delayMin = (24*60 - currentMin) + startMin
		} else {
			delayMin = startMin - currentMin
		}
	} else {
		// 跨午夜：如 22:00-06:00
		// 当前在 06:01~21:59，等待到今天 22:00
		if currentMin > endMin && currentMin < startMin {
			delayMin = startMin - currentMin
		} else {
			// 当前在窗口内，不应该调用此函数
			delayMin = 0
		}
	}

	if delayMin < 1 {
		delayMin = 1 // 最少延迟 1 分钟
	}
	return time.Duration(delayMin) * time.Minute
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
