package scheduler

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"blackbox-scanner/internal/store"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

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
	TaskID uint     `json:"task_id"`
	Targets []string `json:"targets"`
}

// Scheduler 负责任务创建与入队
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

	// 解析目标ID
	var targetIDs []uint
	for _, idStr := range splitIDs(task.TargetIDs) {
		id := uint(idStr)
		targetIDs = append(targetIDs, id)
	}

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
	// 每个阶段完成后由 worker 触发下一阶段
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

func splitIDs(ids string) []int {
	var result []int
	for _, part := range strings.Split(ids, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err == nil && id > 0 {
			result = append(result, id)
		}
	}
	return result
}
