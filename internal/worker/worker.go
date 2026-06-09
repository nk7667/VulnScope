package worker

import (
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/model"
	"blackbox-scanner/internal/scheduler"
	"blackbox-scanner/internal/store"
	"blackbox-scanner/internal/worker/scanner"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/hibiken/asynq"
)

// Worker Asynq 消费者
type Worker struct {
	mux   *asynq.ServeMux
	srv   *asynq.Server
	store *store.Store
	// Worker 自己持有 asynq.Client，用于触发下一阶段
	client *asynq.Client
	cfg    *config.Config
}

func New(redisCfg *config.RedisConfig, s *store.Store, cfg *config.Config) *Worker {
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisCfg.Addr,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	}

	mux := asynq.NewServeMux()
	srv := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: cfg.Worker.Concurrency,
		Queues: map[string]int{
			"retest":  9,
			"high":    6,
			"default": 3,
			"low":     1,
		},
		RetryDelayFunc: asynq.DefaultRetryDelayFunc,
	})

	client := asynq.NewClient(redisOpt)

	w := &Worker{
		mux:    mux,
		srv:    srv,
		store:  s,
		client: client,
		cfg:    cfg,
	}

	// 注册任务处理器
	mux.HandleFunc(scheduler.TypeDomainScan, w.handleDomainScan)
	mux.HandleFunc(scheduler.TypeAliveScan, w.handleAliveScan)
	mux.HandleFunc(scheduler.TypePortScan, w.handlePortScan)
	mux.HandleFunc(scheduler.TypeFingerScan, w.handleFingerScan)
	mux.HandleFunc(scheduler.TypeVulnScan, w.handleVulnScan)

	return w
}

func (w *Worker) Run() error {
	log.Println("[Worker] Starting consumer...")
	return w.srv.Run(w.mux)
}

func (w *Worker) Shutdown() {
	w.srv.Shutdown()
	w.client.Close()
}

// enqueueNextStage Worker 自己入队下一阶段，不依赖 Scheduler
func (w *Worker) enqueueNextStage(currentStage string, taskID uint, targets []string) error {
	payload := scheduler.ScanPayload{
		TaskID:  taskID,
		Targets: targets,
	}

	var nextType string
	var nextProgress string
	switch currentStage {
	case "domain":
		nextType = scheduler.TypeAliveScan
		nextProgress = "alive"
	case "alive":
		nextType = scheduler.TypePortScan
		nextProgress = "port"
	case "port":
		nextType = scheduler.TypeFingerScan
		nextProgress = "finger"
	case "finger":
		nextType = scheduler.TypeVulnScan
		nextProgress = "vuln"
	case "vuln":
		// 流水线完成
		task, err := w.store.GetTask(taskID)
		if err != nil {
			return err
		}
		task.Status = "completed"
		task.Progress = "done"
		return w.store.UpdateTask(task)
	default:
		return nil
	}

	// 更新进度
	task, err := w.store.GetTask(taskID)
	if err != nil {
		return err
	}
	task.Progress = nextProgress
	if err := w.store.UpdateTask(task); err != nil {
		return err
	}

	// 直接入队 Redis
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	asynqTask := asynq.NewTask(nextType, data, asynq.Queue("default"), asynq.MaxRetry(w.cfg.Worker.MaxRetry))
	info, err := w.client.Enqueue(asynqTask)
	if err != nil {
		return err
	}
	log.Printf("[Worker] Enqueued next stage %s, task_id=%d, asynq_id=%s", nextType, taskID, info.ID)
	return nil
}

func (w *Worker) handleDomainScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Domain scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 幂等检查：如果该阶段已完成，跳过
	if w.isStageCompleted(p.TaskID, "domain") {
		log.Printf("[Worker] Domain scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "domain", "info", fmt.Sprintf("开始域名扫描，目标数: %d", len(p.Targets)))

	results, err := scanner.DomainScan(ctx, p.Targets, w.cfg)
	if err != nil {
		w.logTask(p.TaskID, "domain", "error", fmt.Sprintf("域名扫描失败: %v", err))
		w.failTask(p.TaskID, err.Error())
		return err
	}

	w.logTask(p.TaskID, "domain", "info", fmt.Sprintf("域名扫描完成，发现 %d 个域名/IP", len(results)))

	for _, r := range results {
		asset := r.ToAsset(p.TaskID)
		if err := w.store.CreateAsset(asset); err != nil {
			log.Printf("[Worker] Failed to save domain result: %v", err)
		}
	}

	var aliveTargets []string
	for _, r := range results {
		// 如果目标带端口，保留端口信息
		if r.Port > 0 {
			aliveTargets = append(aliveTargets, fmt.Sprintf("%s:%d", r.IP, r.Port))
		} else {
			if r.IP != "" {
				aliveTargets = append(aliveTargets, r.IP)
			}
			if r.Domain != "" {
				aliveTargets = append(aliveTargets, r.Domain)
			}
		}
	}
	return w.enqueueNextStage("domain", p.TaskID, aliveTargets)
}

func (w *Worker) handleAliveScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Alive scan: task_id=%d, targets=%v", p.TaskID, p.Targets)
	// 幂等检查：如果该阶段已完成，跳过
	if w.isStageCompleted(p.TaskID, "alive") {
		log.Printf("[Worker] Alive scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "alive", "info", fmt.Sprintf("开始存活探测，目标数: %d", len(p.Targets)))

	results, err := scanner.AliveScan(ctx, p.Targets, w.cfg)
	if err != nil {
		w.logTask(p.TaskID, "alive", "error", fmt.Sprintf("存活探测失败: %v", err))
		w.failTask(p.TaskID, err.Error())
		return err
	}

	aliveCount := 0
	for _, r := range results {
		if r.Alive {
			aliveCount++
		}
	}
	w.logTask(p.TaskID, "alive", "info", fmt.Sprintf("存活探测完成，存活目标数: %d", aliveCount))

	var aliveTargets []string
	for _, r := range results {
		if r.Alive {
			aliveTargets = append(aliveTargets, r.Target)
		}
		var assets []struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, r.Target, r.Target).Select("id").Scan(&assets)
		for _, a := range assets {
			w.store.DB.Table("assets").Where("id = ?", a.ID).Updates(map[string]interface{}{
				"alive":         r.Alive,
				"status_code":   r.StatusCode,
				"response_time": r.ResponseTime,
				"title":         r.Title,
			})
		}
	}

	return w.enqueueNextStage("alive", p.TaskID, aliveTargets)
}

func (w *Worker) handlePortScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Port scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 幂等检查：如果该阶段已完成，跳过
	if w.isStageCompleted(p.TaskID, "port") {
		log.Printf("[Worker] Port scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "port", "info", fmt.Sprintf("开始端口扫描，目标数: %d", len(p.Targets)))

	// 分离已带端口的目标和需要扫描的目标
	var targetsWithPort []string
	var targetsNeedScan []string
	for _, target := range p.Targets {
		host, port, _ := net.SplitHostPort(target)
		if port != "" && host != "" {
			targetsWithPort = append(targetsWithPort, target)
		} else {
			targetsNeedScan = append(targetsNeedScan, target)
		}
	}

	// 对需要扫描的目标进行端口扫描
	results := make(map[string][]model.Port)
	if len(targetsNeedScan) > 0 {
		scanResults, err := scanner.PortScan(ctx, targetsNeedScan, w.cfg)
		if err != nil {
			w.logTask(p.TaskID, "port", "error", fmt.Sprintf("端口扫描失败: %v", err))
			w.failTask(p.TaskID, err.Error())
			return err
		}
		for k, v := range scanResults {
			results[k] = v
		}
	}

	// 对已带端口的目标，直接添加为开放端口
	for _, target := range targetsWithPort {
		host, portStr, _ := net.SplitHostPort(target)
		portNum := 0
		for _, c := range portStr {
			if c >= '0' && c <= '9' {
				portNum = portNum*10 + int(c-'0')
			}
		}
		if portNum > 0 {
			results[host] = append(results[host], model.Port{
				Port:     portNum,
				Protocol: "tcp",
				State:    "open",
			})
		}
	}

	// 构建带端口的目标列表，传递给下一阶段
	var nextTargets []string
	for target, ports := range results {
		var asset struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, target, target).Select("id").Scan(&asset)
		if asset.ID == 0 {
			continue
		}
		for _, port := range ports {
			port.AssetID = asset.ID
			w.store.CreatePort(&port)
			// 将 target:port 作为下一阶段目标
			nextTargets = append(nextTargets, fmt.Sprintf("%s:%d", target, port.Port))
		}
	}

	if len(nextTargets) == 0 {
		log.Printf("[Worker] Port scan found no open ports, task_id=%d", p.TaskID)
		w.logTask(p.TaskID, "port", "warn", "端口扫描未发现开放端口")
		// 没有开放端口，直接跳到完成
		task, _ := w.store.GetTask(p.TaskID)
		task.Status = "completed"
		task.Progress = "done"
		return w.store.UpdateTask(task)
	}

	log.Printf("[Worker] Port scan found %d open ports, passing to next stage: %v", len(nextTargets), nextTargets)
	w.logTask(p.TaskID, "port", "info", fmt.Sprintf("端口扫描完成，发现 %d 个开放端口", len(nextTargets)))
	return w.enqueueNextStage("port", p.TaskID, nextTargets)
}

func (w *Worker) handleFingerScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Finger scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 幂等检查：如果该阶段已完成，跳过
	if w.isStageCompleted(p.TaskID, "finger") {
		log.Printf("[Worker] Finger scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "finger", "info", fmt.Sprintf("开始指纹识别，目标数: %d", len(p.Targets)))

	results, err := scanner.FingerScan(ctx, p.Targets, w.cfg)
	if err != nil {
		w.logTask(p.TaskID, "finger", "error", fmt.Sprintf("指纹识别失败: %v", err))
		w.failTask(p.TaskID, err.Error())
		return err
	}

	fingerCount := 0
	for _, result := range results {
		fingerCount += len(result.Fingers)
	}
	w.logTask(p.TaskID, "finger", "info", fmt.Sprintf("指纹识别完成，发现 %d 个指纹", fingerCount))

	for target, result := range results {
		// 从 target (host:port) 中提取 host 用于匹配资产
		host := target
		if h, _, err := net.SplitHostPort(target); err == nil {
			host = h
		}

		var asset struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, host, host).Select("id").Scan(&asset)
		if asset.ID == 0 {
			log.Printf("[Worker] Finger scan: no asset found for target=%s host=%s", target, host)
			continue
		}
		for _, f := range result.Fingers {
			f.AssetID = asset.ID
			w.store.CreateFinger(&f)
		}

		// 如果 CPE 为空，从数据库指纹模板表中查找匹配的 CPE
		if result.CPE == "" && len(result.Fingers) > 0 {
			for _, f := range result.Fingers {
				var tpl model.Template
				// 先精确匹配
				if err := w.store.DB.Where("category = ? AND name = ?", "finger", f.Name).First(&tpl).Error; err != nil {
					// 精确匹配失败，尝试模糊匹配（LIKE）
					w.store.DB.Where("category = ? AND name LIKE ?", "finger", "%"+f.Name+"%").First(&tpl)
				}
				if tpl.CPE != "" {
					result.CPE = tpl.CPE
					log.Printf("[Worker] CPE from template DB: %s -> %s", f.Name, tpl.CPE)
					break
				}
			}
		}

		// 更新端口的 CPE 和 Service 信息
		if result.CPE != "" || result.Service != "" {
			// 提取端口号用于精确匹配端口
			_, portStr, _ := net.SplitHostPort(target)
			var ports []model.Port
			isFallback := false
			if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 {
				// 精确匹配该端口
				w.store.DB.Where("asset_id = ? AND port = ?", asset.ID, portNum).Find(&ports)
			}
			if len(ports) == 0 {
				// 回退到该资产所有端口（仅更新 service，不更新 CPE）
				w.store.DB.Where("asset_id = ?", asset.ID).Find(&ports)
				if len(ports) > 0 {
					log.Printf("[Worker] Warning: port %s not found for asset %d, fallback to all ports (only updating service, not CPE)", portStr, asset.ID)
					isFallback = true
				}
			}
			for i := range ports {
				updated := false
				// CPE 只在精确匹配时更新，回退时不更新（避免错误覆盖）
				if !isFallback && result.CPE != "" && ports[i].CPE == "" {
					ports[i].CPE = result.CPE
					updated = true
				}
				if result.Service != "" && (ports[i].Service == "" || ports[i].Service == "unknown") {
					ports[i].Service = result.Service
					updated = true
				}
				if result.Banner != "" && ports[i].Banner == "" {
					ports[i].Banner = result.Banner
					updated = true
				}
				if updated {
					w.store.DB.Save(&ports[i])
				}
			}
		}
	}

	return w.enqueueNextStage("finger", p.TaskID, p.Targets)
}

func (w *Worker) handleVulnScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Vuln scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 幂等检查：如果该阶段已完成，跳过
	if w.isStageCompleted(p.TaskID, "vuln") {
		log.Printf("[Worker] Vuln scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("开始漏洞扫描，目标数: %d", len(p.Targets)))

	// 收集每个目标的 CPE 和 Service，用于模板匹配
	var targetInfos []scanner.TargetServiceInfo
	for _, target := range p.Targets {
		info := scanner.TargetServiceInfo{Target: target}
		host := target
		if h, _, err := net.SplitHostPort(target); err == nil {
			host = h
		}

		// 从端口信息中获取 CPE 和 Service
		var asset struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, host, host).Select("id").Scan(&asset)
		log.Printf("[Worker] Vuln scan target=%s host=%s asset_id=%d", target, host, asset.ID)
		if asset.ID > 0 {
			// 精确匹配该端口的 service
			_, portStr, _ := net.SplitHostPort(target)
			if targetPort, err := strconv.Atoi(portStr); err == nil && targetPort > 0 {
				var port model.Port
				if err := w.store.DB.Where("asset_id = ? AND port = ?", asset.ID, targetPort).First(&port).Error; err == nil {
					info.CPE = port.CPE
					log.Printf("[Worker] Port found: asset_id=%d port=%d cpe=%s service=%s", asset.ID, targetPort, port.CPE, port.Service)
					if port.Service != "" && port.Service != "unknown" {
						info.Service = port.Service
					}
				} else {
					log.Printf("[Worker] Port not found: asset_id=%d port=%d err=%v", asset.ID, targetPort, err)
				}
			}
		}

		// 如果指纹识别没有产出 service，跳过该目标的漏洞扫描
		if info.Service == "" {
			log.Printf("[Worker] Target %s has no service identified, skipping vuln scan", target)
			continue
		}
		targetInfos = append(targetInfos, info)
	}

	// 如果没有可扫描的目标，直接完成
	if len(targetInfos) == 0 {
		w.logTask(p.TaskID, "vuln", "info", "所有目标均未识别出服务，跳过漏洞扫描")
		task, _ := w.store.GetTask(p.TaskID)
		task.Status = "completed"
		task.Progress = "done"
		return w.store.UpdateTask(task)
	}

	// 构建有 service 的目标列表
	var validTargets []string
	for _, info := range targetInfos {
		validTargets = append(validTargets, info.Target)
	}

	// 模板匹配：为每个目标找到匹配的漏洞模板（仅用于日志记录）
	totalMatched := 0
	for _, info := range targetInfos {
		matched, err := w.store.GetMatchedVulnTemplates(info.CPE, info.Service)
		if err != nil {
			log.Printf("[Worker] Template matching failed for %s: %v", info.Target, err)
			continue
		}
		totalMatched += len(matched)
		log.Printf("[Worker] Target %s (CPE=%s, Service=%s) matched %d vuln templates", info.Target, info.CPE, info.Service, len(matched))
	}

	// 执行漏洞扫描：始终使用按目录扫描，确保覆盖面完整
	var vulns []model.Vuln
	var scanErr error
	// 模板匹配仅用于日志参考，不限制扫描范围
	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("模板匹配 %d 个，按服务协议筛选漏洞模板目录进行扫描", totalMatched))
	vulns, scanErr = scanner.VulnScanByService(ctx, validTargets, targetInfos, w.cfg)

	if scanErr != nil {
		w.logTask(p.TaskID, "vuln", "error", fmt.Sprintf("漏洞扫描失败: %v", scanErr))
		w.failTask(p.TaskID, scanErr.Error())
		return scanErr
	}

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("漏洞扫描完成，发现 %d 个漏洞", len(vulns)))
	for _, v := range vulns {
		w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("- %s [%s] %s", v.Name, v.Severity, v.URL))
	}

	for _, v := range vulns {
		v.TaskID = p.TaskID
		// 从 URL 中提取 host 用于匹配资产
		host := v.URL
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			u, e := url.Parse(host)
			if e == nil {
				host = u.Hostname()
			}
		}
		// 去掉端口部分
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		var asset struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, host, host).Select("id").Scan(&asset)
		v.AssetID = asset.ID
		w.store.CreateVuln(&v)
	}

	return w.enqueueNextStage("vuln", p.TaskID, nil)
}

func (w *Worker) failTask(taskID uint, errMsg string) {
	task, err := w.store.GetTask(taskID)
	if err != nil {
		return
	}
	task.Status = "failed"
	task.Error = errMsg
	w.store.UpdateTask(task)
}

// isStageCompleted 检查该阶段是否已完成（幂等检查，防止重启后重复执行）
func (w *Worker) isStageCompleted(taskID uint, stage string) bool {
	var count int64
	w.store.DB.Model(&model.TaskLog{}).Where("task_id = ? AND stage = ? AND level = 'info' AND message LIKE ?", taskID, stage, "%完成%").Count(&count)
	return count > 0
}

// logTask 记录任务执行日志
func (w *Worker) logTask(taskID uint, stage, level, message string) {
	logEntry := &model.TaskLog{
		TaskID:  taskID,
		Stage:   stage,
		Level:   level,
		Message: message,
	}
	if err := w.store.CreateTaskLog(logEntry); err != nil {
		log.Printf("[Worker] Failed to write task log: %v", err)
	}
}
