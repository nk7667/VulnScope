package worker

import (
	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"vulnscope/internal/scheduler"
	"vulnscope/internal/store"
	"vulnscope/internal/worker/scanner"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/hibiken/asynq"
	"golang.org/x/time/rate"
)

// EnqueueFunc 入队回调函数类型，由 Scheduler 提供
type EnqueueFunc func(currentStage string, taskID uint, targets []string) error

// Worker Asynq 消费者（不再持有 asynq.Client，入队由 Scheduler 统一管理）
type Worker struct {
	mux      *asynq.ServeMux
	srv      *asynq.Server
	store    *store.Store
	cfg      *config.Config
	enqueue  EnqueueFunc // 通过回调入队下一阶段
	rdb      *redis.Client // Redis 客户端，用于快速检查任务状态

	// 每目标 QPS 限速
	targetLimiters   map[string]*rate.Limiter
	targetLimitersMu sync.Mutex
}

func New(redisCfg *config.RedisConfig, s *store.Store, cfg *config.Config, enqueueFn EnqueueFunc) *Worker {
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

	// 初始化 Redis 客户端（复用 asynq 的 Redis 配置）
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisCfg.Addr,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	})

	w := &Worker{
		mux:            mux,
		srv:            srv,
		store:          s,
		cfg:            cfg,
		enqueue:        enqueueFn,
		rdb:            rdb,
		targetLimiters: make(map[string]*rate.Limiter),
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
}

// isTaskCancelled 检查任务是否已取消或暂停（优先使用 Redis Set，回退到数据库）
func (w *Worker) isTaskCancelled(taskID uint) bool {
	// 优先检查 Redis Set（毫秒级响应）
	ctx := context.Background()
	key := fmt.Sprintf("vulnscope:cancelled_tasks")
	isMember, err := w.rdb.SIsMember(ctx, key, taskID).Result()
	if err == nil {
		return isMember
	}
	// Redis 不可用时回退到数据库
	task, err := w.store.GetTask(taskID)
	if err != nil {
		return true
	}
	return task.Status == "cancelled" || task.Status == "paused"
}

// markTaskCancelled 在 Redis 中标记任务已取消（由 Scheduler 的 CancelTask 调用）
func (w *Worker) markTaskCancelled(taskID uint) {
	ctx := context.Background()
	w.rdb.SAdd(ctx, "vulnscope:cancelled_tasks", taskID)
}

// getTargetLimiter 获取目标的 QPS 限速器（每目标默认 10 QPS）
func (w *Worker) getTargetLimiter(target string) *rate.Limiter {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		host = h
	}

	w.targetLimitersMu.Lock()
	defer w.targetLimitersMu.Unlock()

	if limiter, ok := w.targetLimiters[host]; ok {
		return limiter
	}

	// 默认每目标 10 QPS，burst 20
	qps := 10
	if w.cfg.Worker.Concurrency > 0 {
		qps = w.cfg.Worker.Concurrency
	}
	limiter := rate.NewLimiter(rate.Limit(qps), qps*2)
	w.targetLimiters[host] = limiter
	return limiter
}

// waitTargetLimit 等待目标 QPS 限速许可
func (w *Worker) waitTargetLimit(ctx context.Context, target string) error {
	limiter := w.getTargetLimiter(target)
	return limiter.Wait(ctx)
}

// skipRetry 返回 asynq.SkipRetry 错误，避免无意义的重试
var skipRetry = fmt.Errorf("skip retry: %w", asynq.SkipRetry)

// cancelHandler 包装 handler 逻辑，在 goroutine 中执行实际工作，
// 主线程监听 ctx.Done，超时/取消时返回 SkipRetry
func (w *Worker) cancelHandler(ctx context.Context, handler func() error) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- handler()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Printf("[Worker] Task cancelled by context: %v", ctx.Err())
		return skipRetry
	}
}

// isExcluded 检查目标是否在排除列表中
func (w *Worker) isExcluded(target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		host = h
	}

	for _, excl := range w.cfg.Worker.ExcludeTargets {
		// 精确匹配
		if host == excl || target == excl {
			return true
		}
		// CIDR 匹配
		if strings.Contains(excl, "/") {
			_, ipNet, err := net.ParseCIDR(excl)
			if err == nil {
				ip := net.ParseIP(host)
				if ip != nil && ipNet.Contains(ip) {
					return true
				}
			}
		}
		// 子域名匹配（排除 *.example.com）
		if strings.HasPrefix(excl, "*.") {
			suffix := excl[1:] // .example.com
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// isPortExcluded 检查端口是否在排除列表中
func (w *Worker) isPortExcluded(port int) bool {
	for _, p := range w.cfg.Worker.ExcludePorts {
		if p == port {
			return true
		}
	}
	return false
}

// checkIPScanCooldown 检查 IP 是否在冷却期内（防重），使用 Redis
func (w *Worker) checkIPScanCooldown(target string) bool {
	if w.cfg.Worker.IPScanCooldownMin <= 0 {
		return false // 未配置冷却时间，不限制
	}

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		host = h
	}

	// 通过数据库 Config 表实现简单防重（不依赖额外 Redis key）
	key := fmt.Sprintf("ip_cooldown:%s", host)
	var cfg model.Config
	if err := w.store.DB.Where("`key` = ?", key).First(&cfg).Error; err == nil {
		// 检查是否在冷却期内
		if time.Since(cfg.UpdatedAt) < time.Duration(w.cfg.Worker.IPScanCooldownMin)*time.Minute {
			return true // 在冷却期内
		}
	}
	// 更新或创建冷却记录
	if cfg.ID > 0 {
		cfg.Value = fmt.Sprintf("%d", time.Now().Unix())
		w.store.DB.Save(&cfg)
	} else {
		w.store.DB.Create(&model.Config{Key: key, Value: fmt.Sprintf("%d", time.Now().Unix())})
	}
	return false
}

// filterTargets 过滤排除目标和冷却期内的目标
func (w *Worker) filterTargets(targets []string) []string {
	var filtered []string
	for _, t := range targets {
		if w.isExcluded(t) {
			log.Printf("[Worker] Target %s excluded, skipping", t)
			continue
		}
		if w.checkIPScanCooldown(t) {
			log.Printf("[Worker] Target %s in cooldown period, skipping", t)
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}

func (w *Worker) handleDomainScan(ctx context.Context, t *asynq.Task) error {
	return w.cancelHandler(ctx, func() error {
		return w.doDomainScan(ctx, t)
	})
}

func (w *Worker) doDomainScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Domain scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 任务取消/暂停检查
	if w.isTaskCancelled(p.TaskID) {
		log.Printf("[Worker] Task %d is cancelled/paused, skipping domain scan", p.TaskID)
		return nil
	}

	// 幂等检查
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
	w.markStageCompleted(p.TaskID, "domain")

	for _, r := range results {
		asset := r.ToAsset(p.TaskID)
		if err := w.store.CreateAsset(asset); err != nil {
			log.Printf("[Worker] Failed to save domain result: %v", err)
		}
	}

	var aliveTargets []string
	for _, r := range results {
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

	// 过滤排除目标
	aliveTargets = w.filterTargets(aliveTargets)

	// domain 阶段完成后，按单个目标粒度入队 alive 阶段
	return w.enqueue("domain", p.TaskID, aliveTargets)
}

func (w *Worker) handleAliveScan(ctx context.Context, t *asynq.Task) error {
	return w.cancelHandler(ctx, func() error {
		return w.doAliveScan(ctx, t)
	})
}

func (w *Worker) doAliveScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Alive scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 任务取消/暂停检查
	if w.isTaskCancelled(p.TaskID) {
		log.Printf("[Worker] Task %d is cancelled/paused, skipping alive scan", p.TaskID)
		return nil
	}

	// 幂等检查
	if w.isStageCompleted(p.TaskID, "alive") {
		log.Printf("[Worker] Alive scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "alive", "info", fmt.Sprintf("开始存活探测，目标数: %d", len(p.Targets)))

	// 每目标 QPS 限速
	for _, target := range p.Targets {
		if err := w.waitTargetLimit(ctx, target); err != nil {
			return skipRetry
		}
	}

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

	// 过滤排除目标
	aliveTargets = w.filterTargets(aliveTargets)

	// 按单个目标粒度入队 port 阶段
	return w.enqueue("alive", p.TaskID, aliveTargets)
}

func (w *Worker) handlePortScan(ctx context.Context, t *asynq.Task) error {
	return w.cancelHandler(ctx, func() error {
		return w.doPortScan(ctx, t)
	})
}

func (w *Worker) doPortScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Port scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 任务取消/暂停检查
	if w.isTaskCancelled(p.TaskID) {
		log.Printf("[Worker] Task %d is cancelled/paused, skipping port scan", p.TaskID)
		return nil
	}

	// 幂等检查
	if w.isStageCompleted(p.TaskID, "port") {
		log.Printf("[Worker] Port scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "port", "info", fmt.Sprintf("开始端口扫描，目标数: %d", len(p.Targets)))

	// 每目标 QPS 限速
	for _, target := range p.Targets {
		if err := w.waitTargetLimit(ctx, target); err != nil {
			return skipRetry
		}
	}

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
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 {
			log.Printf("[Worker] Invalid port in target %s, skipping", target)
			continue
		}
		// 检查端口是否被排除
		if w.isPortExcluded(portNum) {
			log.Printf("[Worker] Port %d excluded, skipping target %s", portNum, target)
			continue
		}
		results[host] = append(results[host], model.Port{
			Port:     portNum,
			Protocol: "tcp",
			State:    "open",
		})
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
			// 过滤排除端口
			if w.isPortExcluded(port.Port) {
				continue
			}
			port.AssetID = asset.ID
			w.store.CreatePort(&port)
			nextTargets = append(nextTargets, fmt.Sprintf("%s:%d", target, port.Port))
		}
	}

	if len(nextTargets) == 0 {
		log.Printf("[Worker] Port scan found no open ports, task_id=%d", p.TaskID)
		w.logTask(p.TaskID, "port", "warn", "端口扫描未发现开放端口")
		task, _ := w.store.GetTask(p.TaskID)
		task.Status = "completed"
		task.Progress = "done"
		return w.store.UpdateTask(task)
	}

	// 开放端口过多保护：截断为前 30 个端口，避免指纹扫描爆炸
	const maxPortsPerTarget = 30
	if len(nextTargets) > maxPortsPerTarget {
		log.Printf("[Worker] Too many open ports (%d), truncating to %d, task_id=%d",
			len(nextTargets), maxPortsPerTarget, p.TaskID)
		w.logTask(p.TaskID, "port", "warn",
			fmt.Sprintf("开放端口过多（%d），截断为前 %d 个以避免扫描爆炸", len(nextTargets), maxPortsPerTarget))
		nextTargets = nextTargets[:maxPortsPerTarget]
	}

	log.Printf("[Worker] Port scan found %d open ports, passing to next stage: %v", len(nextTargets), nextTargets)
	w.logTask(p.TaskID, "port", "info", fmt.Sprintf("端口扫描完成，发现 %d 个开放端口", len(nextTargets)))
	w.markStageCompleted(p.TaskID, "port")

	// 过滤排除目标
	nextTargets = w.filterTargets(nextTargets)

	// 按单个目标粒度入队 finger 阶段
	return w.enqueue("port", p.TaskID, nextTargets)
}

func (w *Worker) handleFingerScan(ctx context.Context, t *asynq.Task) error {
	return w.cancelHandler(ctx, func() error {
		return w.doFingerScan(ctx, t)
	})
}

func (w *Worker) doFingerScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Finger scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 任务取消/暂停检查
	if w.isTaskCancelled(p.TaskID) {
		log.Printf("[Worker] Task %d is cancelled/paused, skipping finger scan", p.TaskID)
		return nil
	}

	// 幂等检查
	if w.isStageCompleted(p.TaskID, "finger") {
		log.Printf("[Worker] Finger scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "finger", "info", fmt.Sprintf("开始指纹识别，目标数: %d", len(p.Targets)))

	// 每目标 QPS 限速
	for _, target := range p.Targets {
		if err := w.waitTargetLimit(ctx, target); err != nil {
			return skipRetry
		}
	}

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

		// 从数据库指纹模板查找匹配的 CPE
		if result.CPE == "" && len(result.Fingers) > 0 {
			for _, f := range result.Fingers {
				var tpl model.Template
				if err := w.store.DB.Where("category = ? AND name = ?", "finger", f.Name).First(&tpl).Error; err != nil {
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
			_, portStr, _ := net.SplitHostPort(target)
			var ports []model.Port
			isFallback := false
			if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 {
				w.store.DB.Where("asset_id = ? AND port = ?", asset.ID, portNum).Find(&ports)
			}
			if len(ports) == 0 {
				w.store.DB.Where("asset_id = ?", asset.ID).Find(&ports)
				if len(ports) > 0 {
					log.Printf("[Worker] Warning: port %s not found for asset %d, fallback to all ports", portStr, asset.ID)
					isFallback = true
				}
			}
			for i := range ports {
				updated := false
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

	// 过滤排除目标
	filteredTargets := w.filterTargets(p.Targets)

	// 按单个目标粒度入队 vuln 阶段
	return w.enqueue("finger", p.TaskID, filteredTargets)
}

func (w *Worker) handleVulnScan(ctx context.Context, t *asynq.Task) error {
	return w.cancelHandler(ctx, func() error {
		return w.doVulnScan(ctx, t)
	})
}

func (w *Worker) doVulnScan(ctx context.Context, t *asynq.Task) error {
	var p scheduler.ScanPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return err
	}
	log.Printf("[Worker] Vuln scan: task_id=%d, targets=%v", p.TaskID, p.Targets)

	// 任务取消/暂停检查
	if w.isTaskCancelled(p.TaskID) {
		log.Printf("[Worker] Task %d is cancelled/paused, skipping vuln scan", p.TaskID)
		return nil
	}

	// 幂等检查
	if w.isStageCompleted(p.TaskID, "vuln") {
		log.Printf("[Worker] Vuln scan already completed for task_id=%d, skipping", p.TaskID)
		return nil
	}

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("开始漏洞扫描，目标数: %d", len(p.Targets)))

	// 每目标 QPS 限速
	for _, target := range p.Targets {
		if err := w.waitTargetLimit(ctx, target); err != nil {
			return skipRetry
		}
	}

	// 复测任务：使用指定模板直接扫描
	if p.IsRetest && len(p.TemplateIDs) > 0 {
		return w.handleRetestScan(ctx, p)
	}

	// 收集每个目标的 CPE 和 Service
	var targetInfos []scanner.TargetServiceInfo
	for _, target := range p.Targets {
		info := scanner.TargetServiceInfo{Target: target}
		host := target
		if h, _, err := net.SplitHostPort(target); err == nil {
			host = h
		}

		var asset struct{ ID uint }
		w.store.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", p.TaskID, host, host).Select("id").Scan(&asset)
		log.Printf("[Worker] Vuln scan target=%s host=%s asset_id=%d", target, host, asset.ID)
		if asset.ID > 0 {
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

		inferredService := scanner.InferServiceByPort(target)
		if inferredService != "" {
			if info.Service == "" || info.Service == "unknown" ||
				(info.Service == "http" && inferredService != "http") {
				log.Printf("[Worker] Target %s service overridden by port inference: %s -> %s", target, info.Service, inferredService)
				info.Service = inferredService
			}
		}

		if info.Service == "" {
			if scanner.ProbeHTTPService(ctx, target, w.cfg.Scanner.InsecureTLS) {
				info.Service = "http"
				log.Printf("[Worker] Target %s detected as HTTP by probe", target)
			}
		}

		if info.Service == "" {
			info.Service = "http"
			log.Printf("[Worker] Target %s defaulting to http for vuln scan", target)
		}

		targetInfos = append(targetInfos, info)
	}

	var validTargets []string
	for _, info := range targetInfos {
		target := info.Target
		if isHTTPService(info.Service) && !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "http://" + target
		}
		validTargets = append(validTargets, target)
	}
	log.Printf("[Worker] Vuln scan validTargets: %v", validTargets)

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

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("模板匹配 %d 个，按服务协议筛选漏洞模板目录进行扫描", totalMatched))
	vulns, scanErr := scanner.VulnScanByService(ctx, validTargets, targetInfos, w.cfg)

	if scanErr != nil {
		w.logTask(p.TaskID, "vuln", "error", fmt.Sprintf("漏洞扫描失败: %v", scanErr))
		w.failTask(p.TaskID, scanErr.Error())
		return scanErr
	}

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("漏洞扫描完成，发现 %d 个漏洞", len(vulns)))
	w.markStageCompleted(p.TaskID, "vuln")
	for _, v := range vulns {
		w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("- %s [%s] %s", v.Name, v.Severity, v.URL))
	}

	for _, v := range vulns {
		v.TaskID = p.TaskID
		v.AssetID = resolveAssetID(w.store, p.TaskID, v.URL)
		w.store.CreateVuln(&v)
	}

	// vuln 是最后阶段，通过 enqueue 触发任务完成
	return w.enqueue("vuln", p.TaskID, nil)
}

// resolveAssetID 从漏洞 URL 解析出关联的资产 ID
// 支持多种 URL 格式：http://host:port/path, host:port, host
func resolveAssetID(s *store.Store, taskID uint, vulnURL string) uint {
	host := vulnURL

	// 1. 尝试从 HTTP URL 中提取 host
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		u, err := url.Parse(host)
		if err == nil {
			host = u.Hostname()
		} else {
			// url.Parse 失败，手动提取
			host = strings.TrimPrefix(host, "http://")
			host = strings.TrimPrefix(host, "https://")
			if idx := strings.Index(host, "/"); idx >= 0 {
				host = host[:idx]
			}
		}
	}

	// 2. 去掉端口
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if host == "" {
		return 0
	}

	// 3. 在 assets 表中查找匹配的资产
	var asset struct{ ID uint }
	s.DB.Table("assets").Where("task_id = ? AND (ip = ? OR domain = ?)", taskID, host, host).Select("id").Scan(&asset)
	return asset.ID
}

// handleRetestScan 处理复测任务：使用指定模板对目标重新验证
func (w *Worker) handleRetestScan(ctx context.Context, p scheduler.ScanPayload) error {
	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("复测扫描：使用 %d 个指定模板验证 %d 个目标", len(p.TemplateIDs), len(p.Targets)))

	// 获取模板文件路径
	var templatePaths []string
	for _, tplID := range p.TemplateIDs {
		var tpl model.Template
		if err := w.store.DB.Where("template_id = ?", tplID).First(&tpl).Error; err != nil {
			log.Printf("[Worker] Retest: template %s not found in DB, using as path", tplID)
			templatePaths = append(templatePaths, tplID)
			continue
		}
		if tpl.FilePath != "" {
			templatePaths = append(templatePaths, tpl.FilePath)
		}
	}

	// 确保目标有 HTTP 前缀
	var validTargets []string
	for _, target := range p.Targets {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "http://" + target
		}
		validTargets = append(validTargets, target)
	}

	vulns, scanErr := scanner.VulnScanWithTemplates(ctx, validTargets, templatePaths, w.cfg)
	if scanErr != nil {
		w.logTask(p.TaskID, "vuln", "error", fmt.Sprintf("复测扫描失败: %v", scanErr))
		w.failTask(p.TaskID, scanErr.Error())
		return scanErr
	}

	w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("复测扫描完成，发现 %d 个漏洞", len(vulns)))
	w.markStageCompleted(p.TaskID, "vuln")

	for _, v := range vulns {
		v.TaskID = p.TaskID
		v.AssetID = resolveAssetID(w.store, p.TaskID, v.URL)
		w.store.CreateVuln(&v)
		w.logTask(p.TaskID, "vuln", "info", fmt.Sprintf("- [复测] %s [%s] %s", v.Name, v.Severity, v.URL))
	}

	// 复测任务完成
	task, _ := w.store.GetTask(p.TaskID)
	if task != nil {
		task.Status = "completed"
		task.Progress = "done"
		w.store.UpdateTask(task)
	}
	return nil
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

func (w *Worker) isStageCompleted(taskID uint, stage string) bool {
	task, err := w.store.GetTask(taskID)
	if err != nil {
		return false
	}
	for _, s := range strings.Split(task.CompletedStages, ",") {
		if s == stage {
			return true
		}
	}
	return false
}

func (w *Worker) markStageCompleted(taskID uint, stage string) {
	task, err := w.store.GetTask(taskID)
	if err != nil {
		return
	}
	stages := strings.Split(task.CompletedStages, ",")
	for _, s := range stages {
		if s == stage {
			return
		}
	}
	if task.CompletedStages == "" {
		task.CompletedStages = stage
	} else {
		task.CompletedStages = task.CompletedStages + "," + stage
	}
	w.store.UpdateTask(task)
}

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

func isHTTPService(service string) bool {
	httpServices := map[string]bool{
		"http": true, "http-alt": true, "http-proxy": true, "https": true,
		"https-alt": true, "www": true, "web": true, "gunicorn": true,
		"nginx": true, "apache": true, "tomcat": true, "iis": true,
		"jetty": true, "lighttpd": true, "caddy": true,
	}
	return httpServices[service]
}
