package main

import (
	"vulnscope/internal/checker"
	"vulnscope/internal/config"
	"vulnscope/internal/model"
	"vulnscope/internal/scheduler"
	"vulnscope/internal/server"
	"vulnscope/internal/store"
	worker "vulnscope/internal/worker"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	mode := flag.String("mode", "", "运行模式: server / worker / all (覆盖配置文件)")
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 命令行参数覆盖配置文件
	if *mode != "" {
		cfg.Mode = *mode
	}

	log.Printf("========================================")
	log.Printf("  黑盒扫描器启动")
	log.Printf("  模式: %s", cfg.Mode)
	log.Printf("  API:  %s", cfg.Server.Addr)
	log.Printf("  Redis: %s", cfg.Redis.Addr)
	log.Printf("========================================")

	// 前置检查：nmap / nuclei 可用性
	if cfg.Mode == "worker" || cfg.Mode == "all" {
		log.Println("[Main] 正在检查扫描工具...")
		nmapPath, nucleiPath, warnings := checker.CheckAndInstall(cfg.Scanner.NmapPath, cfg.Scanner.NucleiPath)
		cfg.Scanner.NmapPath = nmapPath
		cfg.Scanner.NucleiPath = nucleiPath
		for _, w := range warnings {
			log.Printf("[Main] ⚠ %s", w)
		}
		if len(warnings) > 0 {
			log.Println("[Main] 部分工具不可用，扫描功能可能受限")
		} else {
			log.Println("[Main] 所有扫描工具已就绪")
		}
	}

	// 初始化数据库
	s, err := store.New(&cfg.Database)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	// 根据模式启动
	startServer := cfg.Mode == "server" || cfg.Mode == "all"
	startWorker := cfg.Mode == "worker" || cfg.Mode == "all"

	if !startServer && !startWorker {
		log.Fatalf("无效的运行模式: %s (可选: server / worker / all)", cfg.Mode)
	}

	// Scheduler 统一管理入队（唯一 asynq.Client 入口）
	var sched *scheduler.Scheduler
	if startServer {
		sched = scheduler.New(&cfg.Redis, s, cfg)
	}

	// 启动 Worker（通过 Scheduler 回调入队，不再持有 asynq.Client）
	var w *worker.Worker
	if startWorker {
		// 使用 Scheduler 的入队方法作为回调
		var enqueueFn worker.EnqueueFunc
		if sched != nil {
			enqueueFn = sched.EnqueueNextStage
		} else {
			// Worker-only 模式：创建独立的 Scheduler 仅用于入队
			enqueueSched := scheduler.New(&cfg.Redis, s, cfg)
			enqueueFn = enqueueSched.EnqueueNextStage
		}
		w = worker.New(&cfg.Redis, s, cfg, enqueueFn)
		go func() {
			if err := w.Run(); err != nil {
				log.Fatalf("Worker 启动失败: %v", err)
			}
		}()
		log.Println("[Main] Worker 已启动")
	}

	// 启动 API Server
	if startServer {
		r := server.SetupRouter(s, sched, cfg)
		go func() {
			if err := r.Run(cfg.Server.Addr); err != nil {
				log.Fatalf("API Server 启动失败: %v", err)
			}
		}()
		log.Printf("[Main] API Server 已启动, 监听 %s", cfg.Server.Addr)

		// 节点状态同步：定期将节点状态写入数据库
		go syncNodeStatus(s, cfg)
	}

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	fmt.Println()
	log.Printf("[Main] 收到信号 %v, 正在优雅关闭...", sig)

	// 优雅关闭 Worker：等待正在处理的任务完成
	if w != nil {
		log.Println("[Main] 正在关闭 Worker，等待正在处理的任务完成...")
		w.Shutdown()
		log.Println("[Main] Worker 已关闭")
	}

	// 关闭 Scheduler 的 asynq.Client
	if sched != nil {
		sched.Close()
	}

	log.Println("[Main] 已关闭")
}

// syncNodeStatus 定期同步节点状态到数据库
func syncNodeStatus(s *store.Store, cfg *config.Config) {
	hostname, _ := os.Hostname()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var nodeCfg model.Config
		key := fmt.Sprintf("node:%s:status", hostname)
		if err := s.DB.Where("`key` = ?", key).First(&nodeCfg).Error; err != nil {
			s.DB.Create(&model.Config{
				Key:   key,
				Value: fmt.Sprintf("alive:%s", time.Now().Format(time.RFC3339)),
			})
		} else {
			nodeCfg.Value = fmt.Sprintf("alive:%s", time.Now().Format(time.RFC3339))
			s.DB.Save(&nodeCfg)
		}
	}
}
