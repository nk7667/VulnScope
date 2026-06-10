package main

import (
	"blackbox-scanner/internal/checker"
	"blackbox-scanner/internal/config"
	"blackbox-scanner/internal/scheduler"
	"blackbox-scanner/internal/server"
	"blackbox-scanner/internal/store"
	worker "blackbox-scanner/internal/worker"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
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
	log.Printf("  DB:   %s", cfg.Database.DSN)
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

	// Scheduler 只在 server 模式下需要（用于 API 创建任务时入队）
	var sched *scheduler.Scheduler
	if startServer {
		sched = scheduler.New(&cfg.Redis, s, cfg)
	}

	// 启动 Worker（Worker 自己持有 asynq.Client，不依赖 Scheduler）
	if startWorker {
		w := worker.New(&cfg.Redis, s, cfg)
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
	}

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	fmt.Println()
	log.Printf("[Main] 收到信号 %v, 正在关闭...", sig)
	if sched != nil {
		sched.Close()
	}
	log.Println("[Main] 已关闭")
}
