package server

import (
	"blackbox-scanner/internal/scheduler"
	"blackbox-scanner/internal/server/handler"
	"blackbox-scanner/internal/store"

	"github.com/gin-gonic/gin"
)

func SetupRouter(s *store.Store, sched *scheduler.Scheduler) *gin.Engine {
	r := gin.Default()

	// CORS — 前端独立部署，跨域访问 API
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	api := r.Group("/api")
	{
		// 目标管理
		targetH := handler.NewTargetHandler(s)
		api.POST("/targets", targetH.Create)
		api.POST("/targets/import", targetH.BatchImport)
		api.GET("/targets", targetH.List)
		api.GET("/targets/:id", targetH.Get)
		api.DELETE("/targets/:id", targetH.Delete)

		// 任务管理
		taskH := handler.NewTaskHandler(s, sched)
		api.POST("/tasks", taskH.Create)
		api.GET("/tasks", taskH.List)
		api.GET("/tasks/:id", taskH.Get)
		api.DELETE("/tasks/:id", taskH.Delete)
		api.GET("/tasks/:id/logs", taskH.GetLogs)

		// 资产管理
		assetH := handler.NewAssetHandler(s)
		api.GET("/assets", assetH.List)
		api.GET("/assets/:id", assetH.Get)
		api.GET("/assets/:id/ports", assetH.ListPorts)
		api.GET("/assets/:id/fingers", assetH.ListFingers)

		// 漏洞管理
		vulnH := handler.NewVulnHandler(s)
		api.GET("/vulns", vulnH.List)
		api.GET("/vulns/:id", vulnH.Get)
		api.PUT("/vulns/:id/status", vulnH.UpdateStatus)

		// 模板管理
		templateH := handler.NewTemplateHandler(s)
		api.POST("/templates", templateH.Create)
		api.GET("/templates", templateH.List)
		api.DELETE("/templates/:id", templateH.Delete)
		api.DELETE("/templates", templateH.ClearAll)
		api.POST("/templates/sync", templateH.Sync)
		api.GET("/templates/sync/progress", templateH.SyncProgress)
		api.POST("/templates/import/repo", templateH.ImportRepo)
		api.POST("/templates/import/dir", templateH.ImportDir)
	}

	return r
}
