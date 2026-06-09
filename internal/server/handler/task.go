package handler

import (
	"blackbox-scanner/internal/model"
	"blackbox-scanner/internal/scheduler"
	"blackbox-scanner/internal/store"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type TaskHandler struct {
	store     *store.Store
	scheduler *scheduler.Scheduler
}

func NewTaskHandler(s *store.Store, sched *scheduler.Scheduler) *TaskHandler {
	return &TaskHandler{store: s, scheduler: sched}
}

func (h *TaskHandler) Create(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		TargetIDs string `json:"target_ids" binding:"required"` // 逗号分隔的目标ID
		Type      int    `json:"type"`                          // 0:常规, 1:复测
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	t := &model.Task{
		Name:      req.Name,
		TargetIDs: req.TargetIDs,
		Type:      req.Type,
		Status:    "pending",
	}
	if err := h.store.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 触发调度器入队
	go h.scheduler.EnqueueTask(t.ID)

	c.JSON(http.StatusCreated, t)
}

func (h *TaskHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize

	tasks, total, err := h.store.ListTasks(offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 填充每个任务的漏洞数和指纹数
	for i := range tasks {
		vulnCount, _ := h.store.CountVulnsByTask(tasks[i].ID)
		fingerCount, _ := h.store.CountFingersByTask(tasks[i].ID)
		tasks[i].VulnCount = vulnCount
		tasks[i].FingerCount = fingerCount
	}

	c.JSON(http.StatusOK, gin.H{"data": tasks, "total": total, "page": page, "page_size": pageSize})
}

func (h *TaskHandler) Get(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	t, err := h.store.GetTask(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	// 填充漏洞数和指纹数
	vulnCount, _ := h.store.CountVulnsByTask(t.ID)
	fingerCount, _ := h.store.CountFingersByTask(t.ID)
	t.VulnCount = vulnCount
	t.FingerCount = fingerCount

	c.JSON(http.StatusOK, t)
}

func (h *TaskHandler) Delete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := h.store.DeleteTask(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *TaskHandler) GetLogs(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	offset := (page - 1) * pageSize

	logs, total, err := h.store.ListTaskLogs(uint(id), offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "page": page, "page_size": pageSize})
}
