package handler

import (
	"blackbox-scanner/internal/store"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type VulnHandler struct {
	store *store.Store
}

func NewVulnHandler(s *store.Store) *VulnHandler {
	return &VulnHandler{store: s}
}

func (h *VulnHandler) List(c *gin.Context) {
	taskID, _ := strconv.Atoi(c.DefaultQuery("task_id", "0"))
	severity := c.DefaultQuery("severity", "")
	status := c.DefaultQuery("status", "")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize

	vulns, total, err := h.store.ListVulns(uint(taskID), severity, status, offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": vulns, "total": total, "page": page, "page_size": pageSize})
}

func (h *VulnHandler) Get(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	v, err := h.store.GetVuln(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, v)
}

func (h *VulnHandler) UpdateStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	v, err := h.store.GetVuln(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Status int `json:"status" binding:"required"` // 0:未确认, 1:误报, 2:确认, 3:忽略
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v.Status = req.Status
	if err := h.store.UpdateVuln(v); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, v)
}
