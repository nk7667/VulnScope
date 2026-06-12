package handler

import (
	"vulnscope/internal/model"
	"vulnscope/internal/store"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type TargetHandler struct {
	store *store.Store
}

func NewTargetHandler(s *store.Store) *TargetHandler {
	return &TargetHandler{store: s}
}

func (h *TargetHandler) Create(c *gin.Context) {
	var req struct {
		Target string `json:"target" binding:"required"`
		Type   string `json:"type"`
		Group  string `json:"group"`
		Tags   string `json:"tags"`
		Memo   string `json:"memo"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = detectType(req.Target)
	}
	t := &model.Target{
		Target: req.Target,
		Type:   req.Type,
		Group:  req.Group,
		Tags:   req.Tags,
		Memo:   req.Memo,
	}
	if err := h.store.CreateTarget(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, t)
}

// BatchImport 批量导入目标
func (h *TargetHandler) BatchImport(c *gin.Context) {
	var req struct {
		Targets []string `json:"targets" binding:"required"`
		Group   string   `json:"group"`
		Tags    string   `json:"tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created := make([]*model.Target, 0, len(req.Targets))
	for _, t := range req.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		target := &model.Target{
			Target: t,
			Type:   detectType(t),
			Group:  req.Group,
			Tags:   req.Tags,
		}
		if err := h.store.CreateTarget(target); err != nil {
			continue
		}
		created = append(created, target)
	}
	c.JSON(http.StatusCreated, gin.H{"created": len(created), "data": created})
}

func (h *TargetHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize

	targets, total, err := h.store.ListTargets(offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": targets, "total": total, "page": page, "page_size": pageSize})
}

func (h *TargetHandler) Get(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	t, err := h.store.GetTarget(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, t)
}

func (h *TargetHandler) Delete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := h.store.DeleteTarget(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// detectType 根据输入内容自动判断目标类型
func detectType(target string) string {
	if strings.Contains(target, "/") {
		return "cidr"
	}
	if strings.Contains(target, ".") && !strings.Contains(target, " ") {
		// 简单判断: 纯数字和点 → IP
		parts := strings.Split(target, ".")
		if len(parts) == 4 {
			return "ip"
		}
	}
	return "domain"
}
