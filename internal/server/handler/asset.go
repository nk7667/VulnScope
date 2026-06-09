package handler

import (
	"blackbox-scanner/internal/store"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type AssetHandler struct {
	store *store.Store
}

func NewAssetHandler(s *store.Store) *AssetHandler {
	return &AssetHandler{store: s}
}

func (h *AssetHandler) List(c *gin.Context) {
	taskID, _ := strconv.Atoi(c.DefaultQuery("task_id", "0"))
	dedup := c.DefaultQuery("dedup", "true") // 默认去重
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize

	// 去重模式：跨任务合并相同 IP/域名
	if dedup == "true" && taskID == 0 {
		assets, total, err := h.store.ListAssetsDedup(offset, pageSize)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": assets, "total": total, "page": page, "page_size": pageSize})
		return
	}

	// 按任务筛选或非去重模式
	assets, total, err := h.store.ListAssets(uint(taskID), offset, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": assets, "total": total, "page": page, "page_size": pageSize})
}

func (h *AssetHandler) Get(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	a, err := h.store.GetAsset(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

func (h *AssetHandler) ListPorts(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	ports, err := h.store.ListPorts(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": ports})
}

func (h *AssetHandler) ListFingers(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	fingers, err := h.store.ListFingers(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": fingers})
}
