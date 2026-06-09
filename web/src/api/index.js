import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// ========== 目标管理 ==========
export const getTargets = (params) => api.get('/targets', { params })
export const createTarget = (data) => api.post('/targets', data)
export const batchImportTargets = (data) => api.post('/targets/import', data)
export const deleteTarget = (id) => api.delete(`/targets/${id}`)

// ========== 任务管理 ==========
export const getTasks = (params) => api.get('/tasks', { params })
export const createTask = (data) => api.post('/tasks', data)
export const deleteTask = (id) => api.delete(`/tasks/${id}`)
export const getTaskLogs = (id, params) => api.get(`/tasks/${id}/logs`, { params })

// ========== 资产管理 ==========
export const getAssets = (params) => api.get('/assets', { params })
export const getAssetPorts = (id) => api.get(`/assets/${id}/ports`)
export const getAssetFingers = (id) => api.get(`/assets/${id}/fingers`)

// ========== 漏洞管理 ==========
export const getVulns = (params) => api.get('/vulns', { params })
export const updateVulnStatus = (id, data) => api.put(`/vulns/${id}/status`, data)

// ========== 模板管理 ==========
export const getTemplates = (params) => api.get('/templates', { params })
export const createTemplate = (data) => api.post('/templates', data)
export const deleteTemplate = (id) => api.delete(`/templates/${id}`)
export const syncTemplates = () => api.post('/templates/sync')
export const getSyncProgress = () => api.get('/templates/sync/progress')
export const importRepo = (data) => api.post('/templates/import/repo', data, { timeout: 300000 })
export const importDir = (data) => api.post('/templates/import/dir', data, { timeout: 300000 })

export default api
