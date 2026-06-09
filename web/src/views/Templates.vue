<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 16px; font-weight: 600;">Nuclei 模板配置</span>
            <span style="font-size: 12px; color: #909399; margin-left: 8px;">同步官方 POC 模板或添加自定义模板，漏洞扫描阶段将使用这些模板</span>
          </div>
          <div style="display: flex; gap: 8px;">
            <el-dropdown @command="handleImportCmd">
              <el-button type="warning">
                导入模板 <el-icon class="el-icon--right"><ArrowDown /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="repo">从 Git 仓库导入</el-dropdown-item>
                  <el-dropdown-item command="dir">从本地目录导入</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <el-button type="success" :loading="syncing" @click="handleSync">
              {{ syncing ? '同步中...' : '同步官方模板' }}
            </el-button>
            <el-button type="primary" @click="openAddDialog">添加自定义模板</el-button>
          </div>
        </div>
      </template>

      <!-- 搜索栏 -->
      <div style="margin-bottom: 16px; display: flex; gap: 12px; align-items: center;">
        <el-input
          v-model="searchKeyword"
          placeholder="搜索模板名称或标签"
          clearable
          style="width: 280px;"
          @keyup.enter="handleSearch"
          @clear="handleSearch"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-select v-model="searchSeverity" placeholder="严重等级" clearable style="width: 120px;" @change="handleSearch">
          <el-option label="Critical" value="critical" />
          <el-option label="High" value="high" />
          <el-option label="Medium" value="medium" />
          <el-option label="Low" value="low" />
          <el-option label="Info" value="info" />
        </el-select>
        <el-select v-model="searchType" placeholder="来源" clearable style="width: 110px;" @change="handleSearch">
          <el-option label="官方" value="official" />
          <el-option label="自定义" value="custom" />
          <el-option label="第三方" value="thirdparty" />
        </el-select>
        <el-select v-model="searchCategory" placeholder="分类" clearable style="width: 110px;" @change="handleSearch">
          <el-option label="指纹模板" value="finger" />
          <el-option label="漏洞模板" value="vuln" />
        </el-select>
        <el-button @click="handleSearch">搜索</el-button>
        <span style="font-size: 12px; color: #909399; margin-left: auto;">共 {{ total }} 条</span>
      </div>

      <!-- 同步进度条 -->
      <div v-if="syncProgress" style="margin-bottom: 16px;">
        <el-alert :type="syncProgress.phase === 'error' ? 'error' : syncProgress.phase === 'done' ? 'success' : 'info'" :closable="false">
          <template #title>
            <div style="display: flex; align-items: center; gap: 12px;">
              <span>{{ syncProgress.message }}</span>
              <el-tag v-if="syncProgress.phase === 'downloading'" type="warning" size="small">
                <el-icon class="is-loading"><Loading /></el-icon> 下载中
              </el-tag>
              <el-tag v-else-if="syncProgress.phase === 'scanning'" type="info" size="small">
                <el-icon class="is-loading"><Loading /></el-icon> 解析中
              </el-tag>
              <el-tag v-else-if="syncProgress.phase === 'done'" type="success" size="small">已完成</el-tag>
              <el-tag v-else-if="syncProgress.phase === 'error'" type="danger" size="small">失败</el-tag>
            </div>
          </template>
        </el-alert>

        <el-progress
          v-if="syncProgress.total_files > 0"
          :percentage="syncProgress.total_files ? Math.round(syncProgress.processed / syncProgress.total_files * 100) : 0"
          :format="() => `${syncProgress.processed} / ${syncProgress.total_files}`"
          style="margin-top: 8px;"
          :status="syncProgress.phase === 'done' ? 'success' : syncProgress.phase === 'error' ? 'exception' : ''"
        />

        <div v-if="syncProgress.phase === 'done' || syncProgress.running" style="margin-top: 8px; display: flex; gap: 16px; font-size: 13px; color: #666;">
          <span>入库: <b style="color: #67c23a;">{{ syncProgress.synced }}</b></span>
          <span>跳过: <b style="color: #e6a23c;">{{ syncProgress.skipped }}</b></span>
          <span>失败: <b style="color: #f56c6c;">{{ syncProgress.failed }}</b></span>
          <span v-if="syncProgress.template_dir">目录: {{ syncProgress.template_dir }}</span>
        </div>
      </div>

      <el-table :data="templates" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="模板名称" show-overflow-tooltip />
        <el-table-column prop="type" label="来源" width="80">
          <template #default="{ row }">
            <el-tag :type="typeTagStyle(row.type)" size="small">{{ typeLabel(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="category" label="分类" width="90">
          <template #default="{ row }">
            <el-tag :type="row.category === 'finger' ? 'primary' : 'danger'" size="small">
              {{ row.category === 'finger' ? '指纹' : '漏洞' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" width="70">
          <template #default="{ row }">
            <span style="font-size: 12px;">{{ row.protocol || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="等级" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.severity" :type="severityTagType(row.severity)" size="small">
              {{ row.severity }}
            </el-tag>
            <span v-else style="color: #c0c4cc; font-size: 12px;">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="tags" label="标签" show-overflow-tooltip />
        <el-table-column prop="enabled" label="启用" width="70">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'danger'" size="small">{{ row.enabled ? '是' : '否' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" link @click="showDetail(row)">详情</el-button>
            <el-button type="danger" size="small" link @click="handleDelete(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        style="margin-top: 16px; justify-content: flex-end;"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        layout="total, prev, pager, next"
        @current-change="loadTemplates"
      />
    </el-card>

    <!-- 模板详情对话框 -->
    <el-dialog v-model="detailVisible" :title="currentTemplate.name || '模板详情'" width="750px">
      <el-descriptions :column="2" border size="small" style="margin-bottom: 16px;">
        <el-descriptions-item label="模板名称" :span="2">{{ currentTemplate.name }}</el-descriptions-item>
        <el-descriptions-item label="来源">
          <el-tag :type="typeTagStyle(currentTemplate.type)" size="small">{{ typeLabel(currentTemplate.type) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="分类">
          <el-tag :type="currentTemplate.category === 'finger' ? 'primary' : 'danger'" size="small">
            {{ currentTemplate.category === 'finger' ? '指纹模板' : '漏洞模板' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="严重等级">
          <el-tag v-if="currentTemplate.severity" :type="severityTagType(currentTemplate.severity)" size="small">
            {{ currentTemplate.severity }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentTemplate.protocol || '-' }}</el-descriptions-item>
        <el-descriptions-item label="CPE" :span="2">{{ currentTemplate.cpe || '-' }}</el-descriptions-item>
        <el-descriptions-item label="模板ID" :span="2">{{ currentTemplate.template_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="标签" :span="2">{{ currentTemplate.tags || '-' }}</el-descriptions-item>
        <el-descriptions-item label="文件路径" :span="2">{{ currentTemplate.file_path || '-' }}</el-descriptions-item>
        <el-descriptions-item label="启用状态">
          <el-tag :type="currentTemplate.enabled ? 'success' : 'danger'" size="small">
            {{ currentTemplate.enabled ? '已启用' : '已禁用' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ currentTemplate.created_at }}</el-descriptions-item>
      </el-descriptions>
      <div style="margin-bottom: 8px; font-size: 13px; font-weight: 600; color: #303133;">YAML 内容</div>
      <el-input
        type="textarea"
        :model-value="currentTemplate.content"
        :rows="16"
        readonly
        style="font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; font-size: 12.5px;"
      />
    </el-dialog>

    <!-- 添加模板对话框 -->
    <el-dialog v-model="showAddDialog" title="添加 Nuclei 模板" width="700px">
      <el-form :model="addForm" label-width="80px">
        <el-form-item label="模板名称">
          <el-input v-model="addForm.name" placeholder="输入模板名称" />
        </el-form-item>
        <el-form-item label="严重等级">
          <el-select v-model="addForm.severity" placeholder="选择等级">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
            <el-option label="Info" value="info" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签">
          <el-input v-model="addForm.tags" placeholder="逗号分隔" />
        </el-form-item>
        <el-form-item label="模板内容">
          <div style="width: 100%;">
            <div style="margin-bottom: 6px;">
              <el-link type="primary" :underline="false" @click="fillExample" style="font-size: 12px;">
                填充示例模板
              </el-link>
            </div>
            <el-input v-model="addForm.content" type="textarea" :rows="14" placeholder="粘贴 Nuclei YAML 模板内容" />
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleAdd">添加</el-button>
      </template>
    </el-dialog>

    <!-- 从 Git 仓库导入对话框 -->
    <el-dialog v-model="showRepoDialog" title="从 Git 仓库导入模板" width="550px">
      <el-alert type="info" :closable="false" style="margin-bottom: 16px;">
        <template #title>输入第三方 nuclei 模板仓库地址，系统将自动克隆并解析入库</template>
      </el-alert>
      <el-form :model="repoForm" label-width="90px">
        <el-form-item label="仓库地址">
          <el-input v-model="repoForm.repo_url" placeholder="https://github.com/xxx/nuclei-templates.git" />
        </el-form-item>
        <el-form-item label="来源标记">
          <el-input v-model="repoForm.name" placeholder="自定义来源名称（可选）" />
        </el-form-item>
      </el-form>
      <div style="font-size: 12px; color: #909399; margin-top: 8px;">
        常用第三方模板库：<br/>
        • <el-link type="primary" :underline="false" @click="repoForm.repo_url = 'https://github.com/projectdiscovery/nuclei-templates.git'">projectdiscovery/nuclei-templates</el-link> (官方)<br/>
        • <el-link type="primary" :underline="false" @click="repoForm.repo_url = 'https://github.com/geeknik/nuclei-templates.git'">geeknik/nuclei-templates</el-link><br/>
        • <el-link type="primary" :underline="false" @click="repoForm.repo_url = 'https://github.com/nucleusec/nuclei-templates.git'">nucleusec/nuclei-templates</el-link>
      </div>
      <template #footer>
        <el-button @click="showRepoDialog = false">取消</el-button>
        <el-button type="primary" :loading="importing" @click="handleImportRepo">开始导入</el-button>
      </template>
    </el-dialog>

    <!-- 从本地目录导入对话框 -->
    <el-dialog v-model="showDirDialog" title="从本地目录导入模板" width="550px">
      <el-alert type="info" :closable="false" style="margin-bottom: 16px;">
        <template #title>输入本地目录路径，系统将扫描该目录下所有 YAML 文件并入库</template>
      </el-alert>
      <el-form :model="dirForm" label-width="90px">
        <el-form-item label="目录路径">
          <el-input v-model="dirForm.dir_path" placeholder="D:\templates 或 /home/user/templates" />
        </el-form-item>
        <el-form-item label="来源标记">
          <el-input v-model="dirForm.name" placeholder="自定义来源名称（可选，默认 thirdparty）" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDirDialog = false">取消</el-button>
        <el-button type="primary" :loading="importing" @click="handleImportDir">开始导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { getTemplates, createTemplate, deleteTemplate, syncTemplates, getSyncProgress, importRepo, importDir } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Loading, Search, ArrowDown } from '@element-plus/icons-vue'

const templates = ref([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const showAddDialog = ref(false)
const showRepoDialog = ref(false)
const showDirDialog = ref(false)
const syncing = ref(false)
const importing = ref(false)
const syncProgress = ref(null)
let pollTimer = null

// 搜索条件
const searchKeyword = ref('')
const searchSeverity = ref('')
const searchType = ref('')
const searchCategory = ref('')

// 详情
const detailVisible = ref(false)
const currentTemplate = ref({})

// 表单
const addForm = ref({ name: '', severity: '', tags: '', content: '' })
const repoForm = ref({ repo_url: '', name: '' })
const dirForm = ref({ dir_path: '', name: '' })

// 示例模板
const exampleTemplate = `id: custom-sqli-detection

info:
  name: SQL Injection Detection
  author: custom
  severity: high
  description: 检测 SQL 注入漏洞
  tags: sqli,sql,injection

http:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 500
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
        condition: or`

function severityTagType(severity) {
  const map = { critical: 'danger', high: 'warning', medium: '', low: 'info', info: 'success' }
  return map[severity] || ''
}

function typeLabel(type) {
  const map = { official: '官方', custom: '自定义', thirdparty: '第三方' }
  return map[type] || type
}

function typeTagStyle(type) {
  const map = { official: '', custom: 'success', thirdparty: 'warning' }
  return map[type] || 'info'
}

function fillExample() {
  addForm.value.content = exampleTemplate
  addForm.value.name = 'SQL Injection Detection'
  addForm.value.severity = 'high'
  addForm.value.tags = 'sqli,sql,injection'
}

function openAddDialog() {
  addForm.value = { name: '', severity: '', tags: '', content: '' }
  showAddDialog.value = true
}

function handleImportCmd(cmd) {
  if (cmd === 'repo') {
    repoForm.value = { repo_url: '', name: '' }
    showRepoDialog.value = true
  } else if (cmd === 'dir') {
    dirForm.value = { dir_path: '', name: '' }
    showDirDialog.value = true
  }
}

async function loadTemplates() {
  const params = { page: page.value, page_size: pageSize.value }
  if (searchKeyword.value) params.keyword = searchKeyword.value
  if (searchSeverity.value) params.severity = searchSeverity.value
  if (searchType.value) params.type = searchType.value
  if (searchCategory.value) params.type = searchCategory.value
  const { data } = await getTemplates(params)
  templates.value = data.data || []
  total.value = data.total || 0
}

function handleSearch() {
  page.value = 1
  loadTemplates()
}

function showDetail(row) {
  currentTemplate.value = row
  detailVisible.value = true
}

async function pollSyncProgress() {
  try {
    const { data } = await getSyncProgress()
    if (data.running || data.phase === 'done' || data.phase === 'error') {
      syncProgress.value = data
    }
    if (!data.running) {
      syncing.value = false
      if (data.phase === 'done') {
        ElMessage.success(`同步完成！入库 ${data.synced} 个模板`)
        page.value = 1
        loadTemplates()
      }
      stopPolling()
    }
  } catch {
    stopPolling()
  }
}

function startPolling() {
  stopPolling()
  pollTimer = setInterval(pollSyncProgress, 1500)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function handleSync() {
  try {
    await ElMessageBox.confirm(
      '将从 nuclei 官方仓库下载最新 POC 模板并同步到数据库，可能需要几分钟时间。是否继续？',
      '同步官方模板',
      { type: 'info', confirmButtonText: '开始同步', cancelButtonText: '取消' }
    )
  } catch {
    return
  }

  syncing.value = true
  syncProgress.value = { running: true, phase: 'downloading', message: '正在启动同步...', total_files: 0, processed: 0, synced: 0, skipped: 0, failed: 0 }

  try {
    await syncTemplates()
    startPolling()
  } catch (err) {
    const msg = err.response?.data?.error || '同步启动失败'
    ElMessage.error(msg)
    syncing.value = false
    syncProgress.value = null
  }
}

async function handleImportRepo() {
  if (!repoForm.value.repo_url) {
    ElMessage.warning('请输入仓库地址')
    return
  }
  importing.value = true
  try {
    const { data } = await importRepo(repoForm.value)
    ElMessage.success(data.message)
    showRepoDialog.value = false
    page.value = 1
    loadTemplates()
  } catch (err) {
    ElMessage.error(err.response?.data?.error || '导入失败')
  } finally {
    importing.value = false
  }
}

async function handleImportDir() {
  if (!dirForm.value.dir_path) {
    ElMessage.warning('请输入目录路径')
    return
  }
  importing.value = true
  try {
    const { data } = await importDir(dirForm.value)
    ElMessage.success(data.message)
    showDirDialog.value = false
    page.value = 1
    loadTemplates()
  } catch (err) {
    ElMessage.error(err.response?.data?.error || '导入失败')
  } finally {
    importing.value = false
  }
}

async function handleAdd() {
  await createTemplate(addForm.value)
  ElMessage.success('模板添加成功')
  showAddDialog.value = false
  loadTemplates()
}

async function handleDelete(id) {
  await ElMessageBox.confirm('确认删除该模板?', '提示', { type: 'warning' })
  await deleteTemplate(id)
  ElMessage.success('删除成功')
  loadTemplates()
}

onMounted(async () => {
  loadTemplates()
  try {
    const { data } = await getSyncProgress()
    if (data.running) {
      syncing.value = true
      syncProgress.value = data
      startPolling()
    } else if (data.phase === 'done' || data.phase === 'error') {
      syncProgress.value = data
    }
  } catch {}
})

onUnmounted(stopPolling)
</script>
