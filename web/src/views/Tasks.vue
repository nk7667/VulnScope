<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 16px; font-weight: 600;">扫描任务</span>
            <span style="font-size: 12px; color: #909399; margin-left: 8px;">选择目标发起扫描，系统将自动执行：域名解析→存活探测→端口扫描→指纹识别→漏洞扫描</span>
          </div>
          <el-button type="primary" @click="showCreateDialog = true">创建任务</el-button>
        </div>
      </template>

      <el-table :data="tasks" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="任务名称" />
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tooltip v-if="row.status === 'failed' && row.error" :content="row.error" placement="top">
              <el-tag type="danger" size="small">{{ statusLabel(row.status) }}</el-tag>
            </el-tooltip>
            <el-tag v-else :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="当前阶段" width="120">
          <template #default="{ row }">
            <span>{{ progressLabel(row.progress) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            {{ row.type === 0 ? '常规' : '复测' }}
          </template>
        </el-table-column>
        <el-table-column label="扫描结果" width="160">
          <template #default="{ row }">
            <div v-if="row.vuln_count > 0 || row.finger_count > 0">
              <el-tag v-if="row.vuln_count > 0" type="danger" size="small" style="margin-right: 4px;">漏洞 {{ row.vuln_count }}</el-tag>
              <el-tag v-if="row.finger_count > 0" type="success" size="small">指纹 {{ row.finger_count }}</el-tag>
            </div>
            <span v-else style="color: #909399; font-size: 12px;">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button type="primary" size="small" link @click="handleShowLogs(row.id)">日志</el-button>
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
        @current-change="loadTasks"
      />
    </el-card>

    <!-- 创建任务对话框 -->
    <el-dialog v-model="showCreateDialog" title="创建扫描任务" width="500px">
      <el-form :model="createForm" label-width="80px">
        <el-form-item label="任务名称">
          <el-input v-model="createForm.name" placeholder="输入任务名称" />
        </el-form-item>
        <el-form-item label="选择目标">
          <el-select v-model="createForm.selectedTargets" multiple placeholder="选择扫描目标" style="width: 100%">
            <el-option v-for="t in allTargets" :key="t.id" :label="`${t.target} (${t.type})`" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="任务类型">
          <el-radio-group v-model="createForm.type">
            <el-radio :value="0">常规扫描</el-radio>
            <el-radio :value="1">复测扫描</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 任务日志对话框 -->
    <el-dialog v-model="showLogsDialog" title="任务执行日志" width="700px">
      <el-timeline v-if="taskLogs.length > 0">
        <el-timeline-item
          v-for="log in taskLogs"
          :key="log.id"
          :timestamp="log.created_at"
          :type="logLevelType(log.level)"
          placement="top"
        >
          <div>
            <el-tag :type="stageTagType(log.stage)" size="small" style="margin-right: 8px;">{{ stageLabel(log.stage) }}</el-tag>
            <span :style="{ color: log.level === 'error' ? '#f56c6c' : log.level === 'warn' ? '#e6a23c' : '#606266' }">{{ log.message }}</span>
          </div>
        </el-timeline-item>
      </el-timeline>
      <el-empty v-else description="暂无日志" />
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getTasks, createTask, deleteTask, getTargets, getTaskLogs } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'

const tasks = ref([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const showCreateDialog = ref(false)
const allTargets = ref([])
const createForm = ref({ name: '', selectedTargets: [], type: 0 })
const showLogsDialog = ref(false)
const taskLogs = ref([])

function statusType(s) {
  const map = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }
  return map[s] || 'info'
}
function statusLabel(s) {
  const map = { pending: '待执行', running: '执行中', completed: '已完成', failed: '失败' }
  return map[s] || s
}
function progressLabel(p) {
  const map = { '': '未开始', domain: '域名解析', alive: '存活探测', port: '端口扫描', finger: '指纹识别', vuln: '漏洞扫描', done: '已完成' }
  return map[p] || p
}
function stageLabel(s) {
  const map = { system: '系统', domain: '域名', alive: '存活', port: '端口', finger: '指纹', vuln: '漏洞' }
  return map[s] || s
}
function stageTagType(s) {
  const map = { system: 'info', domain: 'primary', alive: 'success', port: 'warning', finger: '', vuln: 'danger' }
  return map[s] || 'info'
}
function logLevelType(level) {
  const map = { info: 'primary', warn: 'warning', error: 'danger' }
  return map[level] || 'primary'
}

async function loadTasks() {
  const { data } = await getTasks({ page: page.value, page_size: pageSize.value })
  tasks.value = data.data || []
  total.value = data.total || 0
}

async function loadAllTargets() {
  const { data } = await getTargets({ page: 1, page_size: 1000 })
  allTargets.value = data.data || []
}

async function handleCreate() {
  const targetIds = createForm.value.selectedTargets.join(',')
  await createTask({
    name: createForm.value.name,
    target_ids: targetIds,
    type: createForm.value.type,
  })
  ElMessage.success('任务创建成功')
  showCreateDialog.value = false
  createForm.value = { name: '', selectedTargets: [], type: 0 }
  loadTasks()
}

async function handleDelete(id) {
  await ElMessageBox.confirm('确认删除该任务?', '提示', { type: 'warning' })
  await deleteTask(id)
  ElMessage.success('删除成功')
  loadTasks()
}

async function handleShowLogs(id) {
  const { data } = await getTaskLogs(id, { page: 1, page_size: 100 })
  taskLogs.value = (data.data || []).reverse() // 按时间正序显示
  showLogsDialog.value = true
}

onMounted(() => {
  loadTasks()
  loadAllTargets()
})
</script>
