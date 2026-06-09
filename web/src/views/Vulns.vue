<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 16px; font-weight: 600;">漏洞结果</span>
            <span style="font-size: 12px; color: #909399; margin-left: 8px;">Nuclei 扫描发现的安全漏洞，可筛选、确认或标记误报</span>
          </div>
          <div style="display: flex; gap: 12px;">
            <el-select v-model="severityFilter" placeholder="严重等级" clearable style="width: 120px" @change="loadVulns">
              <el-option label="Critical" value="critical" />
              <el-option label="High" value="high" />
              <el-option label="Medium" value="medium" />
              <el-option label="Low" value="low" />
              <el-option label="Info" value="info" />
            </el-select>
            <el-select v-model="statusFilter" placeholder="状态" clearable style="width: 120px" @change="loadVulns">
              <el-option label="未确认" value="0" />
              <el-option label="误报" value="1" />
              <el-option label="已确认" value="2" />
              <el-option label="忽略" value="3" />
            </el-select>
          </div>
        </div>
      </template>

      <el-table :data="vulns" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="漏洞名称" show-overflow-tooltip />
        <el-table-column prop="severity" label="等级" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="url" label="URL" show-overflow-tooltip />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="vulnStatusType(row.status)" size="small">{{ vulnStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="发现时间" width="180" />
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <div style="display: flex; align-items: center; gap: 8px;">
              <el-button size="small" link @click="showDetail(row)">详情</el-button>
              <el-dropdown trigger="click" @command="(cmd) => handleStatus(row.id, cmd)">
                <el-button size="small" link>标记</el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="2">确认</el-dropdown-item>
                    <el-dropdown-item command="1">误报</el-dropdown-item>
                    <el-dropdown-item command="3">忽略</el-dropdown-item>
                    <el-dropdown-item command="0">重置为未确认</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        style="margin-top: 16px; justify-content: flex-end;"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        layout="total, prev, pager, next"
        @current-change="loadVulns"
      />
    </el-card>

    <!-- 漏洞详情 -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="700px">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="漏洞名称" :span="2">{{ currentVuln.name }}</el-descriptions-item>
        <el-descriptions-item label="等级">{{ currentVuln.severity }}</el-descriptions-item>
        <el-descriptions-item label="类型">{{ currentVuln.type }}</el-descriptions-item>
        <el-descriptions-item label="URL" :span="2">{{ currentVuln.url }}</el-descriptions-item>
        <el-descriptions-item label="任务ID">{{ currentVuln.task_id }}</el-descriptions-item>
        <el-descriptions-item label="模板ID">{{ currentVuln.template_id }}</el-descriptions-item>
        <el-descriptions-item label="修复建议" :span="2">{{ currentVuln.remediation }}</el-descriptions-item>
      </el-descriptions>
      <div v-if="currentVuln.request" style="margin-top: 16px;">
        <h4>请求证据</h4>
        <el-input type="textarea" :model-value="currentVuln.request" :rows="6" readonly />
      </div>
      <div v-if="currentVuln.response" style="margin-top: 16px;">
        <h4>响应证据</h4>
        <el-input type="textarea" :model-value="currentVuln.response" :rows="6" readonly />
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getVulns, updateVulnStatus } from '../api'
import { ElMessage } from 'element-plus'

const vulns = ref([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const severityFilter = ref('')
const statusFilter = ref('')
const detailVisible = ref(false)
const currentVuln = ref({})

function severityType(s) {
  const map = { critical: 'danger', high: 'warning', medium: '', low: 'info', info: 'success' }
  return map[s] || 'info'
}
function vulnStatusType(s) {
  const map = { 0: 'info', 1: 'warning', 2: 'danger', 3: 'success' }
  return map[s] || 'info'
}
function vulnStatusLabel(s) {
  const map = { 0: '未确认', 1: '误报', 2: '已确认', 3: '忽略' }
  return map[s] || '未知'
}

async function loadVulns() {
  const params = { page: page.value, page_size: pageSize.value }
  if (severityFilter.value) params.severity = severityFilter.value
  if (statusFilter.value) params.status = statusFilter.value
  const { data } = await getVulns(params)
  vulns.value = data.data || []
  total.value = data.total || 0
}

function showDetail(vuln) {
  currentVuln.value = vuln
  detailVisible.value = true
}

async function handleStatus(id, status) {
  await updateVulnStatus(id, { status: parseInt(status) })
  ElMessage.success('状态已更新')
  loadVulns()
}

onMounted(loadVulns)
</script>
