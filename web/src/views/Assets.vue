<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 16px; font-weight: 600;">资产总览</span>
            <span style="font-size: 12px; color: #909399; margin-left: 8px;">扫描发现的存活主机、开放端口和服务指纹</span>
          </div>
          <div style="display: flex; gap: 12px; align-items: center;">
            <el-switch v-model="dedupMode" active-text="合并去重" inactive-text="按任务" @change="loadAssets" />
            <el-select v-model="taskFilter" placeholder="按任务筛选" clearable style="width: 200px" @change="loadAssets" :disabled="dedupMode">
              <el-option v-for="t in tasks" :key="t.id" :label="t.name" :value="t.id" />
            </el-select>
          </div>
        </div>
      </template>

      <el-table :data="assets" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="ip" label="IP" width="150" />
        <el-table-column prop="domain" label="域名" />
        <el-table-column prop="alive" label="存活" width="70">
          <template #default="{ row }">
            <el-tag :type="row.alive ? 'success' : 'danger'" size="small">{{ row.alive ? '是' : '否' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status_code" label="状态码" width="80" />
        <el-table-column prop="title" label="标题" show-overflow-tooltip />
        <el-table-column v-if="dedupMode" prop="task_count" label="任务数" width="80" align="center">
          <template #default="{ row }">
            <el-tag size="small">{{ row.task_count }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="dedupMode" prop="port_count" label="端口数" width="80" align="center">
          <template #default="{ row }">
            <span style="color: #409eff; cursor: pointer;" @click="showDedupPorts(row)">{{ row.port_count }}</span>
          </template>
        </el-table-column>
        <el-table-column v-if="dedupMode" prop="finger_count" label="指纹数" width="80" align="center">
          <template #default="{ row }">
            <span style="color: #e6a23c; cursor: pointer;" @click="showDedupFingers(row)">{{ row.finger_count }}</span>
          </template>
        </el-table-column>
        <el-table-column v-if="!dedupMode" label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" link @click="showPorts(row.id)">端口</el-button>
            <el-button size="small" link @click="showFingers(row.id)">指纹</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        style="margin-top: 16px; justify-content: flex-end;"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        layout="total, prev, pager, next"
        @current-change="loadAssets"
      />
    </el-card>

    <!-- 端口详情 -->
    <el-dialog v-model="portDialogVisible" title="端口信息" width="600px">
      <el-table :data="ports" stripe>
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="state" label="状态" width="100" />
        <el-table-column prop="service" label="服务" />
        <el-table-column prop="version" label="版本" />
      </el-table>
    </el-dialog>

    <!-- 指纹详情 -->
    <el-dialog v-model="fingerDialogVisible" title="指纹信息" width="600px">
      <el-table :data="fingers" stripe>
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="category" label="分类" width="120" />
        <el-table-column prop="version" label="版本" />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getAssets, getAssetPorts, getAssetFingers, getTasks } from '../api'

const assets = ref([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const taskFilter = ref('')
const dedupMode = ref(true)
const tasks = ref([])

const portDialogVisible = ref(false)
const ports = ref([])
const fingerDialogVisible = ref(false)
const fingers = ref([])

async function loadAssets() {
  const params = { page: page.value, page_size: pageSize.value }
  if (dedupMode.value) {
    params.dedup = 'true'
  } else if (taskFilter.value) {
    params.task_id = taskFilter.value
  }
  const { data } = await getAssets(params)
  assets.value = data.data || []
  total.value = data.total || 0
}

async function showPorts(assetId) {
  const { data } = await getAssetPorts(assetId)
  ports.value = data.data || []
  portDialogVisible.value = true
}

async function showFingers(assetId) {
  const { data } = await getAssetFingers(assetId)
  fingers.value = data.data || []
  fingerDialogVisible.value = true
}

// 去重模式下查看端口/指纹：根据 IP 或域名查找所有关联资产
async function showDedupPorts(row) {
  // 查找该 IP/域名关联的所有资产的端口
  const allAssets = assets.value
  // 用第一个关联资产的 ID 来查端口（后端会返回该资产下的端口）
  // 更好的方式：后端提供按 IP 查端口的接口，这里先用现有接口
  const { data } = await getAssetPorts(row.id)
  ports.value = data.data || []
  portDialogVisible.value = true
}

async function showDedupFingers(row) {
  const { data } = await getAssetFingers(row.id)
  fingers.value = data.data || []
  fingerDialogVisible.value = true
}

onMounted(async () => {
  const { data } = await getTasks({ page: 1, page_size: 100 })
  tasks.value = data.data || []
  loadAssets()
})
</script>
