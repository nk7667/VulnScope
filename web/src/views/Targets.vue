<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 16px; font-weight: 600;">扫描目标</span>
            <span style="font-size: 12px; color: #909399; margin-left: 8px;">管理要扫描的对象（IP、域名、网段），添加后可在"扫描任务"中发起扫描</span>
          </div>
          <div>
            <el-button type="primary" @click="showAddDialog = true">添加目标</el-button>
            <el-button @click="showImportDialog = true">批量导入</el-button>
          </div>
        </div>
      </template>

      <el-table :data="targets" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="target" label="目标" />
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag :type="row.type === 'ip' ? '' : row.type === 'domain' ? 'success' : 'warning'" size="small">
              {{ row.type }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="group" label="分组" width="120" />
        <el-table-column prop="tags" label="标签" width="150" />
        <el-table-column prop="memo" label="备注" />
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
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
        @current-change="loadTargets"
      />
    </el-card>

    <!-- 添加目标对话框 -->
    <el-dialog v-model="showAddDialog" title="添加扫描目标" width="500px">
      <el-form :model="addForm" label-width="80px">
        <el-form-item label="目标">
          <el-input v-model="addForm.target" placeholder="IP / 域名 / 网段 (如 192.168.1.0/24)" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="addForm.type" placeholder="自动识别">
            <el-option label="自动识别" value="" />
            <el-option label="IP" value="ip" />
            <el-option label="域名" value="domain" />
            <el-option label="网段" value="cidr" />
          </el-select>
        </el-form-item>
        <el-form-item label="分组">
          <el-input v-model="addForm.group" placeholder="可选" />
        </el-form-item>
        <el-form-item label="标签">
          <el-input v-model="addForm.tags" placeholder="逗号分隔" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="addForm.memo" type="textarea" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleAdd">添加</el-button>
      </template>
    </el-dialog>

    <!-- 批量导入对话框 -->
    <el-dialog v-model="showImportDialog" title="批量导入目标" width="500px">
      <el-form :model="importForm" label-width="80px">
        <el-form-item label="目标列表">
          <el-input v-model="importForm.targets" type="textarea" :rows="8" placeholder="每行一个目标 (IP/域名/网段)" />
        </el-form-item>
        <el-form-item label="分组">
          <el-input v-model="importForm.group" placeholder="可选" />
        </el-form-item>
        <el-form-item label="标签">
          <el-input v-model="importForm.tags" placeholder="逗号分隔" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showImportDialog = false">取消</el-button>
        <el-button type="primary" @click="handleImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getTargets, createTarget, batchImportTargets, deleteTarget } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'

const targets = ref([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const showAddDialog = ref(false)
const showImportDialog = ref(false)
const addForm = ref({ target: '', type: '', group: '', tags: '', memo: '' })
const importForm = ref({ targets: '', group: '', tags: '' })

async function loadTargets() {
  const { data } = await getTargets({ page: page.value, page_size: pageSize.value })
  targets.value = data.data || []
  total.value = data.total || 0
}

async function handleAdd() {
  await createTarget(addForm.value)
  ElMessage.success('添加成功')
  showAddDialog.value = false
  addForm.value = { target: '', type: '', group: '', tags: '', memo: '' }
  loadTargets()
}

async function handleImport() {
  const lines = importForm.value.targets.split('\n').filter(l => l.trim())
  await batchImportTargets({
    targets: lines,
    group: importForm.value.group,
    tags: importForm.value.tags,
  })
  ElMessage.success('导入成功')
  showImportDialog.value = false
  importForm.value = { targets: '', group: '', tags: '' }
  loadTargets()
}

async function handleDelete(id) {
  await ElMessageBox.confirm('确认删除该目标?', '提示', { type: 'warning' })
  await deleteTarget(id)
  ElMessage.success('删除成功')
  loadTargets()
}

onMounted(loadTargets)
</script>
