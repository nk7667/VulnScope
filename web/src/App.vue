<template>
  <el-container style="height: 100vh">
    <el-aside width="200px" class="sidebar">
      <!-- Logo -->
      <div class="logo-area">
        <div class="logo-icon">
          <svg viewBox="0 0 32 32" width="28" height="28">
            <circle cx="16" cy="16" r="14" fill="none" stroke="#00d4ff" stroke-width="2"/>
            <circle cx="16" cy="16" r="6" fill="none" stroke="#00d4ff" stroke-width="1.5"/>
            <line x1="16" y1="2" x2="16" y2="10" stroke="#00d4ff" stroke-width="1.5"/>
            <line x1="16" y1="22" x2="16" y2="30" stroke="#00d4ff" stroke-width="1.5"/>
            <line x1="2" y1="16" x2="10" y2="16" stroke="#00d4ff" stroke-width="1.5"/>
            <line x1="22" y1="16" x2="30" y2="16" stroke="#00d4ff" stroke-width="1.5"/>
            <circle cx="16" cy="16" r="2" fill="#00d4ff"/>
          </svg>
        </div>
        <span class="logo-text">VulnScope</span>
      </div>

      <!-- 导航菜单 -->
      <el-menu
        :default-active="$route.path"
        router
        background-color="transparent"
        text-color="#8b95a5"
        active-text-color="#00d4ff"
        class="nav-menu"
      >
        <el-menu-item index="/targets">
          <el-icon><Aim /></el-icon>
          <span>扫描目标</span>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><VideoPlay /></el-icon>
          <span>扫描任务</span>
        </el-menu-item>
        <el-menu-item index="/assets">
          <el-icon><Monitor /></el-icon>
          <span>资产总览</span>
        </el-menu-item>
        <el-menu-item index="/vulns">
          <el-icon><Warning /></el-icon>
          <span>漏洞结果</span>
        </el-menu-item>
        <el-menu-item index="/templates">
          <el-icon><Document /></el-icon>
          <span>Nuclei 模板</span>
        </el-menu-item>
      </el-menu>

      <!-- 底部版本 -->
      <div class="sidebar-footer">v1.0.0</div>
    </el-aside>

    <el-main class="main-area">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup>
import { Aim, VideoPlay, Monitor, Warning, Document } from '@element-plus/icons-vue'
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

/* 侧边栏 */
.sidebar {
  background: linear-gradient(180deg, #0c1222 0%, #111827 100%);
  border-right: 1px solid #1e293b;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* Logo 区域 */
.logo-area {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px 18px 16px;
}
.logo-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: rgba(0, 212, 255, 0.08);
  border: 1px solid rgba(0, 212, 255, 0.2);
  flex-shrink: 0;
}
.logo-text {
  font-size: 17px;
  font-weight: 700;
  color: #e2e8f0;
  letter-spacing: 0.5px;
}

/* 菜单 */
.nav-menu {
  border-right: none !important;
  flex: 1;
  padding: 4px 8px;
}
.nav-menu .el-menu-item {
  height: 42px !important;
  line-height: 42px !important;
  border-radius: 8px !important;
  margin-bottom: 2px;
  padding: 0 14px !important;
  font-size: 13.5px;
  font-weight: 500;
  transition: all 0.2s;
}
.nav-menu .el-menu-item .el-icon {
  font-size: 17px;
  margin-right: 10px;
}
.nav-menu .el-menu-item:hover {
  background-color: rgba(255,255,255,0.04) !important;
  color: #cbd5e1 !important;
}
.nav-menu .el-menu-item.is-active {
  background: rgba(0, 212, 255, 0.1) !important;
  color: #00d4ff !important;
  border-right: none !important;
  box-shadow: inset 0 0 0 1px rgba(0, 212, 255, 0.15);
}

/* 底部 */
.sidebar-footer {
  padding: 12px 20px;
  color: #475569;
  font-size: 11px;
  text-align: center;
  border-top: 1px solid #1e293b;
}

/* 主内容区 */
.main-area {
  background-color: #f8fafc;
  padding: 24px;
  overflow-y: auto;
}

/* 卡片美化 */
.el-card {
  border: none !important;
  border-radius: 12px !important;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04) !important;
}
.el-card__header {
  border-bottom: 1px solid #f1f5f9 !important;
  padding: 16px 20px !important;
}
.el-card__body {
  padding: 16px 20px !important;
}
</style>
