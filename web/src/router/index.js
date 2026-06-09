import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/targets' },
  { path: '/targets', component: () => import('../views/Targets.vue') },
  { path: '/tasks', component: () => import('../views/Tasks.vue') },
  { path: '/assets', component: () => import('../views/Assets.vue') },
  { path: '/vulns', component: () => import('../views/Vulns.vue') },
  { path: '/templates', component: () => import('../views/Templates.vue') },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
