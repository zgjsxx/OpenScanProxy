import { createRouter, createWebHistory } from 'vue-router'
import LoginPage from './pages/LoginPage.vue'
import DashboardPage from './pages/DashboardPage.vue'
import LogsPage from './pages/LogsPage.vue'
import PolicyPage from './pages/PolicyPage.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', component: LoginPage },
  { path: '/dashboard', component: DashboardPage },
  { path: '/logs', component: LogsPage },
  { path: '/policy', component: PolicyPage },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
