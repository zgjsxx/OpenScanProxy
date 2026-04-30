<template>
  <div class="app-shell" :class="{ 'app-shell--full': !showNav }">
    <aside v-if="showNav" class="sidebar">
      <div class="brand">
        <div class="brand-mark">OS</div>
        <div>
          <div class="brand-title">OpenScanProxy</div>
          <div class="brand-sub">Enterprise Security Console</div>
        </div>
      </div>

      <div class="sidebar-section">
        <div class="sidebar-label">Navigation</div>
        <nav class="menu">
          <router-link to="/dashboard">Dashboard</router-link>
          <router-link to="/policy">Policy Center</router-link>
          <router-link to="/logs">Logs & Reports</router-link>
        </nav>
      </div>

      <div class="sidebar-status">
        <div class="sidebar-label">Current Area</div>
        <div class="sidebar-focus">{{ pageTitle }}</div>
        <div class="brand-sub">统一的访问控制、审计日志与系统配置视图。</div>
      </div>

      <button class="ghost logout" @click="logout">退出登录</button>
    </aside>

    <div class="content-area">
      <header class="topbar" :class="{ compact: !showNav }">
        <div class="topbar-copy">
          <div class="eyebrow">OpenScanProxy Console</div>
          <h1>{{ pageTitle }}</h1>
          <p class="topbar-subtitle">
            {{ pageSubtitle }}
          </p>
        </div>
        <div v-if="showNav" class="topbar-meta">
          <span class="meta-pill">Security Operations Center</span>
          <span class="meta-text">Policy-driven traffic inspection and threat governance</span>
        </div>
      </header>
      <main>
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

const showNav = computed(() => route.path !== '/login')
const pageTitle = computed(() => {
  if (route.path.startsWith('/dashboard')) return 'Dashboard'
  if (route.path.startsWith('/policy')) return 'Policy Center'
  if (route.path.startsWith('/logs')) return 'Logs & Reports'
  return 'OpenScanProxy'
})

const pageSubtitle = computed(() => {
  if (route.path.startsWith('/dashboard')) return '实时查看流量态势、扫描结果和系统运行快照。'
  if (route.path.startsWith('/policy')) return '配置检测处置逻辑、访问控制规则和代理认证策略。'
  if (route.path.startsWith('/logs')) return '检索访问审计、扫描日志与风险处置记录。'
  return '统一的企业级代理安全控制台。'
})

async function logout() {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' })
  router.push('/login')
}
</script>
