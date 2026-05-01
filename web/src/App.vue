<template>
  <div class="app-shell" :class="{ 'app-shell--full': !showNav }">
    <aside v-if="showNav" class="sidebar">
      <div class="brand">
        <div class="brand-mark">OS</div>
        <div>
          <div class="brand-title">OpenScanProxy</div>
          <div class="brand-sub">企业安全控制台</div>
        </div>
      </div>

      <div class="sidebar-section">
        <div class="sidebar-label">导航</div>
        <nav class="menu">
          <router-link to="/dashboard">仪表盘</router-link>
          <router-link to="/policy">策略中心</router-link>
          <router-link to="/auth">认证配置</router-link>
          <router-link to="/logs">日志审计</router-link>
        </nav>
      </div>

      <div class="sidebar-status">
        <div class="sidebar-label">当前页面</div>
        <div class="sidebar-focus">{{ pageTitle }}</div>
        <div class="brand-sub">统一的访问控制、审计日志与系统配置视图。</div>
      </div>

      <button class="ghost logout" @click="logout">退出登录</button>
    </aside>

    <div class="content-area">
      <header class="topbar" :class="{ compact: !showNav }">
        <div class="topbar-copy">
          <div class="eyebrow">OpenScanProxy 控制台</div>
          <h1>{{ pageTitle }}</h1>
          <p class="topbar-subtitle">
            {{ pageSubtitle }}
          </p>
        </div>
        <div v-if="showNav" class="topbar-meta">
          <span class="meta-pill">安全运营中心</span>
          <span class="meta-text">策略驱动的流量检测与威胁治理</span>
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
  if (route.path.startsWith('/dashboard')) return '仪表盘'
  if (route.path.startsWith('/policy')) return '策略中心'
  if (route.path.startsWith('/auth')) return '认证配置'
  if (route.path.startsWith('/logs')) return '日志审计'
  return 'OpenScanProxy'
})

const pageSubtitle = computed(() => {
  if (route.path.startsWith('/dashboard')) return '实时查看流量态势、扫描结果和系统运行快照。'
  if (route.path.startsWith('/policy')) return '配置检测处置逻辑与访问控制规则。'
  if (route.path.startsWith('/auth')) return '管理代理认证方式、MITM 解密和认证用户账号。'
  if (route.path.startsWith('/logs')) return '检索访问审计、扫描日志与风险处置记录。'
  return '统一的企业级代理安全控制台。'
})

async function logout() {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' })
  router.push('/login')
}
</script>
