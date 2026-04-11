<template>
  <div class="app-shell">
    <aside class="sidebar" v-if="showNav">
      <div class="brand">
        <div class="brand-mark">OS</div>
        <div>
          <div class="brand-title">OpenScanProxy</div>
          <div class="brand-sub">Admin Console</div>
        </div>
      </div>
      <nav class="menu">
        <router-link to="/dashboard">Dashboard</router-link>
        <router-link to="/policy">Policy</router-link>
        <router-link to="/logs">Logs</router-link>
      </nav>
      <button class="ghost logout" @click="logout">退出登录</button>
    </aside>

    <div class="content-area">
      <header class="topbar" :class="{ compact: !showNav }">
        <h1>{{ pageTitle }}</h1>
        <div class="welcome" v-if="showNav">Security Operations Center</div>
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

async function logout() {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' })
  router.push('/login')
}
</script>
