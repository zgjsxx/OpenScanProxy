<template>
  <div class="app-shell">
    <header class="topbar">
      <h1>OpenScanProxy 企业控制台</h1>
      <div class="links" v-if="showNav">
        <router-link to="/dashboard">仪表盘</router-link>
        <router-link to="/logs">日志页</router-link>
        <router-link to="/policy">策略页</router-link>
        <button class="ghost" @click="logout">退出</button>
      </div>
    </header>
    <main>
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
const showNav = computed(() => route.path !== '/login')

async function logout() {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' })
  router.push('/login')
}
</script>
