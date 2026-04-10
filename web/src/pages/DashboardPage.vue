<template>
  <div>
    <p class="muted">实时流量可视化 / 访问日志审计 / Policy配置 / 检索查询</p>
    <KpiCards :stats="stats" />
    <div style="margin-top:16px"><SystemConfig :config="config" /></div>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson } from '../api'
import KpiCards from '../components/KpiCards.vue'
import SystemConfig from '../components/SystemConfig.vue'

const router = useRouter()
const stats = ref({})
const config = ref({})
let timer = null

async function load() {
  try {
    stats.value = await getJson('/api/stats')
    config.value = await getJson('/api/config')
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

onMounted(() => {
  load()
  timer = setInterval(load, 3000)
})

onUnmounted(() => clearInterval(timer))
</script>
