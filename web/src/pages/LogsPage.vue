<template>
  <LogsTable :logs="logs" :filters="filters" @refresh="loadLogs" />
</template>

<script setup>
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson } from '../api'
import LogsTable from '../components/LogsTable.vue'

const router = useRouter()
const logs = ref([])
const filters = reactive({ q: '', action: '', result: '', host: '' })
let timer = null

async function loadLogs() {
  try {
    const p = new URLSearchParams({ limit: '300' })
    for (const k of ['q', 'action', 'result', 'host']) {
      const v = String(filters[k] || '').trim()
      if (v) p.set(k, v)
    }
    logs.value = await getJson(`/api/logs?${p.toString()}`)
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

onMounted(() => {
  loadLogs()
  timer = setInterval(loadLogs, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>
