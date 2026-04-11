<script setup>
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson } from '../api'
import LogsTable from '../components/LogsTable.vue'

const router = useRouter()
const logs = ref([])
const filters = reactive({
  q: '',
  action: '',
  result: '',
  host: '',
  method: '',
  user: '',
  status: '',
  path: '',
  time_from: '',
  time_to: '',
  event_type: '',
})
const pager = reactive({ page: 1, pageSize: 100 })
let timer = null
let lastLoadAt = 0

async function loadLogs() {
  const now = Date.now()
  if (now - lastLoadAt < 1500) return
  lastLoadAt = now
  try {
    const p = new URLSearchParams({
      limit: String(pager.pageSize),
      offset: String((pager.page - 1) * pager.pageSize),
    })
    for (const k of ['q', 'action', 'result', 'host', 'method', 'user', 'status', 'path', 'time_from', 'time_to', 'event_type']) {
      const v = String(filters[k] || '').trim()
      if (v) p.set(k, v)
    }
    logs.value = await getJson(`/api/logs?${p.toString()}`)
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

function setPage(page) {
  pager.page = Math.max(1, page)
  loadLogs()
}

onMounted(() => {
  loadLogs()
  timer = setInterval(loadLogs, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <LogsTable :logs="logs" :filters="filters" :pager="pager" @refresh="loadLogs" @set-page="setPage" />
</template>
