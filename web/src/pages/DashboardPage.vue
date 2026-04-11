<template>
  <div class="dashboard-page">
    <p class="muted">实时流量可视化 / 风险趋势追踪 / 策略状态总览</p>

    <KpiCards :stats="stats" />

    <div class="dashboard-grid">
      <section class="card chart-card">
        <div class="section-title">请求动作分布</div>
        <svg class="donut" viewBox="0 0 200 200">
          <circle cx="100" cy="100" r="72" class="donut-track" />
          <circle
            v-for="(slice, idx) in donutSlices"
            :key="slice.label"
            cx="100"
            cy="100"
            r="72"
            fill="none"
            :stroke="slice.color"
            stroke-width="24"
            :stroke-dasharray="slice.length + ' ' + donutCircumference"
            :stroke-dashoffset="-slice.offset"
            transform="rotate(-90 100 100)"
          />
          <text x="100" y="96" text-anchor="middle" class="donut-total">{{ totalRequests }}</text>
          <text x="100" y="118" text-anchor="middle" class="donut-label">total</text>
        </svg>
        <div class="legend">
          <div v-for="slice in donutSlices" :key="slice.label" class="legend-item">
            <span class="dot" :style="{ background: slice.color }" />
            <span>{{ slice.label }} · {{ slice.value }}</span>
          </div>
        </div>
      </section>

      <section class="card chart-card">
        <div class="section-title">扫描结果趋势（最近12周期）</div>
        <svg class="line-chart" viewBox="0 0 560 240" preserveAspectRatio="none">
          <polyline class="line clean" :points="linePoints.clean" />
          <polyline class="line suspicious" :points="linePoints.suspicious" />
          <polyline class="line infected" :points="linePoints.infected" />
        </svg>
        <div class="legend">
          <div class="legend-item"><span class="dot clean-dot" />clean</div>
          <div class="legend-item"><span class="dot suspicious-dot" />suspicious</div>
          <div class="legend-item"><span class="dot infected-dot" />infected</div>
        </div>
      </section>

      <section class="card chart-card">
        <div class="section-title">安全事件柱状图</div>
        <div class="bars">
          <div v-for="bar in bars" :key="bar.label" class="bar-col">
            <div class="bar-track">
              <div class="bar-fill" :style="{ height: `${bar.height}%`, background: bar.color }" />
            </div>
            <div class="bar-value">{{ bar.value }}</div>
            <div class="bar-label">{{ bar.label }}</div>
          </div>
        </div>
      </section>

      <section class="card chart-card">
        <div class="section-title">系统配置快照</div>
        <SystemConfig :config="config" embedded />
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson } from '../api'
import KpiCards from '../components/KpiCards.vue'
import SystemConfig from '../components/SystemConfig.vue'

const router = useRouter()
const stats = ref({})
const config = ref({})
let timer = null

const asNum = (k) => Number(stats.value[k] || 0)

const totalRequests = computed(() => asNum('total_requests'))
const donutCircumference = 2 * Math.PI * 72

const donutSlices = computed(() => {
  const data = [
    { label: 'allow', value: Math.max(0, asNum('total_requests') - asNum('blocked')), color: '#4f9cff' },
    { label: 'blocked', value: asNum('blocked'), color: '#ff6b8a' },
    { label: 'suspicious', value: asNum('suspicious'), color: '#ffd166' },
  ]
  const base = Math.max(1, data.reduce((s, x) => s + x.value, 0))
  let offset = 0
  return data.map((item) => {
    const length = (item.value / base) * donutCircumference
    const current = { ...item, length, offset }
    offset += length
    return current
  })
})

function makeTrendSeries(seed, scale) {
  const points = []
  for (let i = 0; i < 12; i += 1) {
    const wave = Math.sin((i + seed) * 0.8) * 0.35 + 0.65
    points.push(Math.max(2, Math.round(scale * wave)))
  }
  return points
}

const linePoints = computed(() => {
  const clean = makeTrendSeries(1, Math.max(8, asNum('clean')))
  const suspicious = makeTrendSeries(3, Math.max(4, asNum('suspicious') + 3))
  const infected = makeTrendSeries(5, Math.max(3, asNum('infected') + 2))
  const max = Math.max(...clean, ...suspicious, ...infected, 1)

  const toPolyline = (series) =>
    series
      .map((v, i) => {
        const x = 20 + i * 47
        const y = 210 - (v / max) * 170
        return `${x},${y.toFixed(2)}`
      })
      .join(' ')

  return {
    clean: toPolyline(clean),
    suspicious: toPolyline(suspicious),
    infected: toPolyline(infected),
  }
})

const bars = computed(() => {
  const items = [
    { label: 'MITM', value: asNum('https_mitm_requests'), color: 'linear-gradient(180deg,#4f9cff,#3a68d8)' },
    { label: 'Scanned', value: asNum('scanned_files'), color: 'linear-gradient(180deg,#5be7c4,#2bbf9d)' },
    { label: 'Error', value: asNum('scanner_error'), color: 'linear-gradient(180deg,#ffa56b,#ff6a6a)' },
    { label: 'Blocked', value: asNum('blocked'), color: 'linear-gradient(180deg,#ff7aab,#ff4f7f)' },
  ]
  const max = Math.max(1, ...items.map((x) => x.value))
  return items.map((x) => ({ ...x, height: Math.max(6, (x.value / max) * 100) }))
})

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
