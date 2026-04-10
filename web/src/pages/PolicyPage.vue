<template>
  <div class="row" style="flex-direction:column;align-items:stretch;">
    <PolicySwitch :policy="policy" :message="message" @save="savePolicy" />
    <SystemConfig :config="config" />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson, postJson } from '../api'
import PolicySwitch from '../components/PolicySwitch.vue'
import SystemConfig from '../components/SystemConfig.vue'

const router = useRouter()
const policy = ref({ fail_open: false, block_suspicious: false })
const config = ref({})
const message = ref('')

async function load() {
  try {
    policy.value = await getJson('/api/policy')
    config.value = await getJson('/api/config')
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

async function savePolicy(payload) {
  try {
    await postJson('/api/policy', payload)
    message.value = '保存成功'
    await load()
  } catch {
    message.value = '保存失败'
  }
}

onMounted(load)
</script>
