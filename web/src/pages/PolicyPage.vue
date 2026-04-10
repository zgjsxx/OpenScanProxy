<template>
  <div class="row" style="flex-direction:column;align-items:stretch;">
    <PolicySwitch :policy="policy" :message="message" @save="savePolicy" />
    <div class="card">
      <h3>访问策略</h3>
      <div class="grid" style="grid-template-columns:1fr 1fr;">
        <label>域名白名单（每行一条）
          <textarea v-model="accessForm.domain_whitelist" rows="5"></textarea>
        </label>
        <label>域名黑名单（每行一条）
          <textarea v-model="accessForm.domain_blacklist" rows="5"></textarea>
        </label>
        <label>URL 白名单（每行一条）
          <textarea v-model="accessForm.url_whitelist" rows="5"></textarea>
        </label>
        <label>URL 黑名单（每行一条）
          <textarea v-model="accessForm.url_blacklist" rows="5"></textarea>
        </label>
      </div>
      <div class="row">
        <label>默认策略
          <select v-model="accessForm.default_access_action">
            <option value="allow">allow</option>
            <option value="block">block</option>
          </select>
        </label>
        <button @click="saveAccessPolicy">保存访问策略</button>
      </div>
    </div>
    <div class="card">
      <h3>访问测试</h3>
      <div class="row">
        <input v-model="policyTest.host" placeholder="host，如 example.com" />
        <input v-model="policyTest.url" placeholder="url，如 /admin" />
        <input v-model="policyTest.method" placeholder="method，如 GET" />
        <button @click="runPolicyTest">测试</button>
      </div>
      <pre v-if="policyTestResult">{{ policyTestResult }}</pre>
    </div>
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
const accessForm = ref({
  domain_whitelist: '',
  domain_blacklist: '',
  url_whitelist: '',
  url_blacklist: '',
  default_access_action: 'allow',
})
const policyTest = ref({ host: '', url: '/', method: 'GET' })
const policyTestResult = ref('')

const asLines = (text) =>
  text
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean)

async function load() {
  try {
    policy.value = await getJson('/api/policy')
    config.value = await getJson('/api/config')
    const access = await getJson('/api/access-policy')
    accessForm.value = {
      domain_whitelist: (access.domain_whitelist || []).join('\n'),
      domain_blacklist: (access.domain_blacklist || []).join('\n'),
      url_whitelist: (access.url_whitelist || []).join('\n'),
      url_blacklist: (access.url_blacklist || []).join('\n'),
      default_access_action: access.default_access_action || 'allow',
    }
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

async function saveAccessPolicy() {
  try {
    await postJson('/api/access-policy', {
      domain_whitelist: asLines(accessForm.value.domain_whitelist),
      domain_blacklist: asLines(accessForm.value.domain_blacklist),
      url_whitelist: asLines(accessForm.value.url_whitelist),
      url_blacklist: asLines(accessForm.value.url_blacklist),
      default_access_action: accessForm.value.default_access_action,
    })
    message.value = '访问策略保存成功'
    await load()
  } catch {
    message.value = '访问策略保存失败'
  }
}

async function runPolicyTest() {
  try {
    const resp = await postJson('/api/policy/test', policyTest.value)
    policyTestResult.value = JSON.stringify(resp, null, 2)
  } catch {
    policyTestResult.value = '测试失败'
  }
}

onMounted(load)
</script>
