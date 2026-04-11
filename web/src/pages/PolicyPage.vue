<template>
  <div class="row" style="flex-direction:column;align-items:stretch;">
    <PolicySwitch :policy="policy" :message="policyMessage" @save="savePolicy" />
    <div class="card">
      <h3>访问策略</h3>
      <div class="grid" style="grid-template-columns:1fr 1fr;">
        <label>域名白名单（每行一条）
          <textarea v-model="accessForm.domain_whitelist" rows="5"></textarea>
        </label>
        <label>域名黑名单（每行一条）
          <textarea v-model="accessForm.domain_blacklist" rows="5"></textarea>
        </label>
        <label>用户白名单（每行一条）
          <textarea v-model="accessForm.user_whitelist" rows="5"></textarea>
        </label>
        <label>用户黑名单（每行一条）
          <textarea v-model="accessForm.user_blacklist" rows="5"></textarea>
        </label>
        <label>URL 白名单（每行一条）
          <textarea v-model="accessForm.url_whitelist" rows="5"></textarea>
        </label>
        <label>URL 黑名单（每行一条）
          <textarea v-model="accessForm.url_blacklist" rows="5"></textarea>
        </label>
        <label>URL 分类白名单（每行一条，如 social / video）
          <textarea v-model="accessForm.url_category_whitelist" rows="5"></textarea>
        </label>
        <label>URL 分类黑名单（每行一条，如 adult / gambling）
          <textarea v-model="accessForm.url_category_blacklist" rows="5"></textarea>
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
        <span class="muted">{{ accessMessage }}</span>
      </div>
    </div>
    <div class="card">
      <h3>访问测试</h3>
      <div class="row">
        <input v-model="policyTest.user" placeholder="user，如 alice" />
        <input v-model="policyTest.host" placeholder="host，如 example.com" />
        <input v-model="policyTest.url" placeholder="url，如 /admin" />
        <input v-model="policyTest.method" placeholder="method，如 GET" />
        <button @click="runPolicyTest">测试</button>
      </div>
      <pre v-if="policyTestResult">{{ policyTestResult }}</pre>
    </div>
    <div class="card">
      <h3>代理认证用户管理</h3>
      <div class="muted">首次访问代理时，浏览器会弹窗要求输入这里创建的用户名和密码。</div>
      <div class="row" style="margin-top:8px">
        <input v-model="newProxyUser.username" placeholder="用户名" />
        <input v-model="newProxyUser.password" placeholder="密码" type="password" />
        <button @click="createProxyUser">创建/更新用户</button>
        <span class="muted">{{ proxyUserMessage }}</span>
      </div>
      <div class="muted" style="margin-top:8px">已启用：{{ proxyUsers.enabled ? '是' : '否' }}</div>
      <ul>
        <li v-for="u in proxyUsers.users" :key="u.username">{{ u.username }}</li>
      </ul>
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
const policyMessage = ref('')
const accessMessage = ref('')
const proxyUserMessage = ref('')
const accessForm = ref({
  domain_whitelist: '',
  domain_blacklist: '',
  user_whitelist: '',
  user_blacklist: '',
  url_whitelist: '',
  url_blacklist: '',
  url_category_whitelist: '',
  url_category_blacklist: '',
  default_access_action: 'allow',
})
const policyTest = ref({ user: '', host: '', url: '/', method: 'GET' })
const policyTestResult = ref('')
const proxyUsers = ref({ enabled: false, users: [] })
const newProxyUser = ref({ username: '', password: '' })

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
    proxyUsers.value = await getJson('/api/proxy-users')
    accessForm.value = {
      domain_whitelist: (access.domain_whitelist || []).join('\n'),
      domain_blacklist: (access.domain_blacklist || []).join('\n'),
      user_whitelist: (access.user_whitelist || []).join('\n'),
      user_blacklist: (access.user_blacklist || []).join('\n'),
      url_whitelist: (access.url_whitelist || []).join('\n'),
      url_blacklist: (access.url_blacklist || []).join('\n'),
      url_category_whitelist: (access.url_category_whitelist || []).join('\n'),
      url_category_blacklist: (access.url_category_blacklist || []).join('\n'),
      default_access_action: access.default_access_action || 'allow',
    }
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

async function savePolicy(payload) {
  try {
    await postJson('/api/policy', payload)
    policyMessage.value = 'Policy 保存成功'
    await load()
  } catch {
    policyMessage.value = 'Policy 保存失败'
  }
}

async function saveAccessPolicy() {
  try {
    await postJson('/api/access-policy', {
      domain_whitelist: asLines(accessForm.value.domain_whitelist),
      domain_blacklist: asLines(accessForm.value.domain_blacklist),
      user_whitelist: asLines(accessForm.value.user_whitelist),
      user_blacklist: asLines(accessForm.value.user_blacklist),
      url_whitelist: asLines(accessForm.value.url_whitelist),
      url_blacklist: asLines(accessForm.value.url_blacklist),
      url_category_whitelist: asLines(accessForm.value.url_category_whitelist),
      url_category_blacklist: asLines(accessForm.value.url_category_blacklist),
      default_access_action: accessForm.value.default_access_action,
    })
    accessMessage.value = '访问策略保存成功'
    await load()
  } catch {
    accessMessage.value = '访问策略保存失败'
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

async function createProxyUser() {
  try {
    await postJson('/api/proxy-users', newProxyUser.value)
    newProxyUser.value = { username: '', password: '' }
    proxyUserMessage.value = '代理用户保存成功'
    await load()
  } catch {
    proxyUserMessage.value = '代理用户保存失败'
  }
}

onMounted(load)
</script>
