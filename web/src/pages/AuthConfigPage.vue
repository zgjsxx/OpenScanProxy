<template>
  <div class="policy-workbench">
    <section class="card section-shell">
      <div class="section-head">
        <div>
          <div class="section-kicker">Proxy Authentication</div>
          <div class="section-title">代理认证配置</div>
        </div>
        <p class="muted section-note">控制代理认证的开关和认证方式。Basic 模式走浏览器弹窗，Portal 模式走 Web 登录页面。</p>
      </div>

      <div class="auth-config-grid">
        <div class="auth-config-item">
          <label class="field-block">
            <span>启用代理认证</span>
            <select v-model="authConfig.enable_proxy_auth" class="native-select">
              <option :value="false">关闭</option>
              <option :value="true">开启</option>
            </select>
          </label>
          <p class="muted field-hint">关闭时代理直接放行所有流量，开启后根据认证模式验证身份。</p>
        </div>
        <div class="auth-config-item">
          <label class="field-block">
            <span>认证模式</span>
            <select v-model="authConfig.proxy_auth_mode" class="native-select">
              <option value="basic">Basic（浏览器弹窗）</option>
              <option value="portal">Portal（Web 登录页面）</option>
              <option value="hybrid">Hybrid（同时支持两种）</option>
            </select>
          </label>
          <p v-if="authConfig.proxy_auth_mode === 'portal' || authConfig.proxy_auth_mode === 'hybrid'" class="portal-notice muted">
            Portal 模式需要独立 HTTPS 端口（9091）监听。如果启动时未启用 Portal，保存后需重启服务才能生效。
          </p>
        </div>
      </div>

      <div class="action-row split">
        <span
          class="status-text"
          :class="{
            success: authConfigMessage && authConfigMessage.includes('已保存'),
            error: authConfigMessage && authConfigMessage.includes('失败'),
          }"
        >
          {{ authConfigMessage || '修改后请点击保存，认证开关会立即生效。' }}
        </span>
        <button class="primary-btn" @click="saveAuthConfig">保存认证配置</button>
      </div>

      <hr class="section-divider" />

      <div class="section-subhead">
        <span>认证用户管理</span>
        <span class="status-chip mini" :class="proxyUsers.enabled ? 'ok' : 'off'">
          {{ proxyUsers.enabled ? '已启用' : '未启用' }}
        </span>
        <span class="muted" style="font-size:0.82rem">当前 {{ proxyUsers.users.length }} 个账号</span>
      </div>

      <div class="proxy-user-form">
        <label class="field-block">
          <span>用户名</span>
          <input v-model="newProxyUser.username" placeholder="请输入用户名" />
        </label>
        <label class="field-block">
          <span>密码</span>
          <input v-model="newProxyUser.password" placeholder="请输入密码" type="password" />
        </label>
      </div>

      <div class="action-row split">
        <span
          class="status-text"
          :class="{
            success: proxyUserMessage && proxyUserMessage.includes('成功'),
            error: proxyUserMessage && proxyUserMessage.includes('失败'),
          }"
        >
          {{ proxyUserMessage || '支持创建新用户，也支持用同名账号进行密码更新。' }}
        </span>
        <button class="primary-btn" @click="createProxyUser">创建或更新用户</button>
      </div>

      <div class="user-list-panel">
        <div class="user-list-title">已配置账号</div>
        <div v-if="proxyUsers.users.length" class="user-chip-list">
          <span v-for="u in proxyUsers.users" :key="u.username" class="user-chip">
            {{ u.username }}
            <button class="user-chip-del" title="删除用户" @click="deleteProxyUser(u.username)">x</button>
          </span>
        </div>
        <div v-else class="muted">当前还没有配置代理认证用户。</div>
      </div>
    </section>

    <SystemConfig :config="config" />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson, postJson, deleteJson } from '../api'
import SystemConfig from '../components/SystemConfig.vue'

const router = useRouter()
const config = ref({})
const proxyUsers = ref({ enabled: false, users: [] })
const newProxyUser = ref({ username: '', password: '' })
const authConfig = ref({ enable_proxy_auth: false, proxy_auth_mode: 'basic', enable_https_mitm: false })
const authConfigMessage = ref('')
const proxyUserMessage = ref('')

async function load() {
  try {
    config.value = await getJson('/api/config')
    authConfig.value = await getJson('/api/auth-config')
    proxyUsers.value = await getJson('/api/proxy-users')
  } catch (e) {
    if (e.message === 'UNAUTHORIZED') router.push('/login')
  }
}

async function saveAuthConfig() {
  try {
    await postJson('/api/auth-config', authConfig.value)
    authConfigMessage.value = '认证配置已保存'
    await load()
  } catch {
    authConfigMessage.value = '认证配置保存失败'
  }
}

async function createProxyUser() {
  try {
    await postJson('/api/proxy-users', newProxyUser.value)
    newProxyUser.value = { username: '', password: '' }
    proxyUserMessage.value = '代理认证用户保存成功'
    await load()
  } catch {
    proxyUserMessage.value = '代理认证用户保存失败'
  }
}

async function deleteProxyUser(username) {
  try {
    await deleteJson('/api/proxy-users', { username })
    proxyUserMessage.value = `用户 ${username} 已删除`
    await load()
  } catch {
    proxyUserMessage.value = '删除用户失败'
  }
}

onMounted(load)
</script>
