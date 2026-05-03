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
          <div class="pw-wrap">
            <input v-model="newProxyUser.password" :type="pwShow ? 'text' : 'password'" placeholder="请输入密码" />
            <button class="pw-toggle" type="button" @click="pwShow = !pwShow">{{ pwShow ? '隐' : '显' }}</button>
          </div>
        </label>
        <label class="field-block">
          <span>邮箱</span>
          <input v-model="newProxyUser.email" placeholder="例如 user@company.com" />
        </label>
        <label class="field-block">
          <span>角色</span>
          <select v-model="newProxyUser.role" class="native-select">
            <option value="user">user — 允许使用代理</option>
            <option value="administrator">administrator — 管理控制台完全访问</option>
            <option value="operator">operator — 管理控制台只读访问</option>
          </select>
        </label>
        <label class="field-block">
          <span>所属用户组</span>
          <div class="user-chip-list" style="margin-top:4px">
            <span
              v-for="g in userGroups"
              :key="g.name"
              class="user-chip"
              :class="{ selected: newProxyUser.selectedGroups.has(g.name) }"
              @click="toggleUserGroup(g.name)"
            >@{{ g.name }}</span>
            <span v-if="!userGroups.length" class="muted" style="font-size:0.78rem">暂无用户组</span>
          </div>
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
          {{ proxyUserMessage || '同名账号将更新全部信息（密码、邮箱、角色、用户组）。' }}
        </span>
        <button class="primary-btn" @click="createProxyUser">创建或更新用户</button>
      </div>

      <div class="user-list-panel">
        <div class="user-list-title">已配置账号</div>
        <div v-if="proxyUsers.users.length" class="user-table-wrap">
          <table class="user-table">
            <thead>
              <tr>
                <th>用户名</th>
                <th>邮箱</th>
                <th>角色</th>
                <th>用户组</th>
                <th style="width:60px"></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in proxyUsers.users" :key="u.username">
                <td><strong>{{ u.username }}</strong></td>
                <td class="muted">{{ u.email || '-' }}</td>
                <td><span class="role-badge" :class="u.role">{{ roleLabel(u.role) }}</span></td>
                <td>
                  <span v-if="(u.groups || []).length" class="user-chip-list" style="gap:4px">
                    <span v-for="g in (u.groups || [])" :key="g" class="user-chip mini-chip">@{{ g }}</span>
                  </span>
                  <span v-else class="muted">-</span>
                </td>
                <td>
                  <button class="user-chip-del" title="删除用户" @click="deleteProxyUser(u.username)">x</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="muted">当前还没有配置代理认证用户。</div>
      </div>

      <hr class="section-divider" />

      <div class="section-subhead">
        <span>用户组管理</span>
        <span class="muted" style="font-size:0.82rem">当前 {{ userGroups.length }} 个组</span>
      </div>

      <div class="group-form">
        <label class="field-block" style="max-width:320px">
          <span>组名</span>
          <input v-model="newGroup.name" placeholder="例如 engineering" />
        </label>
        <div class="group-member-picker">
          <span class="muted" style="font-size:0.82rem">选择组成员（点击切换）：</span>
          <div class="user-chip-list" style="margin-top:6px">
            <span
              v-for="u in proxyUsers.users"
              :key="u.username"
              class="user-chip"
              :class="{ selected: newGroup.selectedUsers.has(u.username) }"
              @click="toggleGroupUser(u.username)"
            >{{ u.username }}</span>
          </div>
        </div>
      </div>

      <div class="action-row split" style="margin-top:14px">
        <span
          class="status-text"
          :class="{
            success: groupMessage && groupMessage.includes('成功'),
            error: groupMessage && groupMessage.includes('失败'),
          }"
        >
          {{ groupMessage || '输入组名并选择用户后点击保存。' }}
        </span>
        <button class="primary-btn" @click="saveGroup">创建或更新用户组</button>
      </div>

      <div class="user-list-panel" v-if="userGroups.length">
        <div class="user-list-title">已有用户组</div>
        <div v-for="g in userGroups" :key="g.name" class="group-row">
          <div class="group-row-head">
            <span class="group-row-name">@{{ g.name }}</span>
            <span class="muted" style="font-size:0.78rem">{{ (g.users || []).length }} 人</span>
            <button class="user-chip-del" title="删除用户组" @click="deleteGroup(g.name)">x</button>
          </div>
          <div class="user-chip-list" style="margin-top:4px">
            <span v-for="u in (g.users || [])" :key="u" class="user-chip">{{ u }}</span>
          </div>
        </div>
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
const newProxyUser = ref({ username: '', password: '', email: '', role: 'user', selectedGroups: new Set() })
const pwShow = ref(false)
const authConfig = ref({ enable_proxy_auth: false, proxy_auth_mode: 'basic', enable_https_mitm: false })
const authConfigMessage = ref('')
const proxyUserMessage = ref('')
const userGroups = ref([])
const newGroup = ref({ name: '', selectedUsers: new Set() })
const groupMessage = ref('')

async function load() {
  try {
    config.value = await getJson('/api/config')
    authConfig.value = await getJson('/api/auth-config')
    proxyUsers.value = await getJson('/api/proxy-users')
    try { userGroups.value = await getJson('/api/user-groups') } catch {}
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

function roleLabel(r) { return { user: 'user', administrator: 'administrator', operator: 'operator' }[r] || r }

function toggleUserGroup(name) {
  const s = newProxyUser.value.selectedGroups
  if (s.has(name)) s.delete(name)
  else s.add(name)
}

async function createProxyUser() {
  try {
    await postJson('/api/proxy-users', {
      username: newProxyUser.value.username,
      password: newProxyUser.value.password,
      email: newProxyUser.value.email,
      role: newProxyUser.value.role,
      groups: [...newProxyUser.value.selectedGroups],
    })
    newProxyUser.value = { username: '', password: '', email: '', role: 'user', selectedGroups: new Set() }
    pwShow.value = false
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

function toggleGroupUser(username) {
  const s = newGroup.value.selectedUsers
  if (s.has(username)) s.delete(username)
  else s.add(username)
}

async function saveGroup() {
  const name = newGroup.value.name.trim()
  if (!name) {
    groupMessage.value = '请输入组名'
    return
  }
  try {
    await postJson('/api/user-groups', { name, users: [...newGroup.value.selectedUsers] })
    newGroup.value = { name: '', selectedUsers: new Set() }
    groupMessage.value = '用户组保存成功'
    await load()
  } catch {
    groupMessage.value = '用户组保存失败'
  }
}

async function deleteGroup(name) {
  try {
    await deleteJson('/api/user-groups', { name })
    groupMessage.value = `用户组 ${name} 已删除`
    await load()
  } catch {
    groupMessage.value = '删除用户组失败'
  }
}

onMounted(load)
</script>
