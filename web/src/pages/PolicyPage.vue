<template>
  <div class="policy-workbench">
    <section class="policy-hero card">
      <div class="policy-hero-copy">
        <div class="eyebrow">Security Policy Workspace</div>
        <h2>统一管理访问控制、检测策略与代理认证</h2>
        <p class="muted">
          在同一页内完成核心策略开关、访问规则维护、策略验证和代理认证用户管理，减少配置分散带来的误操作。
        </p>
      </div>
      <div class="policy-hero-metrics">
        <div class="metric-tile">
          <span class="metric-label">默认动作</span>
          <strong>{{ defaultActionLabel }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">故障处理</span>
          <strong>{{ policy.fail_open ? 'Fail-open' : 'Fail-close' }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">可疑文件</span>
          <strong>{{ policy.block_suspicious ? '直接拦截' : '仅记录/放行' }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">认证用户</span>
          <strong>{{ proxyUsers.users.length }}</strong>
        </div>
      </div>
    </section>

    <PolicySwitch :policy="policy" :message="policyMessage" @save="savePolicy" />

    <section class="card section-shell">
      <div class="section-head">
        <div>
          <div class="section-kicker">Access Control Matrix</div>
          <div class="section-title">访问策略矩阵</div>
        </div>
        <p class="muted section-note">
          白名单与黑名单均按每行一条录入。分类规则示例：`social`、`video`、`adult`、`gambling`。
        </p>
      </div>

      <div class="policy-groups">
        <section class="subcard">
          <div class="subcard-title">域名规则</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>域名白名单</span>
              <textarea v-model="accessForm.domain_whitelist" rows="6" placeholder="example.com&#10;internal.company.local"></textarea>
            </label>
            <label class="field-block">
              <span>域名黑名单</span>
              <textarea v-model="accessForm.domain_blacklist" rows="6" placeholder="malware.example&#10;phishing.example"></textarea>
            </label>
          </div>
        </section>

        <section class="subcard">
          <div class="subcard-title">用户规则</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>用户白名单</span>
              <textarea v-model="accessForm.user_whitelist" rows="6" placeholder="alice&#10;ops-admin"></textarea>
            </label>
            <label class="field-block">
              <span>用户黑名单</span>
              <textarea v-model="accessForm.user_blacklist" rows="6" placeholder="temp-user&#10;blocked-user"></textarea>
            </label>
          </div>
        </section>

        <section class="subcard">
          <div class="subcard-title">URL 规则</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>URL 白名单</span>
              <textarea v-model="accessForm.url_whitelist" rows="6" placeholder="/health&#10;/api/internal/status"></textarea>
            </label>
            <label class="field-block">
              <span>URL 黑名单</span>
              <textarea v-model="accessForm.url_blacklist" rows="6" placeholder="/admin/debug&#10;/download/unsafe"></textarea>
            </label>
          </div>
        </section>

        <section class="subcard">
          <div class="subcard-title">分类规则</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>URL 分类白名单</span>
              <textarea v-model="accessForm.url_category_whitelist" rows="6" placeholder="social&#10;video"></textarea>
            </label>
            <label class="field-block">
              <span>URL 分类黑名单</span>
              <textarea v-model="accessForm.url_category_blacklist" rows="6" placeholder="adult&#10;gambling"></textarea>
            </label>
          </div>
        </section>
      </div>

      <div class="policy-action-bar">
        <label class="field-inline">
          <span>默认策略</span>
          <select v-model="accessForm.default_access_action">
            <option value="allow">allow</option>
            <option value="block">block</option>
          </select>
        </label>
        <div class="policy-action-copy muted">
          建议仅在白名单足够稳定时将默认动作切换为 `block`，以降低误拦截影响面。
        </div>
        <div class="policy-action-controls">
          <span
            class="status-text"
            :class="{
              success: accessMessage && accessMessage.includes('成功'),
              error: accessMessage && accessMessage.includes('失败'),
            }"
          >
            {{ accessMessage || '访问控制规则变更后会即时提交到服务端。' }}
          </span>
          <button class="primary-btn" @click="saveAccessPolicy">保存访问策略</button>
        </div>
      </div>
    </section>

    <div class="policy-bottom-grid">
      <section class="card section-shell compact-card">
        <div class="section-head">
          <div>
            <div class="section-kicker">Policy Validation</div>
            <div class="section-title">访问测试</div>
          </div>
          <p class="muted section-note">快速验证某个用户访问特定主机与路径时的策略命中结果。</p>
        </div>
        <div class="test-grid">
          <label class="field-block">
            <span>用户</span>
            <input v-model="policyTest.user" placeholder="例如 alice" />
          </label>
          <label class="field-block">
            <span>主机</span>
            <input v-model="policyTest.host" placeholder="例如 example.com" />
          </label>
          <label class="field-block">
            <span>URL</span>
            <input v-model="policyTest.url" placeholder="例如 /admin" />
          </label>
          <label class="field-block">
            <span>Method</span>
            <input v-model="policyTest.method" placeholder="例如 GET" />
          </label>
        </div>
        <div class="action-row">
          <button class="primary-btn" @click="runPolicyTest">执行测试</button>
        </div>
        <pre v-if="policyTestResult" class="result-panel">{{ policyTestResult }}</pre>
      </section>

      <section class="card section-shell compact-card">
        <div class="section-head">
          <div>
            <div class="section-kicker">Proxy Authentication</div>
            <div class="section-title">代理认证用户管理</div>
          </div>
          <p class="muted section-note">
            首次访问代理时，浏览器会提示输入这里创建的用户名和密码。
          </p>
        </div>

        <div class="auth-state">
          <span class="status-chip" :class="proxyUsers.enabled ? 'ok' : 'off'">
            {{ proxyUsers.enabled ? '已启用认证' : '未启用认证' }}
          </span>
          <span class="muted">当前共 {{ proxyUsers.users.length }} 个账号。</span>
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
            <span v-for="u in proxyUsers.users" :key="u.username" class="user-chip">{{ u.username }}</span>
          </div>
          <div v-else class="muted">当前还没有配置代理认证用户。</div>
        </div>
      </section>
    </div>

    <SystemConfig :config="config" />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
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

const defaultActionLabel = computed(() =>
  accessForm.value.default_access_action === 'block' ? '默认阻断' : '默认放行'
)

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
    policyMessage.value = '核心策略已保存'
    await load()
  } catch {
    policyMessage.value = '核心策略保存失败'
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
    proxyUserMessage.value = '代理认证用户保存成功'
    await load()
  } catch {
    proxyUserMessage.value = '代理认证用户保存失败'
  }
}

onMounted(load)
</script>
