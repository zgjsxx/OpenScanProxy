<template>
  <div class="policy-workbench">
    <section class="policy-hero card">
      <div class="policy-hero-copy">
        <div class="eyebrow">Security Policy Workspace</div>
        <h2>按“全局名单、命中规则、默认规则”管理访问策略</h2>
        <p class="muted">
          先配置全局黑白名单，再维护对特定用户生效的访问规则，最后用默认规则兜底，整体更贴近企业常见的访问控制模型。
        </p>
      </div>
      <div class="policy-hero-metrics">
        <div class="metric-tile">
          <span class="metric-label">全局默认动作</span>
          <strong>{{ defaultActionLabel }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">策略规则数</span>
          <strong>{{ accessRules.length }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">故障处理</span>
          <strong>{{ policy.fail_open ? 'Fail-open' : 'Fail-close' }}</strong>
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
          <div class="section-kicker">Global Access Lists</div>
          <div class="section-title">全局黑白名单</div>
        </div>
        <p class="muted section-note">
          这部分优先于命中规则执行，适合放全局例外、企业统一放行项，以及必须统一阻断的站点或类别。
        </p>
      </div>

      <div class="policy-groups">
        <section class="subcard">
          <div class="subcard-title">全局用户名单</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>用户白名单</span>
              <textarea v-model="accessForm.user_whitelist" rows="5" placeholder="vip-user&#10;admin-user"></textarea>
            </label>
            <label class="field-block">
              <span>用户黑名单</span>
              <textarea v-model="accessForm.user_blacklist" rows="5" placeholder="disabled-user&#10;risk-user"></textarea>
            </label>
          </div>
        </section>

        <section class="subcard">
          <div class="subcard-title">域名与 URL 名单</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>域名白名单</span>
              <textarea v-model="accessForm.domain_whitelist" rows="5" placeholder="intranet.company.local&#10;trusted.example.com"></textarea>
            </label>
            <label class="field-block">
              <span>域名黑名单</span>
              <textarea v-model="accessForm.domain_blacklist" rows="5" placeholder="malware.example&#10;phishing.example"></textarea>
            </label>
            <label class="field-block">
              <span>URL 白名单</span>
              <textarea v-model="accessForm.url_whitelist" rows="5" placeholder="/api/internal/*&#10;/health"></textarea>
            </label>
            <label class="field-block">
              <span>URL 黑名单</span>
              <textarea v-model="accessForm.url_blacklist" rows="5" placeholder="/admin/debug&#10;/download/unsafe"></textarea>
            </label>
          </div>
        </section>

        <section class="subcard">
          <div class="subcard-title">全局分类名单</div>
          <div class="policy-field-grid">
            <label class="field-block">
              <span>分类白名单</span>
              <textarea v-model="accessForm.url_category_whitelist" rows="5" placeholder="developer&#10;finance"></textarea>
            </label>
            <label class="field-block">
              <span>分类黑名单</span>
              <textarea v-model="accessForm.url_category_blacklist" rows="5" placeholder="adult&#10;gambling"></textarea>
            </label>
          </div>
        </section>
      </div>
    </section>

    <section class="card section-shell">
      <div class="section-head">
        <div>
          <div class="section-kicker">Per-user Rules</div>
          <div class="section-title">命中规则</div>
        </div>
        <p class="muted section-note">
          每条规则可绑定一个或多个用户，并对这些用户追加更细粒度的域名、URL 或分类访问控制。例如 user001 放行 game，user002 阻断 shopping。
        </p>
      </div>

      <div class="rules-stack">
        <article v-for="(rule, index) in accessRules" :key="rule.id" class="rule-card">
          <div class="rule-card-head">
            <div>
              <div class="rule-index">Rule {{ index + 1 }}</div>
              <input v-model="rule.name" class="rule-name-input" placeholder="例如：研发用户允许 developer / game" />
            </div>
            <button class="ghost danger-btn" @click="removeRule(index)">删除规则</button>
          </div>

          <div class="rule-grid">
            <label class="field-block rule-users-field">
              <span>生效用户</span>
              <textarea v-model="rule.usersText" rows="4" placeholder="user001&#10;user002"></textarea>
            </label>

            <div class="rule-groups">
              <div class="rule-mini-grid">
                <label class="field-block">
                  <span>允许分类</span>
                  <textarea v-model="rule.urlCategoryWhitelistText" rows="4" placeholder="game&#10;developer"></textarea>
                </label>
                <label class="field-block">
                  <span>阻断分类</span>
                  <textarea v-model="rule.urlCategoryBlacklistText" rows="4" placeholder="shopping&#10;social"></textarea>
                </label>
              </div>
              <div class="rule-mini-grid">
                <label class="field-block">
                  <span>允许域名</span>
                  <textarea v-model="rule.domainWhitelistText" rows="4" placeholder="games.company.com"></textarea>
                </label>
                <label class="field-block">
                  <span>阻断域名</span>
                  <textarea v-model="rule.domainBlacklistText" rows="4" placeholder="shop.example.com"></textarea>
                </label>
              </div>
              <div class="rule-mini-grid">
                <label class="field-block">
                  <span>允许 URL</span>
                  <textarea v-model="rule.urlWhitelistText" rows="4" placeholder="/games/*"></textarea>
                </label>
                <label class="field-block">
                  <span>阻断 URL</span>
                  <textarea v-model="rule.urlBlacklistText" rows="4" placeholder="/shop/*"></textarea>
                </label>
              </div>
            </div>
          </div>
        </article>

        <div v-if="!accessRules.length" class="empty-rules muted">
          还没有配置用户规则。你可以新增一条规则，让指定用户只允许或禁止访问某些类别、域名或 URL。
        </div>
      </div>

      <div class="action-row rule-toolbar">
        <button class="primary-btn" @click="addRule">新增规则</button>
        <span class="muted">规则在全局名单之后匹配，未命中任何规则时走默认规则。</span>
      </div>
    </section>

    <section class="card section-shell">
      <div class="section-head">
        <div>
          <div class="section-kicker">Default Rule</div>
          <div class="section-title">默认规则</div>
        </div>
        <p class="muted section-note">
          当请求没有命中全局名单，也没有命中任何用户规则时，系统会按这里配置的默认动作处理。
        </p>
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
          如果你的规则是“按需放行”，默认策略建议设为 `block`；如果你的规则是“按需阻断”，默认策略建议设为 `allow`。
        </div>
        <div class="policy-action-controls">
          <span
            class="status-text"
            :class="{
              success: accessMessage && accessMessage.includes('成功'),
              error: accessMessage && accessMessage.includes('失败'),
            }"
          >
            {{ accessMessage || '保存后将同时提交全局名单、用户规则和默认规则。' }}
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
          <p class="muted section-note">输入用户、主机和 URL，验证它最后命中了全局名单、哪条规则，还是默认规则。</p>
        </div>
        <div class="test-grid">
          <label class="field-block">
            <span>用户</span>
            <input v-model="policyTest.user" placeholder="例如 user001" />
          </label>
          <label class="field-block">
            <span>主机</span>
            <input v-model="policyTest.host" placeholder="例如 steam.example.com" />
          </label>
          <label class="field-block">
            <span>URL</span>
            <input v-model="policyTest.url" placeholder="例如 /game/store" />
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
          <p class="muted section-note">首次访问代理时，浏览器会提示输入这里创建的用户名和密码。</p>
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
const accessRules = ref([])
const policyTest = ref({ user: '', host: '', url: '/', method: 'GET' })
const policyTestResult = ref('')
const proxyUsers = ref({ enabled: false, users: [] })
const newProxyUser = ref({ username: '', password: '' })

const defaultActionLabel = computed(() =>
  accessForm.value.default_access_action === 'block' ? '默认阻断' : '默认放行'
)

const asLines = (text) =>
  String(text || '')
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean)

const createEditableRule = (rule = {}) => ({
  id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
  name: rule.name || '',
  usersText: (rule.users || []).join('\n'),
  domainWhitelistText: (rule.domain_whitelist || []).join('\n'),
  domainBlacklistText: (rule.domain_blacklist || []).join('\n'),
  urlWhitelistText: (rule.url_whitelist || []).join('\n'),
  urlBlacklistText: (rule.url_blacklist || []).join('\n'),
  urlCategoryWhitelistText: (rule.url_category_whitelist || []).join('\n'),
  urlCategoryBlacklistText: (rule.url_category_blacklist || []).join('\n'),
})

function addRule() {
  accessRules.value.push(createEditableRule())
}

function removeRule(index) {
  accessRules.value.splice(index, 1)
}

function serializeRules() {
  return accessRules.value.map((rule, index) => ({
    name: String(rule.name || '').trim() || `rule-${index + 1}`,
    users: asLines(rule.usersText),
    domain_whitelist: asLines(rule.domainWhitelistText),
    domain_blacklist: asLines(rule.domainBlacklistText),
    url_whitelist: asLines(rule.urlWhitelistText),
    url_blacklist: asLines(rule.urlBlacklistText),
    url_category_whitelist: asLines(rule.urlCategoryWhitelistText),
    url_category_blacklist: asLines(rule.urlCategoryBlacklistText),
  }))
}

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
    accessRules.value = (access.access_rules || []).map((rule) => createEditableRule(rule))
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
      access_rules: serializeRules(),
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
