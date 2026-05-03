<template>
  <div class="policy-workbench">
    <section class="policy-hero card">
      <div class="policy-hero-copy">
        <div class="eyebrow">Security Policy Workspace</div>
        <h2>按"全局名单、命中规则、默认规则"管理访问策略</h2>
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
      </div>
    </section>

    <div class="tab-bar">
      <button
        v-for="t in tabs"
        :key="t.key"
        class="tab-item"
        :class="{ active: activeTab === t.key }"
        @click="activeTab = t.key"
      >{{ t.label }}</button>
    </div>

    <template v-if="activeTab === 'overview'">
      <PolicySwitch :policy="policy" :message="policyMessage" @save="savePolicy" />

      <section class="card section-shell">
        <div class="section-head">
          <div>
            <div class="section-kicker">HTTPS Decryption</div>
            <div class="section-title">HTTPS 解密配置</div>
          </div>
          <p class="muted section-note">开启 MITM 后可对 HTTPS 流量进行扫描和策略控制。需要客户端安装并信任 CA 证书。</p>
        </div>

        <div class="switch-grid">
          <label class="toggle-card">
            <div class="toggle-copy">
              <span class="toggle-title">HTTPS 解密（MITM）</span>
              <span class="toggle-desc">开启后代理会签发对应域名的临时证书，实现 HTTPS 流量的可见性与策略控制。</span>
            </div>
            <div class="toggle-side">
              <span class="status-chip" :class="mitmEnabled ? 'ok' : 'off'">
                {{ mitmEnabled ? '已启用' : '未启用' }}
              </span>
              <span class="toggle-switch">
                <input v-model="mitmEnabled" type="checkbox" @change="saveMitmToggle" />
                <span class="toggle-slider"></span>
              </span>
            </div>
          </label>

          <div class="mitm-download-card">
            <div class="toggle-copy">
              <span class="toggle-title">下载 CA 证书</span>
              <span class="toggle-desc">将此证书安装到设备的受信任根证书颁发机构中，以避免浏览器 HTTPS 警告。</span>
            </div>
            <a href="/api/ca-cert" class="primary-btn mitm-dl-btn">下载 CA 证书</a>
          </div>
        </div>

        <div class="action-row split" style="margin-top:14px">
          <span class="status-text" :class="{ success: mitmMessage && mitmMessage.includes('已保存'), error: mitmMessage && mitmMessage.includes('失败') }">
            {{ mitmMessage || '切换 MITM 开关即时生效，无需额外保存。' }}
          </span>
        </div>
      </section>
    </template>

    <template v-if="activeTab === 'lists'">
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
    </template>

    <template v-if="activeTab === 'rules'">
      <template v-if="selectedRuleIndex === null">
        <section class="card section-shell">
          <div class="section-head">
            <div>
              <div class="section-kicker">Per-user Rules</div>
              <div class="section-title">命中规则</div>
            </div>
            <p class="muted section-note">
              点击规则查看和编辑详细配置。规则在全局名单之后匹配，未命中任何规则时走默认规则。
            </p>
          </div>

          <div v-if="accessRules.length" class="rule-cards-list">
            <article
              v-for="(rule, index) in accessRules"
              :key="rule.id"
              class="rule-summary-card"
              @click="selectedRuleIndex = index"
            >
              <div class="rule-summary-left">
                <span class="rule-summary-num">{{ index + 1 }}</span>
                <div class="rule-summary-body">
                  <div class="rule-summary-name">{{ rule.name || '(未命名)' }}</div>
                  <div v-if="rule.usersText.trim()" class="rule-summary-users">{{ rule.usersText.split('\n').filter(Boolean).slice(0, 3).join(', ') }}<span v-if="rule.usersText.split('\n').filter(Boolean).length > 3"> ...</span></div>
                </div>
              </div>
              <div class="rule-summary-conds">
                <span v-if="rule.domainText.trim()" class="cond-tag">域 {{ rule.domainText.split('\n').filter(Boolean).slice(0, 2).join(', ') }}</span>
                <span v-if="rule.urlCategoryText.trim()" class="cond-tag">分类 {{ rule.urlCategoryText.split('\n').filter(Boolean).slice(0, 2).join(', ') }}</span>
                <span v-if="rule.urlText.trim()" class="cond-tag">URL {{ rule.urlText.split('\n').filter(Boolean).slice(0, 2).join(', ') }}</span>
                <span v-if="!rule.domainText.trim() && !rule.urlCategoryText.trim() && !rule.urlText.trim()" class="muted" style="font-size:12px">未设置条件</span>
              </div>
              <div class="rule-summary-right">
                <span class="rule-action-badge" :class="rule.action">{{ rule.action }}</span>
                <span class="rule-summary-arrow">→</span>
              </div>
            </article>
          </div>

          <div v-if="!accessRules.length" class="empty-rules muted">
            还没有配置用户规则。点击下方按钮新增一条规则。
          </div>

          <div class="action-row rule-toolbar">
            <button class="primary-btn" @click="addRule">新增规则</button>
          </div>
        </section>
      </template>

      <template v-if="selectedRuleIndex !== null">
        <section class="card section-shell">
          <div class="section-head">
            <div>
              <button class="ghost back-btn" @click="selectedRuleIndex = null">← 返回规则列表</button>
              <div class="section-title" style="margin-top:4px">Rule {{ selectedRuleIndex + 1 }}</div>
            </div>
            <button class="ghost danger-btn" @click="removeRule(selectedRuleIndex); selectedRuleIndex = null">删除此规则</button>
          </div>

          <article class="rule-edit-form">
            <label class="field-block">
              <span>规则名称</span>
              <input v-model="accessRules[selectedRuleIndex].name" placeholder="例如：test001 访问 game.example.com 放行" />
            </label>

            <label class="field-block">
              <span>生效用户</span>
              <SearchableUserSelect
                v-model="accessRules[selectedRuleIndex].usersText"
                :users="proxyUsers.users"
                :groups="userGroups"
              />
            </label>

            <div class="rule-cond-grid">
              <label class="field-block">
                <span>命中分类</span>
                <textarea v-model="accessRules[selectedRuleIndex].urlCategoryText" rows="2" placeholder="game"></textarea>
              </label>
              <label class="field-block">
                <span>命中域名</span>
                <textarea v-model="accessRules[selectedRuleIndex].domainText" rows="2" placeholder="example.com"></textarea>
              </label>
              <label class="field-block">
                <span>命中 URL</span>
                <textarea v-model="accessRules[selectedRuleIndex].urlText" rows="2" placeholder="/game/*"></textarea>
              </label>
            </div>

            <div class="rule-action-row">
              <label class="field-inline">
                <span>Action</span>
                <select v-model="accessRules[selectedRuleIndex].action" class="rule-action-select">
                  <option value="allow">allow</option>
                  <option value="block">block</option>
                </select>
              </label>
              <span class="muted" style="font-size:13px; line-height:1.6">命中后按此动作直接放行或阻断。</span>
            </div>
          </article>
        </section>
      </template>

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
            如果你的规则是"按需放行"，默认策略建议设为 `block`；如果你的规则是"按需阻断"，默认策略建议设为 `allow`。
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
    </template>

    <template v-if="activeTab === 'test'">
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
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getJson, postJson } from '../api'
import PolicySwitch from '../components/PolicySwitch.vue'
import SearchableUserSelect from '../components/SearchableUserSelect.vue'

const router = useRouter()

const activeTab = ref('overview')
const tabs = [
  { key: 'overview', label: '概览' },
  { key: 'lists', label: '全局名单' },
  { key: 'rules', label: '命中规则' },
  { key: 'test', label: '访问测试' },
]

const policy = ref({ fail_open: false, block_suspicious: false })
const policyMessage = ref('')
const mitmEnabled = ref(false)
const mitmMessage = ref('')
const accessMessage = ref('')
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
const selectedRuleIndex = ref(null)
const proxyUsers = ref({ users: [] })
const userGroups = ref([])
const policyTest = ref({ user: '', host: '', url: '/', method: 'GET' })
const policyTestResult = ref('')

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
  usersText: [...(rule.users || []), ...(rule.groups || []).map(g => '@' + g)].join('\n'),
  domainText: ((rule.domain_whitelist && rule.domain_whitelist.length ? rule.domain_whitelist : rule.domain_blacklist) || []).join('\n'),
  urlText: ((rule.url_whitelist && rule.url_whitelist.length ? rule.url_whitelist : rule.url_blacklist) || []).join('\n'),
  urlCategoryText: ((rule.url_category_whitelist && rule.url_category_whitelist.length ? rule.url_category_whitelist : rule.url_category_blacklist) || []).join('\n'),
  action:
    rule.domain_whitelist?.length || rule.url_whitelist?.length || rule.url_category_whitelist?.length
      ? 'allow'
      : 'block',
})

function addRule() {
  accessRules.value.push(createEditableRule())
  selectedRuleIndex.value = accessRules.value.length - 1
}

function removeRule(index) {
  accessRules.value.splice(index, 1)
}

function serializeRules() {
  return accessRules.value.map((rule, index) => {
    const allUsers = asLines(rule.usersText)
    return {
      name: String(rule.name || '').trim() || `rule-${index + 1}`,
      users: allUsers.filter(u => !u.startsWith('@')),
      groups: allUsers.filter(u => u.startsWith('@')).map(g => g.slice(1)),
      domain_whitelist: rule.action === 'allow' ? asLines(rule.domainText) : [],
      domain_blacklist: rule.action === 'block' ? asLines(rule.domainText) : [],
      url_whitelist: rule.action === 'allow' ? asLines(rule.urlText) : [],
      url_blacklist: rule.action === 'block' ? asLines(rule.urlText) : [],
      url_category_whitelist: rule.action === 'allow' ? asLines(rule.urlCategoryText) : [],
      url_category_blacklist: rule.action === 'block' ? asLines(rule.urlCategoryText) : [],
    }
  })
}

async function load() {
  try {
    policy.value = await getJson('/api/policy')
    const access = await getJson('/api/access-policy')
    try { proxyUsers.value = await getJson('/api/proxy-users') } catch {}
    try { userGroups.value = await getJson('/api/user-groups') } catch {}
    try { const ac = await getJson('/api/auth-config'); mitmEnabled.value = !!ac.enable_https_mitm } catch {}
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

async function saveMitmToggle() {
  try {
    await postJson('/api/auth-config', { enable_https_mitm: mitmEnabled.value })
    mitmMessage.value = '已保存'
    setTimeout(() => { mitmMessage.value = '' }, 2000)
  } catch {
    mitmMessage.value = '保存失败'
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

onMounted(load)
</script>
