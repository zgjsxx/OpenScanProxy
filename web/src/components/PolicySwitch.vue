<template>
  <section class="card section-shell strategy-switch-card">
    <div class="section-head">
      <div>
        <div class="section-kicker">Core Enforcement</div>
        <div class="section-title">核心策略开关</div>
      </div>
      <p class="muted section-note">这些策略会直接影响代理在异常和可疑文件场景下的默认处置方式。</p>
    </div>

    <div class="switch-grid">
      <label class="toggle-card">
        <div class="toggle-copy">
          <span class="toggle-title">扫描错误时放行</span>
          <span class="toggle-desc">启用后，当扫描器异常或超时时，请求将按照 fail-open 模式继续放行。</span>
        </div>
        <div class="toggle-side">
          <span class="status-chip" :class="localPolicy.fail_open ? 'warn' : 'off'">
            {{ localPolicy.fail_open ? '已启用' : '未启用' }}
          </span>
          <span class="toggle-switch">
            <input v-model="localPolicy.fail_open" type="checkbox" />
            <span class="toggle-slider"></span>
          </span>
        </div>
      </label>

      <label class="toggle-card">
        <div class="toggle-copy">
          <span class="toggle-title">拦截 suspicious</span>
          <span class="toggle-desc">启用后，对检测结果为 suspicious 的文件直接执行阻断，而不是仅记录风险。</span>
        </div>
        <div class="toggle-side">
          <span class="status-chip" :class="localPolicy.block_suspicious ? 'ok' : 'off'">
            {{ localPolicy.block_suspicious ? '已启用' : '未启用' }}
          </span>
          <span class="toggle-switch">
            <input v-model="localPolicy.block_suspicious" type="checkbox" />
            <span class="toggle-slider"></span>
          </span>
        </div>
      </label>
    </div>

    <div class="action-row split">
      <span
        class="status-text"
        :class="{
          success: message && message.includes('保存') && !message.includes('失败'),
          error: message && message.includes('失败'),
        }"
      >
        {{ message || '建议策略变更后结合下方访问测试做一次快速验证。' }}
      </span>
      <button class="primary-btn" @click="$emit('save', { ...localPolicy })">保存核心策略</button>
    </div>
  </section>
</template>

<script setup>
import { reactive, watch } from 'vue'

defineEmits(['save'])

const props = defineProps({
  policy: { type: Object, required: true },
  message: { type: String, default: '' },
})

const localPolicy = reactive({ fail_open: false, block_suspicious: false })

watch(
  () => props.policy,
  (p) => {
    localPolicy.fail_open = !!p.fail_open
    localPolicy.block_suspicious = !!p.block_suspicious
  },
  { immediate: true, deep: true }
)
</script>
