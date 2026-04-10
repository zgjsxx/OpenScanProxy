<template>
  <div class="card">
    <div class="row">
      <label><input type="checkbox" v-model="localPolicy.fail_open" /> 扫描错误时放行（fail-open）</label>
      <label><input type="checkbox" v-model="localPolicy.block_suspicious" /> 拦截 suspicious</label>
    </div>
    <div class="row">
      <button @click="$emit('save', { ...localPolicy })">保存 Policy</button>
      <span class="muted">{{ message }}</span>
    </div>
  </div>
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
