<template>
  <div :class="embedded ? 'config-wrap' : 'card config-wrap'">
    <h3 style="margin-top:0">系统配置</h3>
    <pre>{{ pretty }}</pre>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  config: { type: Object, required: true },
  embedded: { type: Boolean, default: false },
})

const pretty = computed(() => JSON.stringify(props.config, null, 2))
</script>
