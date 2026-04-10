<template>
  <div class="card">
    <h3 style="margin-top:0">系统配置</h3>
    <pre>{{ pretty }}</pre>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  config: { type: Object, required: true },
})

const pretty = computed(() => JSON.stringify(props.config, null, 2))
</script>
