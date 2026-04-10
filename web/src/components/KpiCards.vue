<template>
  <div class="grid">
    <div class="card" v-for="k in keys" :key="k">
      <div class="muted">{{ k }}</div>
      <div style="font-size:26px;margin-top:4px">{{ stats[k] ?? 0 }}</div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  stats: { type: Object, required: true },
})

const keys = ['total_requests','https_mitm_requests','scanned_files','clean','infected','suspicious','blocked','scanner_error']
</script>
