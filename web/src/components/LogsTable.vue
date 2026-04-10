<template>
  <div class="card">
    <div class="row">
      <input v-model="filters.q" placeholder="搜索 URL/host/文件名/签名" style="min-width:280px" />
      <select v-model="filters.action"><option value="">全部动作</option><option>allow</option><option>block</option><option>log</option></select>
      <select v-model="filters.result"><option value="">全部结果</option><option>clean</option><option>infected</option><option>suspicious</option><option>error</option></select>
      <input v-model="filters.host" placeholder="host过滤" />
      <select v-model="filters.method"><option value="">全部方法</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>CONNECT</option></select>
      <input v-model="filters.status" placeholder="状态码" style="max-width:100px" />
      <input v-model="filters.path" placeholder="path过滤" />
      <select v-model="filters.event_type"><option value="">全部事件</option><option>access</option><option>scan</option></select>
      <input v-model="filters.time_from" type="datetime-local" />
      <input v-model="filters.time_to" type="datetime-local" />
      <button @click="$emit('refresh')">查询</button>
    </div>
    <div class="muted">命中 {{ logs.length }} 条</div>
    <div class="row" style="margin:8px 0">
      <button @click="$emit('set-page', pager.page - 1)" :disabled="pager.page <= 1">上一页</button>
      <span class="muted">第 {{ pager.page }} 页</span>
      <button @click="$emit('set-page', pager.page + 1)" :disabled="logs.length < pager.pageSize">下一页</button>
    </div>
    <table class="table">
      <thead><tr><th>类型</th><th>时间</th><th>方法</th><th>状态</th><th>客户端</th><th>主机</th><th>URL</th><th>文件</th><th>结果</th><th>动作</th><th>签名</th></tr></thead>
      <tbody>
        <tr v-for="(e, idx) in logs" :key="`${e.timestamp}-${idx}`">
          <td>{{ e.event_type || '' }}</td>
          <td>{{ e.timestamp }}</td>
          <td>{{ e.method || '' }}</td>
          <td>{{ e.status_code || '' }}</td>
          <td>{{ e.client_addr || '' }}</td>
          <td>{{ e.host || '' }}</td>
          <td>{{ e.url || '' }}</td>
          <td>{{ e.filename || '' }}</td>
          <td>{{ e.result || '' }}</td>
          <td><span class="pill" :class="e.action">{{ e.action }}</span></td>
          <td>{{ e.signature || '' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
defineProps({
  logs: { type: Array, required: true },
  filters: { type: Object, required: true },
  pager: { type: Object, required: true },
})
defineEmits(['refresh', 'set-page'])
</script>
