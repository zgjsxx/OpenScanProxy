<template>
  <div class="card" style="max-width:420px;margin:40px auto;">
    <h2>登录</h2>
    <div class="row" style="flex-direction:column;align-items:stretch;">
      <input v-model="u" placeholder="用户名" />
      <input v-model="p" placeholder="密码" type="password" />
      <button @click="login">登录</button>
      <span class="muted">{{ error }}</span>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const u = ref('')
const p = ref('')
const error = ref('')

async function login() {
  error.value = ''
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ u: u.value, p: p.value }),
  })
  if (r.ok) {
    router.push('/dashboard')
  } else {
    error.value = '用户名或密码错误'
  }
}
</script>
