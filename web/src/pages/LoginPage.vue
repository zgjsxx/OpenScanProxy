<template>
  <div class="card login-card">
    <h2>登录</h2>
    <div class="row login-form">
      <input v-model="u" placeholder="用户名" />
      <div class="pw-wrap">
        <input v-model="p" placeholder="密码" :type="pwType" />
        <button type="button" class="pw-toggle" @click="togglePw">
          <svg v-if="pwType === 'password'" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </button>
      </div>
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
const pwType = ref('password')
const error = ref('')

function togglePw() {
  pwType.value = pwType.value === 'password' ? 'text' : 'password'
}

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
