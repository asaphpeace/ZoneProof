<script setup lang="ts">
import ZoneProofLogo from '@/components/layout/ZoneProofLogo.vue'
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const status = ref<'verifying' | 'success' | 'error'>('verifying')
const errorMessage = ref('')

onMounted(async () => {
  const token = route.query.token
  if (typeof token !== 'string' || !token) {
    status.value = 'error'
    errorMessage.value = 'No verification token found in this link.'
    return
  }
  try {
    await api.verifyEmail(token)
    status.value = 'success'
  } catch (e: any) {
    status.value = 'error'
    errorMessage.value = e.message || 'This verification link is invalid or has expired.'
  }
})

function continueToApp() {
  router.push({ name: auth.isAuthenticated ? 'overview' : 'login' })
}
</script>

<template>
  <div class="wrap">
    <div class="card">
      <div class="brand">
        <ZoneProofLogo :size="40" />
      </div>

      <div v-if="status === 'verifying'" class="state">
        <div class="spinner" />
        <div class="state-title">Verifying your email…</div>
      </div>

      <div v-else-if="status === 'success'" class="state">
        <div class="icon good">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
        </div>
        <div class="state-title">Email verified</div>
        <p class="state-sub">Your email address has been confirmed.</p>
        <button class="btn" @click="continueToApp">Continue</button>
      </div>

      <div v-else class="state">
        <div class="icon bad">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
        </div>
        <div class="state-title">Verification failed</div>
        <p class="state-sub">{{ errorMessage }}</p>
        <button class="btn" @click="continueToApp">Go to sign in</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.wrap { min-height:100vh; display:grid; place-items:center; }
.card {
  width:400px; max-width:94vw;
  background:var(--glass); border:1px solid var(--line2);
  border-radius:22px; padding:32px;
  backdrop-filter:blur(16px);
}
.brand { display:flex; align-items:center; gap:12px; margin-bottom:28px; }

.state { text-align:center; padding:12px 0; }
.state-title { font-family:var(--disp); font-weight:800; font-size:18px; margin-top:14px; }
.state-sub { color:var(--muted); font-size:13px; margin:8px 0 20px; line-height:1.5; }

.spinner {
  width:36px; height:36px; margin:0 auto;
  border:3px solid rgba(255,255,255,.1); border-top-color:var(--indigo);
  border-radius:50%; animation:spin .8s linear infinite;
}
@keyframes spin { to { transform:rotate(360deg); } }

.icon { width:52px; height:52px; margin:0 auto; border-radius:50%; display:grid; place-items:center; }
.icon svg { width:26px; height:26px; }
.icon.good { background:rgba(52,224,161,.12); color:var(--good); }
.icon.bad  { background:rgba(255,77,109,.12); color:var(--bad); }

.btn { width:100%; background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:13px; font-family:var(--disp); font-weight:700; font-size:14px; cursor:pointer; transition:opacity .15s; }
.btn:hover { opacity:.88; }
</style>
