<script setup lang="ts">
import ZoneProofLogo from '@/components/layout/ZoneProofLogo.vue'
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const status   = ref<'loading' | 'ready' | 'invalid'>('loading')
const invite   = ref<any>(null)
const errorMsg = ref('')

const token         = ref('')
const fullName      = ref('')
const password      = ref('')
const termsAccepted = ref(false)
const submitting    = ref(false)
const submitError   = ref('')

onMounted(async () => {
  const t = route.query.token
  if (typeof t !== 'string' || !t) {
    status.value = 'invalid'
    errorMsg.value = 'No invite token found in this link.'
    return
  }
  token.value = t
  try {
    invite.value = await api.getInvite(t)
    if (invite.value.accepted) {
      status.value = 'invalid'
      errorMsg.value = 'This invite has already been accepted. Try signing in instead.'
      return
    }
    status.value = 'ready'
  } catch (e: any) {
    status.value = 'invalid'
    errorMsg.value = e.message || 'This invite link is invalid or has expired.'
  }
})

async function submit() {
  submitError.value = ''
  if (!fullName.value.trim()) { submitError.value = 'Enter your name'; return }
  if (password.value.length < 8) { submitError.value = 'Password must be at least 8 characters'; return }
  if (!termsAccepted.value) { submitError.value = 'You must accept the Terms of Service and Privacy Policy'; return }
  submitting.value = true
  try {
    const res = await api.acceptInvite(token.value, fullName.value, password.value, termsAccepted.value)
    auth.applyLoginData(res)
    router.push({ name: 'overview' })
  } catch (e: any) {
    submitError.value = e.message || 'Failed to accept invite'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="brand">
        <ZoneProofLogo :size="40" subtitle="Email Security Posture" />
      </div>

      <div v-if="status === 'loading'" class="state">
        <div class="spinner" />
      </div>

      <div v-else-if="status === 'invalid'" class="state">
        <div class="icon bad">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
        </div>
        <div class="state-title">Invite link invalid</div>
        <p class="state-sub">{{ errorMsg }}</p>
        <button class="btn" @click="router.push({ name: 'login' })">Go to sign in</button>
      </div>

      <template v-else>
        <h2>Join {{ invite.workspace_name || 'the workspace' }}</h2>
        <p class="sub">You've been invited as a <strong>{{ invite.role }}</strong>. Set a password to finish creating your account for <strong>{{ invite.email }}</strong>.</p>
        <form @submit.prevent="submit">
          <div class="field">
            <label>Full name</label>
            <input v-model="fullName" type="text" placeholder="Jane Smith" required autocomplete="name"/>
          </div>
          <div class="field">
            <label>Password</label>
            <input v-model="password" type="password" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password"/>
          </div>
          <label class="terms-row">
            <input v-model="termsAccepted" type="checkbox"/>
            <span>I agree to the <a href="/terms" target="_blank" rel="noopener">Terms of Service</a> and <a href="/privacy" target="_blank" rel="noopener">Privacy Policy</a></span>
          </label>
          <div v-if="submitError" class="err">{{ submitError }}</div>
          <button type="submit" class="btn" :disabled="submitting || !termsAccepted">
            {{ submitting ? 'Joining…' : 'Accept invite & continue' }}
          </button>
        </form>
      </template>
    </div>
  </div>
</template>

<style scoped>
.login-wrap { min-height:100vh; display:grid; place-items:center; }
.login-card {
  width:400px; max-width:94vw;
  background:var(--glass); border:1px solid var(--line2);
  border-radius:22px; padding:32px;
  backdrop-filter:blur(16px);
}
.brand { display:flex; align-items:center; gap:12px; margin-bottom:28px; }

h2 { font-family:var(--disp); font-weight:800; font-size:22px; margin:0; }
.sub { color:var(--muted); font-size:13px; margin:5px 0 24px; line-height:1.5; }
.sub strong { color:var(--txt); }

.field { margin-bottom:14px; }
label { font-family:var(--mono); font-size:10px; letter-spacing:.6px; color:var(--faint); text-transform:uppercase; display:block; margin-bottom:6px; }
input[type=email], input[type=password], input[type=text] {
  width:100%; background:rgba(255,255,255,.05); border:1px solid var(--line2);
  border-radius:11px; padding:12px 14px; color:var(--txt); font-family:var(--body);
  font-size:14px; outline:none; box-sizing:border-box; transition:border-color .15s;
}
input:focus { border-color:var(--indigo); }

.terms-row { display:flex; align-items:flex-start; gap:8px; font-size:11.5px; color:var(--muted); line-height:1.5; margin:4px 0 14px; cursor:pointer; }
.terms-row input[type=checkbox] { margin-top:2px; flex:none; accent-color:var(--indigo); }
.terms-row a { color:var(--accent-soft); text-decoration:none; }
.terms-row a:hover { text-decoration:underline; }

.err { color:var(--bad); font-size:12px; margin-bottom:10px; }

.btn { width:100%; background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:13px; font-family:var(--disp); font-weight:700; font-size:14px; cursor:pointer; margin-top:6px; transition:opacity .15s; }
.btn:disabled { opacity:.6; cursor:not-allowed; }
.btn:hover:not(:disabled) { opacity:.88; }

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
.icon.bad { background:rgba(255,77,109,.12); color:var(--bad); }
</style>
