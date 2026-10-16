<script setup lang="ts">
import ZoneProofLogo from '@/components/layout/ZoneProofLogo.vue'
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { api, setToken } from '@/api/client'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

type Step = 'credentials' | '2fa' | 'register' | 'forgot' | 'reset'
const step = ref<Step>('credentials')

const email         = ref('')
const password      = ref('')
const fullName      = ref('')
const workspaceName = ref('')
const totpCode      = ref('')
const preAuthToken  = ref('')
const resetToken    = ref('')
const newPassword   = ref('')
const termsAccepted = ref(false)

const error   = ref('')
const success = ref('')
const loading = ref(false)

onMounted(() => {
  // A reset-password email link lands here as /reset-password?token=...
  const t = route.query.token
  if (route.path === '/reset-password' && typeof t === 'string' && t) {
    resetToken.value = t
    step.value = 'reset'
    return
  }
  // Redirected here after an action that invalidated the current session
  // token (e.g. ProfileView's change-password) — see route.query.notice.
  if (route.query.notice === 'password-changed') {
    success.value = 'Password changed — sign in with your new password.'
  }
})

async function submitForgot() {
  error.value = ''
  success.value = ''
  loading.value = true
  try {
    const res = await api.forgotPassword(email.value)
    success.value = res.message
  } catch (e: any) {
    error.value = e.message || 'Something went wrong'
  } finally {
    loading.value = false
  }
}

async function submitReset() {
  error.value = ''
  loading.value = true
  try {
    await api.resetPassword(resetToken.value, newPassword.value)
    success.value = 'Password reset — sign in with your new password.'
    step.value = 'credentials'
    password.value = ''
  } catch (e: any) {
    error.value = e.message || 'This reset link is invalid or has expired'
  } finally {
    loading.value = false
  }
}

async function submitCredentials() {
  error.value   = ''
  loading.value = true
  try {
    const res = await auth.login(email.value, password.value)
    if (res?.requires_2fa) {
      preAuthToken.value = res.pre_auth_token
      step.value = '2fa'
      totpCode.value = ''
    } else {
      router.push({ name: 'overview' })
    }
  } catch (e: any) {
    error.value = e.message || 'Login failed'
  } finally {
    loading.value = false
  }
}

async function submitTotpCode() {
  error.value   = ''
  const code = totpCode.value.replace(/\s/g, '')
  if (code.length !== 6) { error.value = 'Enter the 6-digit code from your authenticator app'; return }
  loading.value = true
  try {
    const res = await api.twoFaChallenge(preAuthToken.value, code)
    auth.applyLoginData(res)
    router.push({ name: 'overview' })
  } catch (e: any) {
    error.value = e.message || 'Invalid code'
  } finally {
    loading.value = false
  }
}

async function submitRegister() {
  error.value = ''
  if (!termsAccepted.value) { error.value = 'You must accept the Terms of Service and Privacy Policy'; return }
  loading.value = true
  try {
    const res = await api.register(email.value, password.value, fullName.value || undefined, workspaceName.value || undefined, termsAccepted.value)
    auth.applyLoginData(res)
    router.push({ name: 'overview' })
  } catch (e: any) {
    error.value = e.message || 'Registration failed'
  } finally {
    loading.value = false
  }
}

function backToCredentials() {
  step.value = 'credentials'
  preAuthToken.value = ''
  totpCode.value = ''
  error.value = ''
  success.value = ''
}

function goToForgot() {
  step.value = 'forgot'
  error.value = ''
  success.value = ''
}

function toggleMode() {
  step.value = step.value === 'register' ? 'credentials' : 'register'
  error.value = ''
}
</script>

<template>
  <div class="login-wrap">
    <div class="login-card">

      <!-- Brand -->
      <div class="brand">
        <ZoneProofLogo :size="40" subtitle="Email Security Posture" />
      </div>

      <!-- ── Step: credentials ─────────────────────────────────── -->
      <template v-if="step === 'credentials'">
        <h2>Sign in</h2>
        <p class="sub">Monitor DMARC · MTA-STS · Certificates</p>
        <form @submit.prevent="submitCredentials">
          <div class="field">
            <label>Email</label>
            <input v-model="email" type="email" placeholder="you@example.com" required autocomplete="email"/>
          </div>
          <div class="field">
            <div class="field-row">
              <label>Password</label>
              <button type="button" class="link forgot-link" @click="goToForgot">Forgot password?</button>
            </div>
            <input v-model="password" type="password" placeholder="••••••••" required autocomplete="current-password"/>
          </div>
          <div v-if="success" class="ok">{{ success }}</div>
          <div v-if="error" class="err">{{ error }}</div>
          <button type="submit" class="btn" :disabled="loading">
            {{ loading ? 'Signing in…' : 'Sign in' }}
          </button>
        </form>
        <div class="toggle">
          Don't have an account?
          <button class="link" @click="toggleMode">Sign up</button>
        </div>
      </template>

      <!-- ── Step: forgot password ─────────────────────────────── -->
      <template v-else-if="step === 'forgot'">
        <h2>Reset your password</h2>
        <p class="sub">Enter your account email and we'll send you a reset link.</p>
        <form @submit.prevent="submitForgot">
          <div class="field">
            <label>Email</label>
            <input v-model="email" type="email" placeholder="you@example.com" required autocomplete="email"/>
          </div>
          <div v-if="success" class="ok">{{ success }}</div>
          <div v-if="error" class="err">{{ error }}</div>
          <button type="submit" class="btn" :disabled="loading || !!success">
            {{ loading ? 'Sending…' : 'Send reset link' }}
          </button>
        </form>
        <div class="toggle">
          <button class="link" @click="backToCredentials">← Back to sign in</button>
        </div>
      </template>

      <!-- ── Step: reset password (arrived via email link) ────── -->
      <template v-else-if="step === 'reset'">
        <h2>Choose a new password</h2>
        <p class="sub">Enter a new password for <strong>{{ email || 'your account' }}</strong>.</p>
        <form @submit.prevent="submitReset">
          <div class="field">
            <label>New password</label>
            <input v-model="newPassword" type="password" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password"/>
          </div>
          <div v-if="error" class="err">{{ error }}</div>
          <button type="submit" class="btn" :disabled="loading">
            {{ loading ? 'Resetting…' : 'Reset password' }}
          </button>
        </form>
        <div class="toggle">
          <button class="link" @click="backToCredentials">← Back to sign in</button>
        </div>
      </template>

      <!-- ── Step: 2FA code ────────────────────────────────────── -->
      <template v-else-if="step === '2fa'">
        <div class="twofa-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h2>Two-factor authentication</h2>
        <p class="sub">Open your authenticator app and enter the 6-digit code for <strong>{{ email }}</strong>.</p>
        <form @submit.prevent="submitTotpCode">
          <div class="field" style="text-align:center">
            <input
              v-model="totpCode"
              class="code-input"
              maxlength="6"
              placeholder="000000"
              inputmode="numeric"
              pattern="[0-9 ]*"
              autofocus
              autocomplete="one-time-code"
            />
          </div>
          <div v-if="error" class="err">{{ error }}</div>
          <button type="submit" class="btn" :disabled="loading || totpCode.replace(/\s/g,'').length !== 6">
            {{ loading ? 'Verifying…' : 'Verify' }}
          </button>
        </form>
        <div class="toggle">
          <button class="link" @click="backToCredentials">← Back to sign in</button>
        </div>
      </template>

      <!-- ── Step: register ────────────────────────────────────── -->
      <template v-else>
        <h2>Create account</h2>
        <p class="sub">Start monitoring your email security posture</p>
        <form @submit.prevent="submitRegister">
          <div class="field">
            <label>Full name</label>
            <input v-model="fullName" type="text" placeholder="Jane Smith" autocomplete="name"/>
          </div>
          <div class="field">
            <label>Workspace name</label>
            <input v-model="workspaceName" type="text" placeholder="My Company"/>
          </div>
          <div class="field">
            <label>Email</label>
            <input v-model="email" type="email" placeholder="you@example.com" required autocomplete="email"/>
          </div>
          <div class="field">
            <label>Password</label>
            <input v-model="password" type="password" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password"/>
          </div>
          <label class="terms-row">
            <input v-model="termsAccepted" type="checkbox"/>
            <span>I agree to the <a href="/terms" target="_blank" rel="noopener">Terms of Service</a> and <a href="/privacy" target="_blank" rel="noopener">Privacy Policy</a></span>
          </label>
          <div v-if="error" class="err">{{ error }}</div>
          <button type="submit" class="btn" :disabled="loading || !termsAccepted">
            {{ loading ? 'Creating account…' : 'Create account' }}
          </button>
        </form>
        <div class="toggle">
          Already have an account?
          <button class="link" @click="toggleMode">Sign in</button>
        </div>
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

.twofa-icon {
  width:52px; height:52px; border-radius:16px; display:grid; place-items:center;
  background:rgba(46,230,197,.1); border:1px solid rgba(46,230,197,.2);
  margin-bottom:16px;
}
.twofa-icon svg { width:24px; height:24px; }

.field { margin-bottom:14px; }
label { font-family:var(--mono); font-size:10px; letter-spacing:.6px; color:var(--faint); text-transform:uppercase; display:block; margin-bottom:6px; }
input[type=email], input[type=password], input[type=text] {
  width:100%; background:rgba(255,255,255,.05); border:1px solid var(--line2);
  border-radius:11px; padding:12px 14px; color:var(--txt); font-family:var(--body);
  font-size:14px; outline:none; box-sizing:border-box; transition:border-color .15s;
}
input:focus { border-color:var(--indigo); }

.code-input {
  width:160px; font-family:var(--mono); font-size:28px; letter-spacing:6px;
  text-align:center; background:rgba(255,255,255,.05); border:1px solid var(--line2);
  border-radius:14px; padding:14px 10px; color:var(--txt); outline:none;
  box-sizing:border-box; transition:border-color .15s;
}
.code-input:focus { border-color:var(--accent); }

.err { color:var(--bad); font-size:12px; margin-bottom:10px; }
.ok { color:var(--teal); font-size:12px; margin-bottom:10px; line-height:1.5; }

.field-row { display:flex; align-items:baseline; justify-content:space-between; }
.forgot-link { margin:0 0 6px; font-size:11px; }

.btn { width:100%; background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:13px; font-family:var(--disp); font-weight:700; font-size:14px; cursor:pointer; margin-top:6px; transition:opacity .15s; }
.btn:disabled { opacity:.6; cursor:not-allowed; }
.btn:hover:not(:disabled) { opacity:.88; }

.toggle { margin-top:20px; text-align:center; font-size:13px; color:var(--muted); }
.link { background:none; border:none; color:var(--accent-soft); font-size:13px; cursor:pointer; font-family:var(--body); padding:0 0 0 4px; }
.link:hover { color:var(--txt); }

.terms-row { display:flex; align-items:flex-start; gap:8px; font-size:11.5px; color:var(--muted); line-height:1.5; margin:4px 0 14px; cursor:pointer; }
.terms-row input[type=checkbox] { margin-top:2px; flex:none; accent-color:var(--indigo); }
.terms-row a { color:var(--accent-soft); text-decoration:none; }
.terms-row a:hover { text-decoration:underline; }
</style>
