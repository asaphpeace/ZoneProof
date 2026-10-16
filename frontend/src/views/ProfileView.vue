<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, getToken, API_BASE } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const auth   = useAuthStore()
const ui     = useUiStore()
const router = useRouter()

// ── Profile data ──────────────────────────────────────────────────────────────
const me = ref<any>(null)
const loading = ref(true)

onMounted(async () => {
  try {
    me.value = await api.me()
  } finally {
    loading.value = false
  }
})

// ── Profile edit ──────────────────────────────────────────────────────────────
const editFullName      = ref('')
const editWorkspaceName = ref('')
const profileSaving     = ref(false)

function startEditProfile() {
  editFullName.value      = me.value?.full_name ?? ''
  editWorkspaceName.value = me.value?.workspace_name ?? ''
}

async function saveProfile() {
  profileSaving.value = true
  try {
    const patch: any = {}
    if (editFullName.value !== me.value.full_name)           patch.full_name      = editFullName.value
    if (editWorkspaceName.value !== me.value.workspace_name) patch.workspace_name = editWorkspaceName.value
    if (!Object.keys(patch).length) { profileEditing.value = false; return }
    me.value = await api.updateMe(patch)
    if (patch.full_name)      auth.fullName      = patch.full_name
    if (patch.workspace_name) auth.workspaceName = patch.workspace_name
    profileEditing.value = false
    ui.toast('Profile updated')
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to update profile', 'error')
  } finally {
    profileSaving.value = false
  }
}

const profileEditing = ref(false)

// ── Change password ───────────────────────────────────────────────────────────
const currentPw  = ref('')
const newPw      = ref('')
const confirmPw  = ref('')
const pwSaving   = ref(false)
const pwError    = ref('')
const showCurr   = ref(false)
const showNew    = ref(false)
const showConf   = ref(false)

function pwStrength(pw: string): { score: number; label: string; color: string } {
  if (!pw) return { score: 0, label: '', color: '' }
  let score = 0
  if (pw.length >= 8)  score++
  if (pw.length >= 12) score++
  if (/[A-Z]/.test(pw)) score++
  if (/[0-9]/.test(pw)) score++
  if (/[^A-Za-z0-9]/.test(pw)) score++
  if (score <= 1) return { score, label: 'Weak',   color: '#ff4d6d' }
  if (score <= 3) return { score, label: 'Fair',   color: '#f5c542' }
  return              { score, label: 'Strong', color: '#34e0a1' }
}

async function changePw() {
  pwError.value = ''
  if (newPw.value.length < 8)               { pwError.value = 'Password must be at least 8 characters'; return }
  if (newPw.value !== confirmPw.value)       { pwError.value = 'Passwords do not match'; return }
  if (newPw.value === currentPw.value)       { pwError.value = 'New password must differ from current'; return }
  pwSaving.value = true
  try {
    await api.changePassword(currentPw.value, newPw.value)
    // The backend bumps token_version on password change, which invalidates
    // this very session's token immediately (see User.token_version). The
    // current page would just 401 on its next API call, so log out cleanly
    // and send the user to sign in again with the new password — rather
    // than toast a success message that masks an imminent silent failure.
    // AppToast lives inside AppShell, which unmounts on this redirect anyway,
    // so the message has to travel via the login route's query instead.
    auth.logout()
    router.push({ name: 'login', query: { notice: 'password-changed' } })
  } catch (e: any) {
    pwError.value = e.message ?? 'Failed to update password'
  } finally {
    pwSaving.value = false
  }
}

// ── 2FA ───────────────────────────────────────────────────────────────────────
const totpSetup     = ref<any>(null)   // {secret, otpauth_url, qr_data_url}
const totpCode      = ref('')
const totpSaving    = ref(false)
const totpError     = ref('')
const disableCode   = ref('')
const showDisable   = ref(false)
const disableSaving = ref(false)

async function start2fa() {
  totpError.value = ''
  totpSaving.value = true
  try {
    totpSetup.value = await api.enable2fa()
    totpCode.value  = ''
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to start 2FA setup', 'error')
  } finally {
    totpSaving.value = false
  }
}

async function confirm2fa() {
  const code = totpCode.value.replace(/\s/g, '')
  if (code.length !== 6) { totpError.value = 'Enter the 6-digit code from your app'; return }
  totpError.value  = ''
  totpSaving.value = true
  try {
    await api.verify2fa(code)
    me.value.totp_enabled = true
    totpSetup.value = null
    totpCode.value  = ''
    ui.toast('Two-factor authentication enabled')
  } catch (e: any) {
    totpError.value = e.message ?? 'Invalid code'
  } finally {
    totpSaving.value = false
  }
}

async function disable2fa() {
  const code = disableCode.value.replace(/\s/g, '')
  if (code.length !== 6) return
  disableSaving.value = true
  try {
    await api.disable2fa(code)
    me.value.totp_enabled = false
    showDisable.value = false
    disableCode.value = ''
    ui.toast('Two-factor authentication disabled')
  } catch (e: any) {
    ui.toast(e.message ?? 'Invalid code', 'error')
  } finally {
    disableSaving.value = false
  }
}

// ── Data export ────────────────────────────────────────────────────────────────
const exporting = ref(false)
async function exportData() {
  exporting.value = true
  try {
    const res = await fetch(`${API_BASE}/auth/me/export`, { headers: { Authorization: `Bearer ${getToken()}` } })
    if (!res.ok) throw new Error('Export failed')
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `zoneproof-data-export-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to export data', 'error')
  } finally {
    exporting.value = false
  }
}

// ── Delete account ────────────────────────────────────────────────────────────
const showDelete   = ref(false)
const deleteConfirm = ref('')
const deleting     = ref(false)

async function deleteAccount() {
  if (deleteConfirm.value !== 'DELETE') return
  deleting.value = true
  try {
    await api.deleteAccount()
    auth.logout()
    router.push({ name: 'login' })
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to delete account', 'error')
    deleting.value = false
  }
}

function logout() {
  auth.logout()
  router.push({ name: 'login' })
}

const strength = () => pwStrength(newPw.value)
</script>

<template>
  <div>
    <div class="crumb">09 / Settings</div>
    <h1>Account &amp; Settings</h1>

    <div v-if="loading" class="r-loading">
      <div class="spinner"/><p>Loading…</p>
    </div>

    <template v-else-if="me">

      <!-- ── Row 1: Profile + Password ───────────────────────────────────── -->
      <div class="row2">

        <!-- Profile card -->
        <div class="card">
          <div class="ct">
            <h3 aria-level="2">Profile</h3>
            <button v-if="!profileEditing" class="ghost-btn" @click="profileEditing = true; startEditProfile()">Edit</button>
            <button v-else class="ghost-btn" @click="profileEditing = false">Cancel</button>
          </div>

          <div class="avatar-row">
            <div class="avatar">{{ me.full_name?.[0]?.toUpperCase() || me.email[0].toUpperCase() }}</div>
            <div>
              <div class="av-name">{{ me.full_name || '—' }}</div>
              <div class="av-email">{{ me.email }}</div>
              <div class="av-role">{{ me.role }}</div>
            </div>
          </div>

          <template v-if="!profileEditing">
            <div class="field-group" style="margin-top:18px">
              <div class="field-row">
                <span class="fl">Full name</span>
                <span class="fv">{{ me.full_name || '—' }}</span>
              </div>
              <div class="field-row">
                <span class="fl">Workspace</span>
                <span class="fv">{{ me.workspace_name }}</span>
              </div>
              <div class="field-row">
                <span class="fl">Plan</span>
                <span class="fv">
                  <span class="plan-chip" @click="router.push({ name: 'billing' })" tabindex="0" role="link" @keydown.enter.prevent="router.push({ name: 'billing' })" @keydown.space.prevent="router.push({ name: 'billing' })">{{ me.plan }}</span>
                </span>
              </div>
              <div class="field-row">
                <span class="fl">Member since</span>
                <span class="fv fmono">{{ new Date(me.created_at).toLocaleDateString('en-ZA', { year:'numeric', month:'short', day:'numeric' }) }}</span>
              </div>
              <div class="field-row">
                <span class="fl">2FA</span>
                <span class="fv">
                  <span :class="['status-chip', me.totp_enabled ? 'chip-good' : 'chip-off']">
                    {{ me.totp_enabled ? 'Enabled' : 'Not enabled' }}
                  </span>
                </span>
              </div>
            </div>
          </template>

          <template v-else>
            <div style="margin-top:18px">
              <div class="field">
                <label>Full name</label>
                <input v-model="editFullName" type="text" placeholder="Your name"/>
              </div>
              <div v-if="me.role === 'admin'" class="field">
                <label>Workspace name</label>
                <input v-model="editWorkspaceName" type="text" placeholder="Company or team name"/>
              </div>
              <button class="btn" :disabled="profileSaving" @click="saveProfile">
                <span v-if="profileSaving" class="btn-spinner"/>
                <span v-else>Save changes</span>
              </button>
            </div>
          </template>
        </div>

        <!-- Change password -->
        <div class="card">
          <div class="ct"><h3 aria-level="2">Change password</h3></div>
          <form @submit.prevent="changePw">
            <div class="field">
              <label>Current password</label>
              <div class="pw-wrap">
                <input v-model="currentPw" :type="showCurr ? 'text' : 'password'" placeholder="••••••••" required autocomplete="current-password"/>
                <button type="button" class="eye-btn" :aria-label="showCurr ? 'Hide current password' : 'Show current password'" :aria-pressed="showCurr" @click="showCurr = !showCurr">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <template v-if="showCurr">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </template>
                    <template v-else>
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                    </template>
                  </svg>
                </button>
              </div>
            </div>
            <div class="field">
              <label>New password</label>
              <div class="pw-wrap">
                <input v-model="newPw" :type="showNew ? 'text' : 'password'" placeholder="Min 8 characters" required autocomplete="new-password"/>
                <button type="button" class="eye-btn" :aria-label="showNew ? 'Hide new password' : 'Show new password'" :aria-pressed="showNew" @click="showNew = !showNew">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <template v-if="showNew">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </template>
                    <template v-else>
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                    </template>
                  </svg>
                </button>
              </div>
              <!-- Strength meter -->
              <div v-if="newPw" class="strength-row">
                <div class="strength-bar">
                  <div
                    v-for="i in 5" :key="i"
                    class="strength-seg"
                    :style="i <= strength().score ? `background:${strength().color}` : ''"
                  />
                </div>
                <span class="strength-label" :style="`color:${strength().color}`">{{ strength().label }}</span>
              </div>
            </div>
            <div class="field">
              <label>Confirm new password</label>
              <div class="pw-wrap">
                <input v-model="confirmPw" :type="showConf ? 'text' : 'password'" placeholder="••••••••" required autocomplete="new-password"/>
                <button type="button" class="eye-btn" :aria-label="showConf ? 'Hide confirmation password' : 'Show confirmation password'" :aria-pressed="showConf" @click="showConf = !showConf">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                  </svg>
                </button>
              </div>
              <div v-if="confirmPw && confirmPw !== newPw" class="match-err">Passwords do not match</div>
            </div>
            <div v-if="pwError" class="err">{{ pwError }}</div>
            <button class="btn" type="submit" :disabled="pwSaving || !currentPw || !newPw || newPw !== confirmPw">
              <span v-if="pwSaving" class="btn-spinner"/>
              <span v-else>Update password</span>
            </button>
          </form>
        </div>
      </div>

      <!-- ── 2FA card ─────────────────────────────────────────────────────── -->
      <div class="card">
        <div class="ct">
          <h3 aria-level="2">Two-factor authentication</h3>
          <span :class="['status-chip', me.totp_enabled ? 'chip-good' : 'chip-off']">
            {{ me.totp_enabled ? 'Enabled' : 'Disabled' }}
          </span>
        </div>

        <p class="section-desc">
          Protect your account with a time-based one-time password (TOTP) from an app like Google Authenticator, Authy, or 1Password.
        </p>

        <!-- Setup flow -->
        <template v-if="!me.totp_enabled && !totpSetup">
          <button class="btn" :disabled="totpSaving" @click="start2fa">
            <span v-if="totpSaving" class="btn-spinner"/>
            <span v-else>Enable 2FA</span>
          </button>
        </template>

        <template v-else-if="totpSetup">
          <div class="totp-setup">
            <div class="totp-qr">
              <img :src="totpSetup.qr_data_url" alt="QR code" width="160" height="160"/>
            </div>
            <div class="totp-right">
              <div class="totp-step">1. Scan the QR code with your authenticator app</div>
              <div class="totp-step">2. Or enter this key manually:</div>
              <div class="totp-secret">{{ totpSetup.secret }}</div>
              <div class="totp-step" style="margin-top:14px">3. Enter the 6-digit code to confirm</div>
              <div class="totp-code-row">
                <input
                  v-model="totpCode"
                  class="code-input"
                  maxlength="6"
                  placeholder="000000"
                  inputmode="numeric"
                  @keyup.enter="confirm2fa"
                />
                <button class="btn" :disabled="totpSaving || totpCode.replace(/\s/g,'').length !== 6" @click="confirm2fa">
                  <span v-if="totpSaving" class="btn-spinner"/>
                  <span v-else>Verify &amp; enable</span>
                </button>
              </div>
              <div v-if="totpError" class="err" style="margin-top:8px">{{ totpError }}</div>
              <button class="ghost-btn" style="margin-top:10px" @click="totpSetup = null">Cancel</button>
            </div>
          </div>
        </template>

        <!-- Disable flow -->
        <template v-else-if="me.totp_enabled">
          <div v-if="!showDisable">
            <button class="btn btn-danger-ghost" @click="showDisable = true">Disable 2FA</button>
          </div>
          <div v-else class="disable-2fa-row">
            <p class="warn-note">Enter a code from your authenticator app to confirm disabling 2FA.</p>
            <div class="totp-code-row">
              <input
                v-model="disableCode"
                class="code-input"
                maxlength="6"
                placeholder="000000"
                inputmode="numeric"
                @keyup.enter="disable2fa"
              />
              <button class="btn btn-danger" :disabled="disableSaving || disableCode.length !== 6" @click="disable2fa">
                <span v-if="disableSaving" class="btn-spinner"/>
                <span v-else>Confirm disable</span>
              </button>
              <button class="ghost-btn" @click="showDisable = false; disableCode = ''">Cancel</button>
            </div>
          </div>
        </template>
      </div>

      <!-- ── Reporting config (read-only) ────────────────────────────────── -->
      <div class="card">
        <div class="ct">
          <h3 aria-level="2">Reporting configuration</h3>
          <span class="sectag">read-only</span>
        </div>
        <p class="section-desc">
          Each domain receives a unique reporting address routed through mailsentry.co.za.
          These settings are managed by ZoneProof.
        </p>
        <div class="field-group">
          <div class="field-row"><span class="fl">Reporting domain</span><span class="fv fmono">mailsentry.co.za</span></div>
          <div class="field-row"><span class="fl">IMAP polling</span><span class="fv">Every 5 minutes</span></div>
          <div class="field-row"><span class="fl">DNS polling</span><span class="fv">Every 60 minutes</span></div>
          <div class="field-row"><span class="fl">Cert probing</span><span class="fv">Every 24 hours</span></div>
          <div class="field-row"><span class="fl">Cert alerts</span><span class="fv">30 day &amp; 7 day thresholds</span></div>
        </div>
      </div>

      <!-- ── Danger zone ──────────────────────────────────────────────────── -->
      <div class="card">
        <div class="ct"><h3 aria-level="2">Your data</h3></div>
        <div class="danger-row">
          <div>
            <div class="danger-label">Export my data</div>
            <div class="danger-sub">Download a JSON file with your account, workspace, team, and domain monitoring summary.</div>
          </div>
          <button class="btn" @click="exportData" :disabled="exporting">
            {{ exporting ? 'Preparing…' : 'Export data' }}
          </button>
        </div>
      </div>

      <div class="card danger-card">
        <div class="ct"><h3 aria-level="2">Danger zone</h3></div>

        <!-- Sign out -->
        <div class="danger-row">
          <div>
            <div class="danger-label">Sign out</div>
            <div class="danger-sub">Ends your current session on this device.</div>
          </div>
          <button class="btn btn-danger-ghost" @click="logout">Sign out</button>
        </div>

        <!-- Delete account / workspace -->
        <div class="danger-row" style="margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,77,109,.12)">
          <div>
            <div class="danger-label">
              {{ me.role === 'admin' ? 'Delete workspace' : 'Remove my account' }}
            </div>
            <div class="danger-sub">
              <template v-if="me.role === 'admin'">
                Permanently deletes this workspace, all domains, all users, and all data. Cannot be undone.
              </template>
              <template v-else>
                Removes your account from this workspace. Domains and other users are unaffected.
              </template>
            </div>
          </div>
          <button class="btn btn-danger" @click="showDelete = true">
            {{ me.role === 'admin' ? 'Delete workspace' : 'Remove account' }}
          </button>
        </div>
      </div>

    </template>

    <!-- ── Delete confirmation modal ────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="showDelete" class="modal-backdrop" @click.self="showDelete = false; deleteConfirm = ''">
        <div class="modal">
          <div class="modal-head">
            <h3 aria-level="2">{{ me?.role === 'admin' ? 'Delete workspace' : 'Remove account' }}</h3>
            <button class="modal-close" @click="showDelete = false; deleteConfirm = ''">✕</button>
          </div>
          <div class="modal-body">
            <div class="delete-warn">
              <svg viewBox="0 0 24 24" fill="none" stroke="#ff4d6d" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <p v-if="me?.role === 'admin'">
                This will permanently delete <strong>{{ me.workspace_name }}</strong> and all its domains, reports, team members, and data. This action cannot be undone.
              </p>
              <p v-else>
                This will remove your account from <strong>{{ me.workspace_name }}</strong>. You will immediately lose access.
              </p>
            </div>
            <label class="field-label" style="margin-top:16px">
              Type <strong style="color:var(--bad)">DELETE</strong> to confirm
            </label>
            <input v-model="deleteConfirm" class="field-input" placeholder="DELETE" autocomplete="off"/>
          </div>
          <div class="modal-foot">
            <button class="btn-cancel" @click="showDelete = false; deleteConfirm = ''">Cancel</button>
            <button
              class="btn btn-danger"
              :disabled="deleteConfirm !== 'DELETE' || deleting"
              @click="deleteAccount"
            >
              <span v-if="deleting" class="btn-spinner"/>
              <span v-else>{{ me?.role === 'admin' ? 'Delete workspace' : 'Remove account' }}</span>
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.crumb { font-family:var(--mono); font-size:10px; color:var(--faint); letter-spacing:.5px; margin-bottom:8px; }
h1 { font-family:var(--disp); font-weight:900; font-size:22px; margin-bottom:24px; }

.r-loading { display:flex; flex-direction:column; align-items:center; gap:12px; padding:60px; color:var(--muted); }
.spinner { width:28px; height:28px; border:3px solid rgba(255,255,255,.1); border-top-color:var(--indigo); border-radius:50%; animation:spin .8s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }

.row2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
@media (max-width:800px) { .row2 { grid-template-columns:1fr; } }

.card {
  background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07);
  border-radius:18px; padding:22px 24px; margin-bottom:16px;
}
.ct { display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }
.ct h3 { font-family:var(--disp); font-weight:700; font-size:15px; margin:0; }
.sectag { font-family:var(--mono); font-size:9px; letter-spacing:1px; text-transform:uppercase; color:var(--teal); }

/* Avatar */
.avatar-row { display:flex; align-items:center; gap:14px; }
.avatar { width:52px; height:52px; border-radius:16px; background:linear-gradient(135deg,#5b5cf0,#2ee6c5); display:grid; place-items:center; font-family:var(--disp); font-weight:800; font-size:22px; flex:none; color:#fff; }
.av-name  { font-family:var(--disp); font-weight:700; font-size:15px; }
.av-email { font-size:11.5px; color:var(--muted); margin-top:2px; font-family:var(--mono); }
.av-role  { font-family:var(--mono); font-size:9px; letter-spacing:.8px; text-transform:uppercase; color:var(--teal); margin-top:4px; }

/* Field rows */
.field-group { display:flex; flex-direction:column; gap:10px; }
.field-row { display:flex; align-items:center; gap:12px; }
.fl { font-family:var(--mono); font-size:10px; color:var(--faint); text-transform:uppercase; letter-spacing:.5px; min-width:120px; }
.fv { font-size:12.5px; color:var(--txt); }
.fmono { font-family:var(--mono); font-size:11px; color:var(--teal); }

/* Status chips */
.status-chip { font-family:var(--mono); font-size:9px; font-weight:700; letter-spacing:.4px; text-transform:uppercase; padding:2px 8px; border-radius:20px; }
.chip-good { background:rgba(52,224,161,.12); color:#34e0a1; }
.chip-off  { background:rgba(255,255,255,.07); color:var(--faint); }
.plan-chip { font-family:var(--mono); font-size:9.5px; font-weight:700; text-transform:uppercase; background:rgba(91,92,240,.15); color:var(--indigo); padding:2px 9px; border-radius:20px; cursor:pointer; }
.plan-chip:hover { background:rgba(91,92,240,.25); }

/* Form fields */
.field { margin-bottom:14px; }
label { font-family:var(--mono); font-size:9.5px; letter-spacing:.5px; color:var(--faint); text-transform:uppercase; display:block; margin-bottom:6px; }
input[type=text], input[type=email], input[type=password] {
  width:100%; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.09);
  border-radius:11px; padding:10px 13px; color:var(--txt); font-family:var(--body);
  font-size:13px; outline:none; box-sizing:border-box; transition:border-color .15s;
}
input:focus { border-color:rgba(91,92,240,.5); }

/* Password show/hide */
.pw-wrap { position:relative; }
.pw-wrap input { padding-right:42px; }
.eye-btn { position:absolute; right:12px; top:50%; transform:translateY(-50%); background:none; border:none; color:var(--faint); cursor:pointer; padding:4px; display:grid; place-items:center; }
.eye-btn:hover { color:var(--txt); }
.eye-btn svg { width:15px; height:15px; }

/* Strength meter */
.strength-row { display:flex; align-items:center; gap:8px; margin-top:6px; }
.strength-bar { display:flex; gap:3px; flex:1; }
.strength-seg { height:3px; flex:1; background:rgba(255,255,255,.08); border-radius:3px; transition:background .3s; }
.strength-label { font-family:var(--mono); font-size:9px; font-weight:700; letter-spacing:.4px; text-transform:uppercase; min-width:44px; text-align:right; }
.match-err { font-family:var(--mono); font-size:9.5px; color:#ff4d6d; margin-top:5px; }

/* Buttons */
.btn {
  display:inline-flex; align-items:center; justify-content:center; gap:7px;
  background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none;
  border-radius:12px; padding:10px 20px; font-family:var(--disp); font-weight:700;
  font-size:13px; cursor:pointer; transition:opacity .15s;
}
.btn:disabled { opacity:.55; cursor:not-allowed; }
.btn:hover:not(:disabled) { opacity:.88; }
.btn-danger { background:#d7264b; }
.btn-danger-ghost { background:none; border:1px solid rgba(255,77,109,.4); color:#ff4d6d; }
.btn-danger-ghost:hover { background:rgba(255,77,109,.1); }
.btn-spinner { width:13px; height:13px; border:2px solid rgba(255,255,255,.3); border-top-color:#fff; border-radius:50%; animation:spin .7s linear infinite; }

.ghost-btn { background:none; border:1px solid rgba(255,255,255,.1); color:var(--muted); padding:6px 13px; border-radius:10px; font-family:var(--disp); font-weight:600; font-size:11.5px; cursor:pointer; transition:.15s; }
.ghost-btn:hover { border-color:rgba(255,255,255,.2); color:var(--txt); }

/* 2FA setup */
.section-desc { font-size:12.5px; color:var(--muted); margin:0 0 16px; line-height:1.55; }
.totp-setup { display:flex; gap:20px; flex-wrap:wrap; }
.totp-qr img { border-radius:12px; border:2px solid rgba(255,255,255,.08); display:block; }
.totp-right { flex:1; min-width:220px; }
.totp-step { font-size:12px; color:var(--muted); margin-bottom:6px; }
.totp-secret { font-family:var(--mono); font-size:12px; color:var(--teal); background:rgba(46,230,197,.08); border:1px solid rgba(46,230,197,.2); border-radius:8px; padding:7px 11px; letter-spacing:1.5px; word-break:break-all; margin-bottom:4px; }
.totp-code-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:6px; }
.code-input { width:110px; font-family:var(--mono); font-size:20px; letter-spacing:4px; text-align:center; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.1); border-radius:11px; padding:10px; color:var(--txt); outline:none; }
.code-input:focus { border-color:rgba(91,92,240,.5); }
.warn-note { font-size:12px; color:var(--warn); background:rgba(245,197,66,.07); border:1px solid rgba(245,197,66,.2); border-radius:8px; padding:9px 12px; margin:0 0 10px; }
.disable-2fa-row { margin-top:12px; }

.err { color:#ff4d6d; font-family:var(--mono); font-size:10.5px; margin-bottom:10px; }

/* Danger zone */
.danger-card { border-color:rgba(255,77,109,.18); }
.danger-row { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:14px; }
.danger-label { font-size:13.5px; font-weight:600; color:var(--txt); margin-bottom:3px; }
.danger-sub { font-size:12px; color:var(--muted); max-width:420px; }

/* Delete modal */
.modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.65); backdrop-filter:blur(4px); display:grid; place-items:center; z-index:900; }
.modal { background:#10111e; border:1px solid rgba(255,77,109,.3); border-radius:20px; width:440px; max-width:calc(100vw - 32px); box-shadow:0 24px 80px rgba(0,0,0,.5); }
.modal-head { display:flex; align-items:center; justify-content:space-between; padding:20px 22px 0; }
.modal-head h3 { font-family:var(--disp); font-size:16px; font-weight:800; color:#ff4d6d; margin:0; }
.modal-close { background:none; border:none; color:var(--faint); font-size:16px; cursor:pointer; padding:4px 6px; }
.modal-body { padding:18px 22px; }
.modal-foot { display:flex; justify-content:flex-end; gap:10px; padding:0 22px 20px; }
.btn-cancel { background:none; border:1px solid rgba(255,255,255,.1); color:var(--muted); padding:8px 16px; border-radius:10px; font-family:var(--disp); font-weight:700; font-size:12px; cursor:pointer; }
.btn-cancel:hover { border-color:rgba(255,255,255,.2); color:var(--txt); }

.delete-warn { display:flex; gap:12px; align-items:flex-start; }
.delete-warn svg { width:28px; height:28px; flex:none; margin-top:2px; }
.delete-warn p { font-size:13px; color:var(--muted); line-height:1.55; margin:0; }
.delete-warn strong { color:var(--txt); }
.field-label { display:block; font-family:var(--mono); font-size:9.5px; color:var(--faint); letter-spacing:.5px; text-transform:uppercase; margin-bottom:6px; }
.field-input { width:100%; background:rgba(255,255,255,.04); border:1px solid rgba(255,77,109,.2); border-radius:10px; color:var(--txt); font-size:13px; padding:9px 12px; outline:none; box-sizing:border-box; font-family:var(--mono); letter-spacing:1.5px; }
.field-input:focus { border-color:rgba(255,77,109,.5); }
</style>
