<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const router = useRouter()
const auth   = useAuthStore()
const ui     = useUiStore()

const clients  = ref<any[]>([])
const loading  = ref(true)
const showNew  = ref(false)
const deleting = ref<string | null>(null)

// New client form
const newName    = ref('')
const newEmail   = ref('')
const newBrand   = ref('')
const creating   = ref(false)

// Invite modal
const inviteClient  = ref<any | null>(null)
const inviteEmail   = ref('')
const inviteRole    = ref('admin')
const inviteMode    = ref<'invite' | 'direct'>('invite')
const invitePassword = ref('')
const inviteFullName = ref('')
const inviting       = ref(false)
const inviteResult   = ref<any | null>(null)

const isMsp = computed(() => ['msp', 'enterprise'].includes(auth.plan))

onMounted(loadClients)

async function loadClients() {
  loading.value = true
  try {
    clients.value = await api.mspClients()
  } catch {
    /* 403 if not MSP — handled via isMsp gate in template */
  } finally {
    loading.value = false
  }
}

async function createClient() {
  if (!newName.value.trim()) return
  creating.value = true
  try {
    const client = await api.mspCreateClient({
      name: newName.value.trim(),
      billing_email: newEmail.value || undefined,
      brand_name: newBrand.value || undefined,
    })
    clients.value = [...clients.value, client]
    showNew.value = false
    newName.value = newEmail.value = newBrand.value = ''
    ui.toast(`Client "${client.name}" created`)
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to create client', 'error')
  } finally {
    creating.value = false
  }
}

async function removeClient(id: string, name: string) {
  if (!confirm(`Remove "${name}" and all their data? This cannot be undone.`)) return
  deleting.value = id
  try {
    await api.mspDeleteClient(id)
    clients.value = clients.value.filter(c => c.id !== id)
    ui.toast(`Client "${name}" removed`)
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to remove client', 'error')
  } finally {
    deleting.value = null
  }
}

function openInvite(client: any) {
  inviteClient.value = client
  inviteEmail.value = inviteFullName.value = invitePassword.value = ''
  inviteRole.value = 'admin'
  inviteMode.value = 'invite'
  inviteResult.value = null
}

async function sendInvite() {
  if (!inviteEmail.value || !inviteFullName.value) return
  inviting.value = true
  try {
    const result = await api.mspInviteToClient(inviteClient.value.id, {
      email: inviteEmail.value,
      full_name: inviteFullName.value,
      role: inviteRole.value,
      send_invite: inviteMode.value === 'invite',
      password: inviteMode.value === 'direct' ? invitePassword.value : undefined,
    })
    inviteResult.value = result
    ui.toast(inviteMode.value === 'invite' ? 'Invite created' : 'Account created')
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to send invite', 'error')
  } finally {
    inviting.value = false
  }
}

function gradeColor(color: string) { return color }
function planLabel(p: string) { return { free: 'Free', starter: 'Starter', pro: 'Pro', msp: 'MSP', enterprise: 'Ent' }[p] ?? p }
</script>

<template>
  <div>
    <div class="crumb">10 / MSP</div>
    <div class="page-head">
      <div>
        <h1>MSP Clients</h1>
        <p class="sub">Manage all client tenants from one place.</p>
      </div>
      <RouterLink v-if="isMsp" :to="{ name: 'msp-brand-guard' }" class="btn-new" style="text-decoration:none">Brand Guard roll-up</RouterLink>
      <button v-if="isMsp" class="btn-new" @click="showNew = true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M12 5v14M5 12h14"/>
        </svg>
        Add client
      </button>
    </div>

    <!-- Gate: not MSP plan -->
    <div v-if="!isMsp" class="gate-banner">
      <div class="gate-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <div>
        <div class="gate-title">MSP plan required</div>
        <div class="gate-sub">Sub-tenant management is available on the MSP and Enterprise plans.</div>
      </div>
      <button class="btn-upgrade" @click="router.push({ name: 'billing' })">View plans</button>
    </div>

    <template v-else>
      <!-- Loading -->
      <div v-if="loading" class="r-loading">
        <div class="spinner"/><p>Loading clients…</p>
      </div>

      <!-- Empty state -->
      <div v-else-if="clients.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
        </div>
        <div class="empty-title">No clients yet</div>
        <div class="empty-sub">Create your first client tenant to start managing their email security posture.</div>
        <button class="btn-upgrade" @click="showNew = true">Add first client</button>
      </div>

      <!-- Client grid -->
      <div v-else class="clients-grid">
        <div v-for="c in clients" :key="c.id" class="client-card">
          <div class="cc-head">
            <div>
              <div class="cc-name">{{ c.name }}</div>
              <div class="cc-meta">
                <span class="plan-chip">{{ planLabel(c.plan) }}</span>
                <span class="meta-sep">·</span>
                <span class="cc-domains">{{ c.domain_count }} domain{{ c.domain_count !== 1 ? 's' : '' }}</span>
              </div>
            </div>
            <div class="grade-circle" :style="`border-color:${c.sentinel_grade_color}`">
              <div class="grade-letter" :style="`color:${c.sentinel_grade_color}`">{{ c.sentinel_grade }}</div>
              <div class="grade-score">{{ c.sentinel_score }}</div>
            </div>
          </div>

          <!-- Status flags -->
          <div class="cc-flags">
            <div class="flag" :class="c.dmarc_reject_count > 0 ? 'flag-good' : 'flag-warn'">
              <span class="flag-icon">{{ c.dmarc_reject_count > 0 ? '✓' : '◑' }}</span>
              {{ c.dmarc_reject_count }}/{{ c.domain_count }} on reject
            </div>
            <div v-if="c.cert_alerts > 0" class="flag flag-bad">
              <span class="flag-icon">✗</span>
              {{ c.cert_alerts }} cert alert{{ c.cert_alerts !== 1 ? 's' : '' }}
            </div>
            <div v-if="c.dmarc_none_count > 0" class="flag flag-warn">
              <span class="flag-icon">◑</span>
              {{ c.dmarc_none_count }} no DMARC
            </div>
          </div>

          <!-- Actions -->
          <div class="cc-actions">
            <button class="act-btn act-btn-primary" @click="openInvite(c)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
                <line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/>
              </svg>
              Invite user
            </button>
            <button
              class="act-btn act-btn-danger"
              :disabled="deleting === c.id"
              @click="removeClient(c.id, c.name)"
            >
              <span v-if="deleting === c.id" class="mini-spinner"/>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
                <path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>
              </svg>
            </button>
          </div>
        </div>
      </div>
    </template>

    <!-- New client modal -->
    <Teleport to="body">
      <div v-if="showNew" class="modal-backdrop" @click.self="showNew = false">
        <div class="modal">
          <div class="modal-head">
            <h3>Add client tenant</h3>
            <button class="modal-close" @click="showNew = false">✕</button>
          </div>
          <div class="modal-body">
            <label class="field-label">Client / company name *</label>
            <input v-model="newName" class="field-input" placeholder="Acme Corp" @keyup.enter="createClient"/>
            <label class="field-label" style="margin-top:14px">Billing email (optional)</label>
            <input v-model="newEmail" class="field-input" type="email" placeholder="billing@client.com"/>
            <label class="field-label" style="margin-top:14px">Brand name for white-label reports</label>
            <input v-model="newBrand" class="field-input" placeholder="Acme IT Services"/>
          </div>
          <div class="modal-foot">
            <button class="btn-cancel" @click="showNew = false">Cancel</button>
            <button class="btn-upgrade" :disabled="!newName.trim() || creating" @click="createClient">
              <span v-if="creating" class="mini-spinner white"/>
              <span v-else>Create client</span>
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Invite modal -->
    <Teleport to="body">
      <div v-if="inviteClient" class="modal-backdrop" @click.self="inviteClient = null">
        <div class="modal">
          <div class="modal-head">
            <h3>Add user to {{ inviteClient.name }}</h3>
            <button class="modal-close" @click="inviteClient = null">✕</button>
          </div>

          <template v-if="!inviteResult">
            <div class="modal-body">
              <!-- Mode toggle -->
              <div class="toggle-row">
                <button :class="['toggle-opt', inviteMode === 'invite' ? 'tog-active' : '']" @click="inviteMode = 'invite'">Send invite link</button>
                <button :class="['toggle-opt', inviteMode === 'direct' ? 'tog-active' : '']" @click="inviteMode = 'direct'">Create account now</button>
              </div>

              <label class="field-label" style="margin-top:14px">Full name *</label>
              <input v-model="inviteFullName" class="field-input" placeholder="Jane Smith"/>
              <label class="field-label" style="margin-top:14px">Email *</label>
              <input v-model="inviteEmail" class="field-input" type="email" placeholder="jane@client.com"/>
              <label class="field-label" style="margin-top:14px">Role</label>
              <select v-model="inviteRole" class="field-input">
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
              <template v-if="inviteMode === 'direct'">
                <label class="field-label" style="margin-top:14px">Temporary password *</label>
                <input v-model="invitePassword" class="field-input" type="password" placeholder="Min 8 characters"/>
              </template>
            </div>
            <div class="modal-foot">
              <button class="btn-cancel" @click="inviteClient = null">Cancel</button>
              <button
                class="btn-upgrade"
                :disabled="!inviteEmail || !inviteFullName || (inviteMode === 'direct' && !invitePassword) || inviting"
                @click="sendInvite"
              >
                <span v-if="inviting" class="mini-spinner white"/>
                <span v-else>{{ inviteMode === 'invite' ? 'Send invite' : 'Create account' }}</span>
              </button>
            </div>
          </template>

          <template v-else>
            <div class="modal-body">
              <div class="result-success">
                <svg viewBox="0 0 24 24" fill="none" stroke="#34e0a1" stroke-width="2.2">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <template v-if="inviteResult.mode === 'invite'">
                  <p>Invite link created for <strong>{{ inviteResult.email }}</strong></p>
                  <div class="invite-url-box">{{ inviteResult.invite_url }}</div>
                  <p class="hint">Share this link with the user — it expires in 7 days.</p>
                </template>
                <template v-else>
                  <p>Account created for <strong>{{ inviteResult.email }}</strong></p>
                  <p class="hint">The user can now log in with the temporary password you set.</p>
                </template>
              </div>
            </div>
            <div class="modal-foot">
              <button class="btn-upgrade" @click="inviteClient = null; inviteResult = null">Done</button>
            </div>
          </template>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.crumb { font-family:var(--mono); font-size:10px; color:var(--faint); letter-spacing:.5px; margin-bottom:8px; }
h1 { font-family:var(--disp); font-size:22px; font-weight:900; color:var(--txt); margin:0; }
.sub { font-size:12px; color:var(--muted); margin:4px 0 0; }

.page-head { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:24px; }
.btn-new {
  display:flex; align-items:center; gap:6px; padding:9px 16px; border-radius:12px;
  background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none;
  font-family:var(--disp); font-weight:700; font-size:12.5px; cursor:pointer;
}
.btn-new svg { width:14px; height:14px; }
.btn-new:hover { opacity:.88; }

/* Gate */
.gate-banner {
  display:flex; align-items:center; gap:16px; padding:20px 24px;
  background:rgba(91,92,240,.07); border:1px solid rgba(91,92,240,.2); border-radius:16px;
}
.gate-icon { width:44px; height:44px; border-radius:12px; display:grid; place-items:center; background:rgba(91,92,240,.15); flex:none; }
.gate-icon svg { width:22px; height:22px; color:var(--indigo); }
.gate-title { font-family:var(--disp); font-weight:800; font-size:15px; color:var(--txt); margin-bottom:3px; }
.gate-sub { font-size:12px; color:var(--muted); }

/* Loading */
.r-loading { display:flex; flex-direction:column; align-items:center; gap:12px; padding:60px; color:var(--muted); }
.spinner { width:28px; height:28px; border:3px solid rgba(255,255,255,.1); border-top-color:var(--indigo); border-radius:50%; animation:spin .8s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }

/* Empty */
.empty-state { text-align:center; padding:60px 20px; }
.empty-icon { width:56px; height:56px; border-radius:18px; display:grid; place-items:center; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.08); margin:0 auto 16px; }
.empty-icon svg { width:26px; height:26px; color:var(--muted); }
.empty-title { font-family:var(--disp); font-size:17px; font-weight:800; color:var(--txt); margin-bottom:6px; }
.empty-sub { font-size:12px; color:var(--muted); max-width:380px; margin:0 auto 20px; }

/* Clients grid */
.clients-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }

.client-card {
  background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07);
  border-radius:16px; padding:18px 20px; display:flex; flex-direction:column; gap:14px;
  transition:border-color .15s;
}
.client-card:hover { border-color:rgba(255,255,255,.13); }

.cc-head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }
.cc-name { font-family:var(--disp); font-size:15px; font-weight:800; color:var(--txt); margin-bottom:5px; }
.cc-meta { display:flex; align-items:center; gap:6px; font-size:10.5px; color:var(--muted); }
.plan-chip { font-family:var(--mono); font-size:8.5px; font-weight:700; letter-spacing:.4px; text-transform:uppercase; background:rgba(91,92,240,.14); color:var(--indigo); padding:1px 7px; border-radius:10px; }
.meta-sep { color:var(--faint); }

.grade-circle {
  width:52px; height:52px; flex:none; border-radius:50%; border:2px solid;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
}
.grade-letter { font-family:var(--disp); font-size:18px; font-weight:900; line-height:1; }
.grade-score { font-family:var(--mono); font-size:8.5px; color:var(--faint); margin-top:1px; }

.cc-flags { display:flex; flex-wrap:wrap; gap:6px; }
.flag { display:flex; align-items:center; gap:4px; font-family:var(--mono); font-size:9.5px; padding:3px 8px; border-radius:20px; }
.flag-icon { font-size:10px; }
.flag-good { background:rgba(52,224,161,.1); color:#34e0a1; }
.flag-warn { background:rgba(245,197,66,.1); color:#f5c542; }
.flag-bad  { background:rgba(255,77,109,.1); color:#ff4d6d; }

.cc-actions { display:flex; gap:8px; margin-top:auto; }
.act-btn {
  display:flex; align-items:center; gap:6px; padding:7px 12px; border-radius:10px;
  font-family:var(--disp); font-weight:700; font-size:11.5px; cursor:pointer; border:none;
  transition:opacity .15s;
}
.act-btn svg { width:13px; height:13px; }
.act-btn-primary { background:rgba(91,92,240,.15); color:var(--indigo); flex:1; justify-content:center; }
.act-btn-primary:hover { background:rgba(91,92,240,.25); }
.act-btn-danger { background:rgba(255,77,109,.1); color:#ff4d6d; }
.act-btn-danger:hover:not(:disabled) { background:rgba(255,77,109,.2); }
.act-btn-danger:disabled { opacity:.45; cursor:default; }

.mini-spinner { display:inline-block; width:11px; height:11px; border:2px solid rgba(255,255,255,.3); border-top-color:currentColor; border-radius:50%; animation:spin .7s linear infinite; }
.mini-spinner.white { border-top-color:#fff; }

/* Upgrade button */
.btn-upgrade {
  padding:9px 18px; border-radius:10px; border:none;
  background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff;
  font-family:var(--disp); font-weight:700; font-size:12.5px; cursor:pointer;
  display:flex; align-items:center; gap:8px;
}
.btn-upgrade:disabled { opacity:.55; cursor:default; }
.btn-upgrade:hover:not(:disabled) { opacity:.88; }

/* Modal */
.modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.6); backdrop-filter:blur(4px); display:grid; place-items:center; z-index:900; }
.modal { background:#10111e; border:1px solid rgba(255,255,255,.1); border-radius:20px; width:420px; max-width:calc(100vw - 32px); box-shadow:0 24px 80px rgba(0,0,0,.5); }
.modal-head { display:flex; align-items:center; justify-content:space-between; padding:20px 22px 0; }
.modal-head h3 { font-family:var(--disp); font-size:16px; font-weight:800; color:var(--txt); margin:0; }
.modal-close { background:none; border:none; color:var(--faint); font-size:16px; cursor:pointer; padding:4px 6px; border-radius:6px; }
.modal-close:hover { color:var(--txt); }
.modal-body { padding:18px 22px; }
.modal-foot { display:flex; justify-content:flex-end; gap:10px; padding:0 22px 20px; }
.btn-cancel { background:none; border:1px solid rgba(255,255,255,.1); color:var(--muted); padding:8px 16px; border-radius:10px; font-family:var(--disp); font-weight:700; font-size:12px; cursor:pointer; }
.btn-cancel:hover { border-color:rgba(255,255,255,.2); color:var(--txt); }

.field-label { display:block; font-family:var(--mono); font-size:9.5px; color:var(--faint); letter-spacing:.5px; text-transform:uppercase; margin-bottom:6px; }
.field-input {
  width:100%; background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08);
  border-radius:10px; color:var(--txt); font-size:13px; padding:9px 12px;
  outline:none; box-sizing:border-box; transition:border-color .15s; font-family:inherit;
}
.field-input:focus { border-color:rgba(91,92,240,.5); }

.toggle-row { display:flex; background:rgba(255,255,255,.05); border-radius:10px; padding:3px; gap:3px; }
.toggle-opt { flex:1; padding:7px; border:none; background:none; color:var(--muted); font-family:var(--disp); font-weight:600; font-size:11.5px; border-radius:8px; cursor:pointer; transition:.15s; }
.toggle-opt.tog-active { background:rgba(91,92,240,.25); color:var(--txt); }

.result-success { text-align:center; }
.result-success svg { width:40px; height:40px; margin:8px auto 16px; display:block; }
.result-success p { color:var(--txt); font-size:13px; margin:0 0 8px; }
.result-success strong { color:#34e0a1; }
.invite-url-box { background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.08); border-radius:8px; padding:10px 12px; font-family:var(--mono); font-size:10px; color:var(--teal); word-break:break-all; margin:10px 0; }
.hint { font-family:var(--mono); font-size:10px; color:var(--faint); }
</style>
