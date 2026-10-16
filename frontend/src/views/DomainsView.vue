<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import AddDomainWizard from '@/components/wizard/AddDomainWizard.vue'

const router = useRouter()
const auth   = useAuthStore()
const ui     = useUiStore()

const domains     = ref<any[]>([])
const loading     = ref(true)
const search      = ref('')
const page        = ref(1)
const PAGE_SIZE   = 25

// Add domain wizard
const showWizard = ref(false)

async function onWizardClose() {
  showWizard.value = false
  await load()
}

// Delete modal
const domainToDelete  = ref<any>(null)
const deleteLoading   = ref(false)

// Per-row async states
const syncingIds    = ref(new Set<string>())

// Verify ownership slide-over
const verifyDomain    = ref<any>(null)   // domain object being verified
const verifyRecord    = ref<any>(null)   // WizardStep2Out from backend
const verifyLoading   = ref(false)       // loading the record
const verifyChecking  = ref(false)       // running the ownership check
const verifyResult    = ref<any>(null)   // last check result
const copied          = ref('')          // which field was just copied

const PLAN_LIMITS: Record<string, number> = {
  free: 1, starter: 5, pro: 20, msp: 150, enterprise: Infinity,
}
const domainLimit = computed(() => PLAN_LIMITS[auth.plan] ?? 1)
const atLimit     = computed(() => domains.value.length >= domainLimit.value)

async function load() {
  loading.value = true
  try { domains.value = await api.domains() }
  finally { loading.value = false }
}

onMounted(load)

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  return q ? domains.value.filter(d => d.domain.toLowerCase().includes(q)) : domains.value
})

// Group subdomains under their parent — a domain row sorts immediately
// after the parent it belongs to, instead of appearing as an unrelated row
// elsewhere in the list (see parent_domain, derived server-side).
const sorted = computed(() => {
  return [...filtered.value].sort((a, b) => {
    const rootA = a.parent_domain || a.domain
    const rootB = b.parent_domain || b.domain
    if (rootA !== rootB) return rootA.localeCompare(rootB)
    const rankA = a.parent_domain ? 1 : 0
    const rankB = b.parent_domain ? 1 : 0
    if (rankA !== rankB) return rankA - rankB
    return a.domain.localeCompare(b.domain)
  })
})

const totalPages = computed(() => Math.max(1, Math.ceil(sorted.value.length / PAGE_SIZE)))
const paginated  = computed(() => sorted.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))
watch(search, () => { page.value = 1 })

function openAdd() {
  if (atLimit.value) { ui.toast(`Plan limit reached — upgrade to add more domains`); return }
  showWizard.value = true
}

async function syncDns(d: any, evt: Event) {
  evt.stopPropagation()
  if (syncingIds.value.has(d.id)) return
  syncingIds.value = new Set([...syncingIds.value, d.id])
  try {
    await api.syncDomainDns(d.id)
    await load()
    ui.toast(`DNS synced for ${d.domain}`)
  } catch (e: any) {
    ui.toast(e.message || 'Sync failed')
  } finally {
    const next = new Set(syncingIds.value)
    next.delete(d.id)
    syncingIds.value = next
  }
}

async function openVerify(d: any, evt: Event) {
  evt.stopPropagation()
  verifyDomain.value  = d
  verifyRecord.value  = null
  verifyResult.value  = null
  verifyLoading.value = true
  try {
    verifyRecord.value = await api.wizardStart(d.domain)
  } catch (e: any) {
    verifyRecord.value = { error: e.message || 'Could not load record' }
  } finally {
    verifyLoading.value = false
  }
}

async function runVerifyCheck() {
  if (!verifyDomain.value) return
  verifyChecking.value = true
  verifyResult.value   = null
  try {
    verifyResult.value = await api.verifyOwnership(verifyDomain.value.id)
    if (verifyResult.value.verified) {
      await load()
      const updated = domains.value.find(d => d.id === verifyDomain.value.id)
      if (updated) verifyDomain.value = updated
    }
  } catch (e: any) {
    verifyResult.value = { verified: false, message: e.message || 'Check failed' }
  } finally {
    verifyChecking.value = false
  }
}

function copyText(text: string, key: string) {
  navigator.clipboard.writeText(text)
  copied.value = key
  setTimeout(() => { copied.value = '' }, 1800)
}

function promptDelete(d: any, evt: Event) {
  evt.stopPropagation()
  domainToDelete.value = d
}

async function confirmDelete() {
  if (!domainToDelete.value) return
  deleteLoading.value = true
  try {
    await api.deleteDomain(domainToDelete.value.id)
    ui.toast(`${domainToDelete.value.domain} removed`)
    domainToDelete.value = null
    await load()
  } catch (e: any) {
    ui.toast(e.message || 'Delete failed')
  } finally {
    deleteLoading.value = false
  }
}

function openDomain(d: any) {
  router.push({ name: 'domain-detail', params: { id: d.id } })
}

function fmtDate(dt: string) {
  return new Date(dt).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: '2-digit' })
}

const DMARC_LABEL: Record<string, string> = {
  reject: 'Reject', quarantine: 'Quarantine', monitor: 'Monitor', none: 'None',
}
const DMARC_CLASS: Record<string, string> = {
  reject: 'pill-good', quarantine: 'pill-warn', monitor: 'pill-warn', none: 'pill-bad',
}
const MTA_LABEL: Record<string, string> = {
  enforce: 'Enforce', testing: 'Testing', none: 'None',
}
const MTA_CLASS: Record<string, string> = {
  enforce: 'pill-good', testing: 'pill-warn', none: 'pill-bad',
}
</script>

<template>
  <div class="domains-view">

    <!-- Header -->
    <div class="page-header">
      <div class="header-left">
        <div class="crumb">01 / Domains</div>
        <h1>Domains</h1>
        <span class="domain-count">{{ domains.length }} domain{{ domains.length !== 1 ? 's' : '' }}</span>
      </div>
      <div class="header-right">
        <div class="search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <input v-model="search" placeholder="Search domains…" class="search-input" />
        </div>
        <button class="btn-add" @click="openAdd" :class="{ disabled: atLimit }" :title="atLimit ? `${domains.length}/${domainLimit} domains — upgrade to add more` : ''">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M12 5v14M5 12h14"/>
          </svg>
          Add domain
          <span v-if="atLimit" class="limit-badge">{{ domains.length }}/{{ domainLimit }}</span>
        </button>
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrap" v-if="!loading">

      <!-- Empty state -->
      <div v-if="domains.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="1.5">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 8v4M12 16h.01"/>
          </svg>
        </div>
        <div class="empty-title">No domains yet</div>
        <div class="empty-sub">Add your first domain to start monitoring DMARC, MTA-STS, and certificate health.</div>
        <button class="btn-add" @click="openAdd" style="margin-top:20px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M12 5v14M5 12h14"/>
          </svg>
          Add domain
        </button>
      </div>

      <template v-else>
        <!-- Column headers -->
        <div class="thead">
          <span class="th">Domain</span>
          <span class="th">Ownership</span>
          <span class="th">DMARC</span>
          <span class="th">MTA-STS</span>
          <span class="th">Added</span>
          <span class="th" style="text-align:right">Actions</span>
        </div>

        <!-- No search results -->
        <div v-if="filtered.length === 0" class="no-results">
          No domains match "<strong>{{ search }}</strong>"
        </div>

        <!-- Rows -->
        <div
          v-for="d in paginated"
          :key="d.id"
          class="row"
          @click="openDomain(d)"
        >
          <!-- Domain -->
          <div class="cell-domain" :class="{ 'cell-domain-sub': d.parent_domain }">
            <span class="domain-name">
              <span v-if="d.parent_domain" class="sub-arrow">↳</span>
              {{ d.domain }}
            </span>
            <span v-if="d.parent_domain" class="parent-tag">subdomain of {{ d.parent_domain }}</span>
            <span class="reporting-addr">{{ d.reporting_address }}</span>
          </div>

          <!-- Ownership -->
          <div class="cell-ownership" @click.stop>
            <span v-if="d.ownership_verified" class="pill pill-good">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="pill-icon">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              Verified
            </span>
            <button v-else class="verify-btn" @click="openVerify(d, $event)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              Verify ownership
            </button>
          </div>

          <!-- DMARC policy -->
          <div class="cell">
            <span class="pill" :class="DMARC_CLASS[d.dmarc_stage] || 'pill-bad'">
              {{ DMARC_LABEL[d.dmarc_stage] || 'None' }}
            </span>
          </div>

          <!-- MTA-STS -->
          <div class="cell">
            <span class="pill" :class="MTA_CLASS[d.mta_sts_stage] || 'pill-bad'">
              {{ MTA_LABEL[d.mta_sts_stage] || 'None' }}
            </span>
          </div>

          <!-- Added date -->
          <div class="cell cell-date">{{ fmtDate(d.added_at) }}</div>

          <!-- Actions -->
          <div class="cell-actions" @click.stop>
            <button
              class="icon-btn"
              title="Sync DNS"
              :disabled="syncingIds.has(d.id)"
              @click="syncDns(d, $event)"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: syncingIds.has(d.id) }">
                <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
              </svg>
            </button>
            <button class="icon-btn" title="Open domain detail" @click="openDomain(d)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </button>
            <button class="icon-btn icon-btn-danger" title="Remove domain" @click="promptDelete(d, $event)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                <path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>
              </svg>
            </button>
          </div>
        </div>

        <!-- Pagination -->
        <div v-if="totalPages > 1" class="pagination">
          <button class="page-btn" :disabled="page === 1" @click="page--">← Prev</button>
          <span class="page-info">{{ page }} / {{ totalPages }}</span>
          <button class="page-btn" :disabled="page === totalPages" @click="page++">Next →</button>
        </div>
      </template>
    </div>

    <!-- Loading skeleton -->
    <div v-else class="loading-rows">
      <div v-for="i in 5" :key="i" class="skeleton-row" />
    </div>

  </div>

  <AddDomainWizard v-if="showWizard" @close="onWizardClose" />

  <!-- ── Verify ownership slide-over ──────────────────────────────────── -->
  <Teleport to="body">
    <div v-if="verifyDomain" class="overlay" @click.self="verifyDomain = null">
      <div class="slideover">
        <div class="slideover-header">
          <div>
            <div class="so-title">Verify ownership</div>
            <div class="so-sub">{{ verifyDomain.domain }}</div>
          </div>
          <button class="close-btn" @click="verifyDomain = null">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        <div class="slideover-body" style="overflow-y:auto">

          <!-- Loading -->
          <div v-if="verifyLoading" class="verify-loading">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" class="spin" style="width:24px;height:24px">
              <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
            </svg>
            Loading your unique record…
          </div>

          <!-- Error fetching record -->
          <div v-else-if="verifyRecord?.error" class="verify-error">
            {{ verifyRecord.error }}
          </div>

          <!-- Already verified -->
          <div v-else-if="verifyDomain.ownership_verified" class="verify-success-banner">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            <span>Ownership of <strong>{{ verifyDomain.domain }}</strong> is verified.</span>
          </div>

          <template v-else-if="verifyRecord">
            <!-- Explainer -->
            <div class="verify-intro">
              <p>ZoneProof needs to confirm you control <strong>{{ verifyDomain.domain }}</strong>. Add the DNS record below to your domain registrar or DNS provider, then click <em>Check now</em>.</p>
              <p>Your reporting address is embedded in this record — it's how ZoneProof receives DMARC reports for your domain.</p>
            </div>

            <!-- Step 1: DNS host -->
            <div class="verify-step">
              <div class="step-num">1</div>
              <div class="step-body">
                <div class="step-label">Add a TXT record at this host</div>
                <div class="copy-row">
                  <code class="copy-val">{{ verifyRecord.record_host }}</code>
                  <button class="copy-btn" @click="copyText(verifyRecord.record_host, 'host')">
                    <svg v-if="copied !== 'host'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    {{ copied === 'host' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
                <div class="step-hint">This is the standard DMARC record host for your domain.</div>
              </div>
            </div>

            <!-- Step 2: Record value -->
            <div class="verify-step">
              <div class="step-num">2</div>
              <div class="step-body">
                <div class="step-label">Set the TXT record value to</div>
                <div class="copy-row copy-row-tall">
                  <code class="copy-val copy-val-wrap">{{ verifyRecord.generated_record }}</code>
                  <button class="copy-btn" @click="copyText(verifyRecord.generated_record, 'record')">
                    <svg v-if="copied !== 'record'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    {{ copied === 'record' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
                <div class="step-hint">
                  The <code class="inline-code">rua=mailto:</code> tag contains your unique reporting address.
                  ZoneProof uses it to receive aggregate reports and confirm you own this domain.
                </div>
              </div>
            </div>

            <!-- Reporting address callout -->
            <div class="reporting-callout">
              <div class="rc-label">Your unique reporting address</div>
              <div class="copy-row" style="margin-top:8px">
                <code class="copy-val" style="font-size:12px">{{ verifyRecord.reporting_address }}</code>
                <button class="copy-btn" @click="copyText(verifyRecord.reporting_address, 'rua')">
                  <svg v-if="copied !== 'rua'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                  {{ copied === 'rua' ? 'Copied' : 'Copy' }}
                </button>
              </div>
              <div class="rc-note">DNS changes can take up to 24–48 hours to propagate. You can click Check now at any time.</div>
            </div>

            <!-- Check result -->
            <div v-if="verifyResult" class="verify-result" :class="verifyResult.verified ? 'result-ok' : 'result-fail'">
              <svg v-if="verifyResult.verified" viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <div>
                <div class="result-title">{{ verifyResult.verified ? 'Ownership confirmed' : 'Not verified yet' }}</div>
                <div class="result-msg">{{ verifyResult.message }}</div>
              </div>
            </div>
          </template>

        </div>

        <div class="slideover-footer" v-if="verifyRecord && !verifyRecord.error && !verifyDomain.ownership_verified">
          <button class="btn-cancel" @click="verifyDomain = null">Close</button>
          <button class="btn-confirm" :disabled="verifyChecking" @click="runVerifyCheck">
            <svg v-if="verifyChecking" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin btn-icon">
              <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
            </svg>
            {{ verifyChecking ? 'Checking DNS…' : 'Check now' }}
          </button>
        </div>
        <div class="slideover-footer" v-else-if="verifyDomain.ownership_verified">
          <button class="btn-confirm" style="flex:1" @click="verifyDomain = null">Done</button>
        </div>
      </div>
    </div>
  </Teleport>

  <!-- ── Delete confirmation modal ─────────────────────────────────────── -->
  <Teleport to="body">
    <div v-if="domainToDelete" class="overlay" @click.self="domainToDelete = null">
      <div class="modal">
        <div class="modal-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </div>
        <div class="modal-title">Remove domain?</div>
        <div class="modal-body">
          <strong>{{ domainToDelete.domain }}</strong> and all its data — DMARC reports, DNS history,
          certificate records, and TLS sessions — will be permanently deleted.
          This cannot be undone.
        </div>
        <div class="modal-actions">
          <button class="btn-cancel" @click="domainToDelete = null">Cancel</button>
          <button class="btn-delete" :disabled="deleteLoading" @click="confirmDelete">
            {{ deleteLoading ? 'Removing…' : 'Remove domain' }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.domains-view { max-width: 1100px; }

/* ── Header ───────────────────────────────────────────────────────────── */
.page-header {
  display: flex; align-items: flex-end; justify-content: space-between;
  margin-bottom: 28px; gap: 16px; flex-wrap: wrap;
}
.header-left { display: flex; align-items: baseline; gap: 14px; }
.header-right { display: flex; align-items: center; gap: 12px; }
.crumb { font-family: var(--mono); font-size: 10px; letter-spacing: 1px; color: var(--faint); text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 26px; margin: 0; letter-spacing: -.4px; }
.domain-count {
  font-family: var(--mono); font-size: 10px; color: var(--faint);
  background: rgba(255,255,255,.06); border: 1px solid var(--line); border-radius: 20px; padding: 2px 10px;
}

.search-wrap {
  display: flex; align-items: center; gap: 8px;
  background: rgba(255,255,255,.05); border: 1px solid var(--line2);
  border-radius: 10px; padding: 8px 14px; transition: border-color .15s;
}
.search-wrap:focus-within { border-color: var(--indigo); }
.search-wrap svg { width: 14px; height: 14px; color: var(--faint); flex: none; }
.search-input {
  background: none; border: none; outline: none; color: var(--txt);
  font-family: var(--body); font-size: 13px; width: 180px;
}
.search-input::placeholder { color: var(--faint); }

.btn-add {
  display: flex; align-items: center; gap: 7px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff;
  border: none; border-radius: 11px; padding: 9px 16px;
  font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer;
  transition: opacity .15s; white-space: nowrap;
}
.btn-add svg { width: 14px; height: 14px; }
.btn-add:hover { opacity: .88; }
.btn-add.disabled { opacity: .5; cursor: not-allowed; }
.limit-badge {
  font-family: var(--mono); font-size: 9px; background: rgba(255,255,255,.2);
  border-radius: 8px; padding: 1px 6px;
}

/* ── Table ────────────────────────────────────────────────────────────── */
.table-wrap {
  background: var(--glass); border: 1px solid var(--line2); border-radius: 18px;
  overflow: hidden;
}
.thead {
  display: grid;
  grid-template-columns: 2fr 1.2fr .8fr .8fr .8fr 1fr;
  gap: 12px; align-items: center;
  font-family: var(--mono); font-size: 9px; letter-spacing: .7px; text-transform: uppercase;
  color: var(--faint); padding: 13px 20px; border-bottom: 1px solid var(--line);
}
.th { }

.row {
  display: grid;
  grid-template-columns: 2fr 1.2fr .8fr .8fr .8fr 1fr;
  gap: 12px; align-items: center;
  padding: 14px 20px; cursor: pointer;
  border-bottom: 1px solid var(--line);
  transition: background .12s;
}
.row:last-child { border-bottom: none; }
.row:hover { background: rgba(255,255,255,.033); }

.cell-domain { min-width: 0; }
.cell-domain-sub { padding-left: 14px; }
.domain-name {
  display: block; font-family: var(--mono); font-size: 13px; font-weight: 600;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.sub-arrow { color: var(--faint); margin-right: 3px; }
.parent-tag {
  display: block; font-family: var(--mono); font-size: 9.5px; color: #9aa6ff;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;
}
.reporting-addr {
  display: block; font-family: var(--mono); font-size: 9.5px; color: var(--faint);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 3px;
}

.cell, .cell-ownership, .cell-date { display: flex; align-items: center; }
.cell-date { font-family: var(--mono); font-size: 11px; color: var(--muted); }

/* ── Pills ────────────────────────────────────────────────────────────── */
.pill {
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: .3px;
  padding: 3px 10px; border-radius: 20px;
}
.pill-icon { width: 10px; height: 10px; }
.pill-good { background: rgba(52,224,161,.12); color: var(--good); border: 1px solid rgba(52,224,161,.25); }
.pill-warn { background: rgba(245,197,66,.10); color: var(--warn); border: 1px solid rgba(245,197,66,.2); }
.pill-bad  { background: rgba(255,77,109,.10);  color: var(--bad);  border: 1px solid rgba(255,77,109,.2); }

/* ── Verify button ────────────────────────────────────────────────────── */
.verify-btn {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  color: var(--warn); background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25);
  border-radius: 20px; padding: 3px 10px; cursor: pointer; transition: .15s;
}
.verify-btn:hover:not(:disabled) { background: rgba(245,197,66,.16); }
.verify-btn:disabled { opacity: .6; cursor: not-allowed; }
.verify-btn svg { width: 11px; height: 11px; }

/* ── Row actions ──────────────────────────────────────────────────────── */
.cell-actions {
  display: flex; align-items: center; justify-content: flex-end; gap: 4px;
}
.icon-btn {
  width: 30px; height: 30px; display: grid; place-items: center;
  background: none; border: 1px solid transparent; border-radius: 8px;
  color: var(--faint); cursor: pointer; transition: .15s;
}
.icon-btn svg { width: 14px; height: 14px; }
.icon-btn:hover { background: rgba(255,255,255,.07); color: var(--txt); border-color: var(--line2); }
.icon-btn:disabled { opacity: .4; cursor: not-allowed; }
.icon-btn-danger:hover { background: rgba(255,77,109,.1); color: var(--bad); border-color: rgba(255,77,109,.25); }

/* ── Spin animation ───────────────────────────────────────────────────── */
.spin { animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Pagination ───────────────────────────────────────────────────────── */
.pagination {
  display: flex; align-items: center; justify-content: center; gap: 16px;
  padding: 16px; border-top: 1px solid var(--line);
}
.page-btn {
  background: none; border: 1px solid var(--line2); border-radius: 8px;
  color: var(--muted); font-family: var(--mono); font-size: 11px;
  padding: 6px 14px; cursor: pointer; transition: .15s;
}
.page-btn:hover:not(:disabled) { color: var(--txt); border-color: var(--indigo); }
.page-btn:disabled { opacity: .3; cursor: not-allowed; }
.page-info { font-family: var(--mono); font-size: 11px; color: var(--faint); }

/* ── Empty state ──────────────────────────────────────────────────────── */
.empty-state {
  display: flex; flex-direction: column; align-items: center;
  padding: 60px 24px; text-align: center;
}
.empty-icon {
  width: 52px; height: 52px; border-radius: 16px; display: grid; place-items: center;
  background: rgba(46,230,197,.08); border: 1px solid rgba(46,230,197,.15); margin-bottom: 16px;
}
.empty-icon svg { width: 26px; height: 26px; }
.empty-title { font-family: var(--disp); font-weight: 700; font-size: 17px; margin-bottom: 8px; }
.empty-sub { color: var(--muted); font-size: 13px; max-width: 380px; line-height: 1.6; }

.no-results { padding: 32px; text-align: center; color: var(--muted); font-size: 13px; }
.no-results strong { color: var(--txt); }

/* ── Loading skeletons ────────────────────────────────────────────────── */
.loading-rows { display: flex; flex-direction: column; gap: 8px; }
.skeleton-row {
  height: 56px; background: var(--glass); border: 1px solid var(--line2);
  border-radius: 12px; animation: pulse 1.4s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { opacity: .4 } 50% { opacity: .8 } }

/* ── Slide-over & modal overlay ───────────────────────────────────────── */
.overlay {
  position: fixed; inset: 0; background: rgba(6,6,15,.65);
  backdrop-filter: blur(6px); z-index: 900;
  display: flex; align-items: center; justify-content: flex-end;
}

.slideover-footer {
  display: flex; gap: 10px; padding: 20px 28px; border-top: 1px solid var(--line);
}

/* ── Modal ────────────────────────────────────────────────────────────── */
.overlay:has(.modal) { justify-content: center; align-items: center; }
.modal {
  width: 420px; max-width: 94vw;
  background: #0e0e1e; border: 1px solid var(--line2); border-radius: 20px;
  padding: 32px; text-align: center;
}
.modal-icon {
  width: 52px; height: 52px; border-radius: 14px; display: grid; place-items: center;
  background: rgba(255,77,109,.08); border: 1px solid rgba(255,77,109,.2);
  margin: 0 auto 18px;
}
.modal-icon svg { width: 24px; height: 24px; }
.modal-title { font-family: var(--disp); font-weight: 700; font-size: 18px; margin-bottom: 12px; }
.modal-body { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 24px; }
.modal-body strong { color: var(--txt); }
.modal-actions { display: flex; gap: 10px; justify-content: center; }

/* ── Verify slide-over internals ──────────────────────────────────────── */
.verify-loading {
  display: flex; align-items: center; gap: 12px; padding: 32px;
  color: var(--muted); font-size: 13px; justify-content: center;
}
.verify-error { padding: 20px; color: var(--bad); font-size: 13px; }

.verify-success-banner {
  display: flex; align-items: center; gap: 10px;
  padding: 16px; margin-bottom: 16px;
  background: rgba(52,224,161,.08); border: 1px solid rgba(52,224,161,.2); border-radius: 12px;
  font-size: 13px; color: var(--muted);
}
.verify-success-banner svg { width: 18px; height: 18px; flex: none; }
.verify-success-banner strong { color: var(--txt); }

.verify-intro {
  font-size: 13px; color: var(--muted); line-height: 1.65; margin-bottom: 24px;
}
.verify-intro p { margin: 0 0 10px; }
.verify-intro strong { color: var(--txt); }
.verify-intro em { color: var(--teal); font-style: normal; }

.verify-step {
  display: flex; gap: 14px; margin-bottom: 22px;
}
.step-num {
  width: 24px; height: 24px; flex: none; border-radius: 50%;
  background: rgba(91,92,240,.18); border: 1px solid rgba(91,92,240,.35);
  color: var(--indigo); font-family: var(--mono); font-size: 11px; font-weight: 700;
  display: grid; place-items: center; margin-top: 1px;
}
.step-body { flex: 1; min-width: 0; }
.step-label {
  font-family: var(--mono); font-size: 10px; text-transform: uppercase;
  letter-spacing: .6px; color: var(--faint); margin-bottom: 8px;
}
.step-hint { font-size: 11px; color: var(--faint); line-height: 1.5; margin-top: 8px; }

.copy-row {
  display: flex; align-items: center; gap: 8px;
  background: rgba(0,0,0,.25); border: 1px solid var(--line2); border-radius: 10px;
  padding: 10px 12px;
}
.copy-row-tall { align-items: flex-start; }
.copy-val {
  flex: 1; font-family: var(--mono); font-size: 11.5px; color: var(--teal);
  word-break: break-all; white-space: pre-wrap; line-height: 1.55;
}
.copy-val-wrap { white-space: pre-wrap; }
.copy-btn {
  flex: none; display: flex; align-items: center; gap: 5px;
  background: rgba(255,255,255,.07); border: 1px solid var(--line2);
  border-radius: 7px; padding: 5px 10px;
  font-family: var(--mono); font-size: 10px; color: var(--muted);
  cursor: pointer; transition: .15s; white-space: nowrap; align-self: flex-start;
}
.copy-btn:hover { color: var(--txt); border-color: var(--indigo); }
.copy-btn svg { width: 12px; height: 12px; }

.inline-code {
  font-family: var(--mono); font-size: 11px; color: var(--teal);
  background: rgba(46,230,197,.08); padding: 1px 5px; border-radius: 4px;
}

.reporting-callout {
  background: rgba(46,230,197,.05); border: 1px solid rgba(46,230,197,.15);
  border-radius: 12px; padding: 14px 16px; margin-bottom: 20px;
}
.rc-label {
  font-family: var(--mono); font-size: 9px; text-transform: uppercase;
  letter-spacing: .6px; color: var(--teal);
}
.rc-note { font-size: 11px; color: var(--faint); line-height: 1.55; margin-top: 10px; }

.verify-result {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 14px 16px; border-radius: 12px; margin-bottom: 4px;
}
.verify-result svg { width: 18px; height: 18px; flex: none; margin-top: 1px; }
.result-ok   { background: rgba(52,224,161,.07); border: 1px solid rgba(52,224,161,.2); }
.result-fail { background: rgba(255,77,109,.07); border: 1px solid rgba(255,77,109,.2); }
.result-title { font-weight: 700; font-size: 13px; margin-bottom: 3px; }
.result-msg { font-size: 12px; color: var(--muted); line-height: 1.5; }

/* ── Shared button styles ─────────────────────────────────────────────── */
.btn-cancel {
  flex: 1; background: rgba(255,255,255,.06); border: 1px solid var(--line2);
  border-radius: 11px; padding: 11px; color: var(--muted);
  font-family: var(--disp); font-weight: 600; font-size: 13px; cursor: pointer; transition: .15s;
}
.btn-cancel:hover { color: var(--txt); }
.btn-confirm {
  flex: 1; display: flex; align-items: center; justify-content: center; gap: 7px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff;
  border: none; border-radius: 11px; padding: 11px;
  font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer; transition: opacity .15s;
}
.btn-confirm:disabled { opacity: .55; cursor: not-allowed; }
.btn-confirm:hover:not(:disabled) { opacity: .88; }
.btn-icon { width: 14px; height: 14px; }
.btn-delete {
  flex: 1; background: var(--bad); color: #fff;
  border: none; border-radius: 11px; padding: 11px;
  font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer; transition: opacity .15s;
}
.btn-delete:disabled { opacity: .55; cursor: not-allowed; }
.btn-delete:hover:not(:disabled) { opacity: .88; }
</style>
