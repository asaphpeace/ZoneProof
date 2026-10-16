<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'

const props = defineProps<{ domains: string[] }>()
const emit  = defineEmits<{ next: [domainNames: string[]]; cancel: [] }>()

const domainsStore = useDomainsStore()
const ui           = useUiStore()

// ── Data ────────────────────────────────────────────────────────────────────

interface DomainData {
  domain: string
  skipped: boolean
  // DMARC (from wizardStart)
  already_exists: boolean
  dmarc_exists: boolean
  current_record: string | null
  generated_record: string
  reporting_address: string
  // TLS (from wizardTlsInfo)
  tlsrpt_record: string
  tlsrpt_host: string
  mta_sts_dns_record: string
  mta_sts_dns_host: string
  mta_sts_policy: string
  policy_url: string
  mta_sts_cname_target: string
  mta_sts_cname_host: string
  // UI state
  hostingMode: 'managed' | 'self'
  open: boolean   // accordion
}

const items   = ref<DomainData[]>([])
const loading = ref(true)
const loadingIdx = ref(0)
const error   = ref('')
const saving  = ref(false)
const copiedKey = ref<string | null>(null)

// ── Load ─────────────────────────────────────────────────────────────────────

onMounted(async () => {
  try {
    for (let i = 0; i < props.domains.length; i++) {
      loadingIdx.value = i
      const dmarc = await api.wizardStart(props.domains[i])
      const tls   = await api.wizardTlsInfo(props.domains[i])
      items.value.push({
        ...dmarc,
        ...tls,
        hostingMode: 'managed',
        open: true,
        skipped: dmarc.already_exists,
      })
    }
  } catch (e: any) {
    error.value = e.message || 'Failed to load domain information'
  } finally {
    loading.value = false
  }
})

// ── Copy ─────────────────────────────────────────────────────────────────────

async function copy(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedKey.value = key
    setTimeout(() => { copiedKey.value = null }, 2000)
  } catch {}
}

// ── Save & continue ───────────────────────────────────────────────────────────

async function save() {
  saving.value = true
  error.value = ''
  try {
    const toProcess = items.value.filter(r => !r.skipped)
    for (const r of toProcess) {
      await api.wizardConfirm(r.domain)
    }
    await domainsStore.fetch()
    for (const r of toProcess) {
      if (r.hostingMode === 'managed') {
        const dom = domainsStore.list.find((d: any) => d.domain === r.domain)
        if (dom) await api.setMtaStsHostingMode(dom.id, 'managed')
      }
    }
    const n  = toProcess.filter(r => !r.already_exists).length
    const re = toProcess.filter(r => r.already_exists).length
    const parts = []
    if (n)  parts.push(`${n} domain${n > 1 ? 's' : ''} added`)
    if (re) parts.push(`${re} re-onboarded`)
    if (parts.length) ui.toast(parts.join(' · ') + ' successfully')
    emit('next', toProcess.map(r => r.domain))
  } catch (e: any) {
    error.value = e.message || 'Failed to save'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div>
    <div class="sh">DNS records to publish</div>
    <p class="hint">Copy each record into your DNS provider. You can do this now or later — the Roadmap tracks what's still pending.</p>

    <!-- Loading -->
    <div v-if="loading" class="progress-wrap">
      <div class="spin" />
      <div>
        <div class="prog-label">Loading <b>{{ props.domains[loadingIdx] }}</b>…</div>
        <div class="prog-bar-track">
          <div class="prog-bar-fill" :style="{ width: ((loadingIdx / props.domains.length) * 100) + '%' }" />
        </div>
        <div class="prog-count">{{ loadingIdx + 1 }} of {{ props.domains.length }}</div>
      </div>
    </div>

    <!-- Error -->
    <div v-else-if="error && !items.length" class="err-box">
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2" style="width:16px;height:16px;flex:none"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      {{ error }}
    </div>

    <!-- Domain cards -->
    <template v-else>
      <div v-for="r in items" :key="r.domain" class="domain-card" :class="{ dimmed: r.skipped }">

        <!-- Card header -->
        <div class="card-head" @click="r.open = !r.open" tabindex="0" role="button" :aria-expanded="r.open" @keydown.enter.prevent="r.open = !r.open" @keydown.space.prevent="r.open = !r.open">
          <div class="card-head-left">
            <span class="dn">{{ r.domain }}</span>
            <span v-if="r.already_exists" class="badge amber">Re-onboard</span>
          </div>
          <div class="card-head-right">
            <label class="toggle-wrap" v-if="r.already_exists" @click.stop>
              <input type="checkbox" :checked="!r.skipped" @change="r.skipped = !($event.target as HTMLInputElement).checked" />
              <span class="toggle-label">{{ r.skipped ? 'Skip' : 'Include' }}</span>
            </label>
            <svg class="chevron" :class="{ open: r.open }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
          </div>
        </div>

        <template v-if="r.open && !r.skipped">

          <!-- ── Section 1: DMARC ─────────────────────────── -->
          <div class="section">
            <div class="section-title">
              <span class="section-num">1</span>
              DMARC
              <span class="section-sub">{{ r.dmarc_exists ? 'Update existing record' : 'Publish new record' }}</span>
            </div>

            <div v-if="r.dmarc_exists" class="record-row">
              <div class="record-label">Current record</div>
              <div class="record-box current">
                <span class="record-text muted">{{ r.current_record }}</span>
              </div>
            </div>

            <div class="record-row">
              <div class="record-label">Reporting address</div>
              <div class="record-box indigo">
                <span class="record-text teal">{{ r.reporting_address }}</span>
                <button class="copy-btn" @click="copy(r.reporting_address, r.domain + '-rua')">
                  <svg v-if="copiedKey !== r.domain + '-rua'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  {{ copiedKey === r.domain + '-rua' ? 'Copied' : 'Copy' }}
                </button>
              </div>
            </div>

            <div class="record-row">
              <div class="record-label">{{ r.dmarc_exists ? 'Updated record to publish' : 'Record to publish' }} <span class="dns-at">at _dmarc.{{ r.domain }}</span></div>
              <div class="record-box new">
                <span class="record-text teal">{{ r.generated_record }}</span>
                <button class="copy-btn" @click="copy(r.generated_record, r.domain + '-dmarc')">
                  <svg v-if="copiedKey !== r.domain + '-dmarc'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  {{ copiedKey === r.domain + '-dmarc' ? 'Copied' : 'Copy' }}
                </button>
              </div>
            </div>
          </div>

          <!-- ── Section 2: TLS-RPT ───────────────────────── -->
          <div class="section">
            <div class="section-title">
              <span class="section-num">2</span>
              TLS-RPT
              <span class="section-sub">Enables TLS failure reporting</span>
            </div>

            <div class="record-row">
              <div class="record-label">TXT record <span class="dns-at">at {{ r.tlsrpt_host }}</span></div>
              <div class="record-box new">
                <span class="record-text teal">{{ r.tlsrpt_record }}</span>
                <button class="copy-btn" @click="copy(r.tlsrpt_record, r.domain + '-tlsrpt')">
                  <svg v-if="copiedKey !== r.domain + '-tlsrpt'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  {{ copiedKey === r.domain + '-tlsrpt' ? 'Copied' : 'Copy' }}
                </button>
              </div>
            </div>
          </div>

          <!-- ── Section 3: MTA-STS ───────────────────────── -->
          <div class="section">
            <div class="section-title">
              <span class="section-num">3</span>
              MTA-STS
              <span class="section-sub">Enforces TLS for inbound mail</span>
            </div>

            <!-- Hosting toggle -->
            <div class="hosting-toggle">
              <button
                class="hosting-opt" :class="{ active: r.hostingMode === 'managed' }"
                @click="r.hostingMode = 'managed'"
              >
                <div class="opt-top">
                  <b>ZoneProof-hosted</b>
                  <span class="opt-badge recommended">Recommended</span>
                </div>
                <span>Publish one CNAME — no server or file to manage</span>
              </button>
              <button
                class="hosting-opt" :class="{ active: r.hostingMode === 'self' }"
                @click="r.hostingMode = 'self'"
              >
                <div class="opt-top"><b>Self-hosted</b></div>
                <span>You serve the policy file from your own HTTPS server</span>
              </button>
            </div>

            <!-- Ordering warning for managed mode -->
            <div v-if="r.hostingMode === 'managed'" class="notice teal">
              <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" style="width:15px;height:15px;flex:none;margin-top:1px"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
              <div>
                <b>Order matters:</b> click <em>Save &amp; continue</em> first, then change your DNS.
                ZoneProof activates managed hosting immediately on save — if you update DNS before saving,
                the CNAME resolves but no cert has been issued yet, causing a brief gap in coverage.
              </div>
            </div>

            <!-- MTA-STS DNS TXT record (both modes need this) -->
            <div class="record-row">
              <div class="record-label">TXT record <span class="dns-at">at {{ r.mta_sts_dns_host }}</span></div>
              <div class="record-box new">
                <span class="record-text teal">{{ r.mta_sts_dns_record }}</span>
                <button class="copy-btn" @click="copy(r.mta_sts_dns_record, r.domain + '-mta-dns')">
                  <svg v-if="copiedKey !== r.domain + '-mta-dns'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  {{ copiedKey === r.domain + '-mta-dns' ? 'Copied' : 'Copy' }}
                </button>
              </div>
            </div>

            <!-- Managed: CNAME -->
            <template v-if="r.hostingMode === 'managed'">
              <div class="record-row">
                <div class="record-label">CNAME record <span class="dns-at">at {{ r.mta_sts_cname_host }}</span></div>
                <div class="record-box new">
                  <span class="record-text teal">{{ r.mta_sts_cname_target }}</span>
                  <button class="copy-btn" @click="copy(r.mta_sts_cname_target, r.domain + '-cname')">
                    <svg v-if="copiedKey !== r.domain + '-cname'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    {{ copiedKey === r.domain + '-cname' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
              </div>
              <p class="sub-note">ZoneProof will serve the policy file at <code>{{ r.policy_url }}</code> automatically, always reflecting your current MX records.</p>
            </template>

            <!-- Self-hosted: policy file -->
            <template v-else>
              <div class="record-row">
                <div class="record-label">Policy file <span class="dns-at">at {{ r.policy_url }}</span></div>
                <div class="record-box current policy-file">
                  <pre class="record-text muted">{{ r.mta_sts_policy }}</pre>
                  <button class="copy-btn" @click="copy(r.mta_sts_policy, r.domain + '-policy')">
                    <svg v-if="copiedKey !== r.domain + '-policy'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    {{ copiedKey === r.domain + '-policy' ? 'Copied' : 'Copy' }}
                  </button>
                </div>
              </div>
              <p class="sub-note">Serve this file over HTTPS with <code>Content-Type: text/plain</code>.</p>
            </template>
          </div>

        </template>

        <!-- Skipped state -->
        <div v-else-if="r.skipped && r.already_exists" class="skip-note">
          This domain stays as-is in your portfolio.
        </div>

      </div>

      <div v-if="error" class="err-box" style="margin-top:8px">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2" style="width:16px;height:16px;flex:none"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
        {{ error }}
      </div>

      <div class="actions">
        <button class="btn ghost" @click="emit('cancel')">Cancel</button>
        <button class="btn" :disabled="saving" @click="save">
          {{ saving ? 'Saving…' : 'Save & continue →' }}
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 18px; margin-bottom: 8px; }
.hint { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 18px; }

/* Loading */
.progress-wrap { display: flex; align-items: flex-start; gap: 14px; padding: 20px 0; }
.spin { width: 20px; height: 20px; border: 2px solid var(--line2); border-top-color: var(--teal); border-radius: 50%; animation: spin .8s linear infinite; flex: none; margin-top: 2px; }
@keyframes spin { to { transform: rotate(360deg); } }
.prog-label { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.prog-bar-track { width: 260px; height: 4px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; }
.prog-bar-fill { height: 100%; background: linear-gradient(90deg,#2ee6c5,#5b5cf0); border-radius: 4px; transition: width .35s ease; }
.prog-count { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 5px; }

/* Domain card */
.domain-card { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 16px; margin-bottom: 14px; overflow: hidden; transition: opacity .2s; }
.domain-card.dimmed { opacity: .5; }

.card-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; cursor: pointer; user-select: none; }
.card-head:hover { background: rgba(255,255,255,.02); }
.card-head-left { display: flex; align-items: center; gap: 10px; }
.card-head-right { display: flex; align-items: center; gap: 10px; }
.dn { font-family: var(--mono); font-size: 13px; font-weight: 600; }
.badge { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .6px; padding: 2px 8px; border-radius: 20px; }
.badge.amber { background: rgba(255,190,0,.15); border: 1px solid rgba(255,190,0,.3); color: var(--amber); }
.chevron { width: 16px; height: 16px; color: var(--faint); transition: transform .2s; }
.chevron.open { transform: rotate(180deg); }

.toggle-wrap { display: flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; }
.toggle-wrap input { accent-color: var(--teal); cursor: pointer; }
.toggle-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }

/* Sections */
.section { padding: 14px 16px; border-top: 1px solid var(--line); }
.section-title { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-family: var(--disp); font-weight: 700; font-size: 13px; }
.section-num { width: 20px; height: 20px; border-radius: 50%; background: rgba(91,92,240,.25); border: 1px solid rgba(91,92,240,.4); color: #9aa6ff; font-family: var(--mono); font-size: 10px; display: grid; place-items: center; flex: none; }
.section-sub { font-family: var(--body); font-weight: 400; font-size: 11.5px; color: var(--faint); }

/* Records */
.record-row { margin-bottom: 10px; }
.record-label { font-family: var(--mono); font-size: 9.5px; text-transform: uppercase; letter-spacing: .7px; color: var(--faint); margin-bottom: 5px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.dns-at { color: var(--indigo); opacity: .7; font-size: 9px; }
.record-box { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: rgba(255,255,255,.03); }
.record-box.current { border-color: rgba(255,255,255,.1); background: rgba(255,255,255,.02); }
.record-box.new { border-color: rgba(46,230,197,.2); background: rgba(46,230,197,.04); }
.record-box.indigo { border-color: rgba(91,92,240,.2); background: rgba(91,92,240,.04); }
.record-box.policy-file { align-items: flex-start; }
.record-text { font-family: var(--mono); font-size: 11.5px; line-height: 1.6; flex: 1; word-break: break-all; }
.record-text.teal { color: var(--teal); }
.record-text.muted { color: var(--muted); }
pre.record-text { white-space: pre; margin: 0; }

.copy-btn { display: flex; align-items: center; gap: 5px; background: rgba(255,255,255,.07); border: 1px solid var(--line); border-radius: 7px; padding: 5px 10px; font-family: var(--mono); font-size: 10px; color: var(--muted); cursor: pointer; white-space: nowrap; flex: none; transition: background .15s; }
.copy-btn:hover { background: rgba(255,255,255,.12); }
.copy-btn svg { width: 12px; height: 12px; }

.sub-note { font-size: 11.5px; color: var(--faint); margin-top: 6px; line-height: 1.55; }
.sub-note code { font-family: var(--mono); font-size: 10.5px; background: rgba(255,255,255,.06); padding: 1px 5px; border-radius: 4px; color: var(--muted); }

/* Hosting toggle */
.hosting-toggle { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
.hosting-opt { display: flex; flex-direction: column; gap: 4px; text-align: left; background: rgba(255,255,255,.03); border: 1px solid var(--line2); border-radius: 11px; padding: 10px 12px; cursor: pointer; color: var(--muted); font-size: 12px; transition: border-color .15s, background .15s; }
.hosting-opt b { color: var(--txt); font-size: 12.5px; }
.hosting-opt span { font-size: 11px; color: var(--faint); }
.hosting-opt.active { border-color: var(--indigo); background: rgba(91,92,240,.1); }
.hosting-opt.active b { color: #9aa6ff; }
.opt-top { display: flex; align-items: center; gap: 8px; }
.opt-badge { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .5px; padding: 2px 6px; border-radius: 5px; }
.opt-badge.recommended { background: rgba(46,230,197,.15); border: 1px solid rgba(46,230,197,.25); color: var(--teal); }

/* Notices */
.notice { display: flex; gap: 10px; padding: 12px 14px; border-radius: 11px; font-size: 12.5px; line-height: 1.55; color: var(--muted); margin-bottom: 12px; }
.notice.teal { background: rgba(46,230,197,.07); border: 1px solid rgba(46,230,197,.2); }
.notice b { color: var(--txt); }
.notice em { font-style: normal; color: var(--teal); }

.skip-note { padding: 12px 16px; font-size: 12px; color: var(--faint); font-style: italic; border-top: 1px solid var(--line); }

/* Error */
.err-box { display: flex; gap: 10px; padding: 13px 15px; background: rgba(255,80,80,.07); border: 1px solid rgba(255,80,80,.25); border-radius: 12px; font-size: 13px; color: var(--muted); align-items: flex-start; }

/* Actions */
.actions { margin-top: 16px; display: flex; justify-content: flex-end; gap: 10px; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none; border-radius: 12px; padding: 11px 24px; font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); }
.btn:disabled { opacity: .6; cursor: not-allowed; }
</style>
