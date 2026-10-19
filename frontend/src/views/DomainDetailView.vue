<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'
import AiBadge from '@/components/ui/AiBadge.vue'
import PlatformHealthMatrix from '@/components/domain/PlatformHealthMatrix.vue'

const route  = useRoute()
const router = useRouter()
const ui     = useUiStore()

const domainId = route.params.id as string

const detail      = ref<any>(null)
const dmarcInfo   = ref<any>(null)
const tlsInfo     = ref<any>(null)
const senderRecs  = ref<any[]>([])
const loading     = ref(true)
const syncing     = ref(false)
const copied      = ref('')
const dismissing  = ref<string | null>(null)

const subdomains        = ref<any[]>([])
const subdomainsLoading = ref(false)
const subdomainsLoaded  = ref(false)
const subdomainsError   = ref('')
const subdomainSources  = ref<Record<string, string>>({})
const subdomainCoverage = ref<any>(null)
const addingSubdomain   = ref<string | null>(null)

onMounted(async () => {
  try {
    detail.value = await api.domain(domainId)
    const [d, t, s] = await Promise.all([
      api.wizardStart(detail.value.domain).catch(() => null),
      api.wizardTlsInfo(detail.value.domain).catch(() => null),
      api.get(`/domains/${domainId}/dmarc/sender-recommendations`).catch(() => []),
    ])
    dmarcInfo.value = d
    tlsInfo.value   = t
    senderRecs.value = s || []
  } finally {
    loading.value = false }
})

async function loadSubdomains() {
  subdomainsLoading.value = true
  subdomainsLoaded.value = true
  subdomainsError.value = ''
  try {
    const res = await api.discoverSubdomains(domainId)
    subdomains.value = res.subdomains || []
    subdomainSources.value = res.sources || {}
    subdomainCoverage.value = res.coverage || null
  } catch (e: any) {
    // A failed request is not "no subdomains": say so and let the user retry.
    subdomains.value = []
    subdomainSources.value = {}
    subdomainCoverage.value = null
    subdomainsError.value = e?.message && e.message !== 'Unauthorized' ? e.message : 'The scan could not be completed.'
  } finally {
    subdomainsLoading.value = false
  }
}

async function addSubdomain(hostname: string) {
  addingSubdomain.value = hostname
  try {
    await api.wizardStart(hostname)
    await api.wizardConfirm(hostname)
    // Also record the disposition — without this, the recommendation
    // engine's gate (which checks subdomain_dispositions, not
    // already_monitored) would still treat this as undecided even though
    // it's now separately monitored.
    await api.setSubdomainDisposition(domainId, hostname, 'monitor')
    ui.toast(`${hostname} added — set it up from the Domains page`)
    const found = subdomains.value.find(s => s.hostname === hostname)
    if (found) { found.already_monitored = true; found.disposition = 'monitor' }
  } catch (e: any) {
    ui.toast(e.message || 'Failed to add domain')
  } finally {
    addingSubdomain.value = null
  }
}

const DISPOSITION_LABELS: Record<string, string> = { monitor: 'will monitor', exclude: 'excluded', inherited_sp: 'covered by sp=' }
function dispositionLabel(d: string): string { return DISPOSITION_LABELS[d] ?? d }

const excludeTarget = ref<string | null>(null)
const excludeReason = ref('')
const settingDisposition = ref<string | null>(null)

async function confirmExclude() {
  if (!excludeTarget.value || !excludeReason.value.trim()) return
  settingDisposition.value = excludeTarget.value
  try {
    await api.setSubdomainDisposition(domainId, excludeTarget.value, 'exclude', excludeReason.value.trim())
    const found = subdomains.value.find(s => s.hostname === excludeTarget.value)
    if (found) { found.disposition = 'exclude'; found.disposition_reason = excludeReason.value.trim() }
    ui.toast('Excluded')
  } catch (e: any) {
    ui.toast(e.message || 'Failed to exclude')
  } finally {
    settingDisposition.value = null
    excludeTarget.value = null
    excludeReason.value = ''
  }
}

async function setInheritedSp(hostname: string) {
  settingDisposition.value = hostname
  try {
    await api.setSubdomainDisposition(domainId, hostname, 'inherited_sp')
    const found = subdomains.value.find(s => s.hostname === hostname)
    if (found) found.disposition = 'inherited_sp'
    ui.toast('Marked as covered by sp=')
  } catch (e: any) {
    ui.toast(e.message || 'Failed to update')
  } finally {
    settingDisposition.value = null
  }
}

async function dismissRec(recId: string) {
  dismissing.value = recId
  try {
    await api.post(`/domains/${domainId}/dmarc/sender-recommendations/${recId}/dismiss`, {})
    senderRecs.value = senderRecs.value.filter((r: any) => r.id !== recId)
    ui.toast('Dismissed')
  } catch {
    ui.toast('Failed to dismiss')
  } finally {
    dismissing.value = null }
}

async function snoozeRec(recId: string) {
  dismissing.value = recId
  try {
    await api.post(`/domains/${domainId}/dmarc/sender-recommendations/${recId}/snooze?days=14`, {})
    senderRecs.value = senderRecs.value.filter((r: any) => r.id !== recId)
    ui.toast('Snoozed for 14 days')
  } catch {
    ui.toast('Failed to snooze')
  } finally {
    dismissing.value = null }
}

const CLASS_LABEL: Record<string, string> = {
  known_esp: 'Known ESP',
  unknown: 'Unknown sender',
  suspicious: 'Suspicious',
  tls_issue: 'TLS issue',
}
const CLASS_COLOR: Record<string, string> = {
  known_esp: 'var(--teal)',
  unknown: 'var(--warn)',
  suspicious: 'var(--bad)',
  tls_issue: '#9aa6ff',
}
const CLASS_BG: Record<string, string> = {
  known_esp: 'rgba(46,230,197,.1)',
  unknown: 'rgba(245,197,66,.1)',
  suspicious: 'rgba(255,77,109,.08)',
  tls_issue: 'rgba(91,92,240,.1)',
}
const FIX_LABEL: Record<string, string> = {
  tls_issue: 'Recommended action',
}

async function syncDns() {
  syncing.value = true
  try {
    await api.syncDomainDns(domainId)
    detail.value = await api.domain(domainId)
    ui.toast('DNS synced')
  } catch (e: any) {
    ui.toast(e.message || 'Sync failed')
  } finally {
    syncing.value = false }
}

function copyText(text: string, key: string) {
  navigator.clipboard.writeText(text)
  copied.value = key
  setTimeout(() => { copied.value = '' }, 1800)
}

function fmtDate(dt: string | null) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const DMARC_COLOR: Record<string, string> = {
  reject: 'var(--good)', quarantine: 'var(--warn)', monitor: 'var(--warn)', none: 'var(--bad)',
}
const MTA_COLOR: Record<string, string> = {
  enforce: 'var(--good)', testing: 'var(--warn)', none: 'var(--bad)',
}
</script>

<template>
  <div class="detail-view">

    <!-- Back nav -->
    <button class="back-btn" @click="router.push({ name: 'domains' })">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M19 12H5M12 5l-7 7 7 7"/>
      </svg>
      All domains
    </button>

    <div v-if="loading" class="loading-state">Loading domain…</div>

    <template v-else-if="detail">
      <!-- Header -->
      <div class="page-header">
        <div class="header-left">
          <div class="crumb">02 / Domains / {{ detail.domain }}</div>
          <h1>{{ detail.domain }}</h1>
          <span v-if="detail.ownership_verified" class="pill pill-good">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="pill-icon">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            Verified
          </span>
          <span v-else class="pill pill-warn">Unverified</span>
        </div>
        <div class="header-actions">
          <span class="last-checked" v-if="detail.last_checked_at">Last checked {{ fmtDate(detail.last_checked_at) }}</span>
          <button class="btn-secondary" :disabled="syncing" @click="syncDns">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: syncing }">
              <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
            </svg>
            {{ syncing ? 'Syncing…' : 'Sync DNS' }}
          </button>
        </div>
      </div>

      <!-- Status strip -->
      <div class="status-strip">
        <div class="status-item">
          <div class="status-label">DMARC stage</div>
          <div class="status-val" :style="`color:${DMARC_COLOR[detail.dmarc_stage] || 'var(--bad)'}`">
            {{ detail.dmarc_stage ? detail.dmarc_stage.charAt(0).toUpperCase() + detail.dmarc_stage.slice(1) : 'None' }}
          </div>
        </div>
        <div class="status-div" />
        <div class="status-item">
          <div class="status-label">Policy</div>
          <div class="status-val">{{ detail.dmarc_policy || '—' }}</div>
        </div>
        <div class="status-div" />
        <div class="status-item">
          <div class="status-label">PCT</div>
          <div class="status-val">{{ detail.dmarc_pct != null ? detail.dmarc_pct + '%' : '—' }}</div>
        </div>
        <div class="status-div" />
        <div class="status-item">
          <div class="status-label">MTA-STS</div>
          <div class="status-val" :style="`color:${MTA_COLOR[detail.mta_sts_stage] || 'var(--bad)'}`">
            {{ detail.mta_sts_stage ? detail.mta_sts_stage.charAt(0).toUpperCase() + detail.mta_sts_stage.slice(1) : 'None' }}
          </div>
        </div>
        <div class="status-div" />
        <div class="status-item">
          <div class="status-label">Added</div>
          <div class="status-val" style="font-size:12px">{{ fmtDate(detail.added_at) }}</div>
        </div>
      </div>

      <!-- Sender Actions (Step 3 AI) -->
      <div v-if="senderRecs.length > 0" class="sender-actions">
        <div class="sa-header">
          <div class="sa-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" class="sa-icon">
              <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
            </svg>
            Sender Actions
            <span class="sa-count">{{ senderRecs.length }}</span>
          </div>
          <AiBadge />
        </div>
        <div class="sa-grid">
          <div v-for="rec in senderRecs" :key="rec.id" class="sa-card"
            :class="`sa-card--${rec.classification}`">
            <div class="sa-card-top">
              <div class="sa-org">{{ rec.source_org }}</div>
              <span class="sa-badge"
                :style="`color:${CLASS_COLOR[rec.classification]};background:${CLASS_BG[rec.classification]};border-color:${CLASS_COLOR[rec.classification]}44`">
                {{ CLASS_LABEL[rec.classification] || rec.classification }}
              </span>
            </div>
            <p v-if="rec.source_ip" class="sa-ip">{{ rec.source_ip }}</p>
            <p class="sa-rec">{{ rec.recommendation }}</p>
            <div v-if="rec.dns_fix" class="sa-fix">
              <span class="sa-fix-label">{{ FIX_LABEL[rec.classification] ?? 'DNS action' }}</span>
              <span class="sa-fix-text">{{ rec.dns_fix }}</span>
            </div>
            <div class="sa-card-foot">
              <button class="sa-snooze" :disabled="dismissing === rec.id" @click="snoozeRec(rec.id)">
                Not now — remind me in 2 weeks
              </button>
              <button class="sa-dismiss" :disabled="dismissing === rec.id" @click="dismissRec(rec.id)">
                {{ dismissing === rec.id ? 'Dismissing…' : 'Dismiss' }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Sending platforms — declared (proactive) + detected (passive) -->
      <PlatformHealthMatrix :domain-id="domainId" />

      <!-- Discovered subdomains — passive sources always; bounded active DNS
           check + AXFR attempt also run once ownership is verified -->
      <div class="subdomain-card">
        <div class="sd-header">
          <div class="sd-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="#9aa6ff" stroke-width="2" class="sd-icon">
              <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
            </svg>
            Discovered subdomains
          </div>
          <button class="sd-scan-btn" :disabled="subdomainsLoading" @click="loadSubdomains">
            {{ subdomainsLoading ? 'Scanning…' : (subdomainsLoaded ? 'Scan again' : 'Scan for subdomains') }}
          </button>
        </div>

        <div v-if="!subdomainsLoaded" class="sd-empty">
          Checks Certificate Transparency logs, your own ingested DMARC data, and certificate
          SAN fields for subdomains of {{ detail.domain }}.
          <template v-if="detail.ownership_verified">
            Since ownership is verified, this also runs a small bounded DNS check
            (mail/smtp/webmail/autodiscover-style candidates only) and a quick zone-transfer attempt.
          </template>
          <template v-else>
            Active DNS checks unlock once ownership is verified — passive sources only until then.
          </template>
        </div>
        <div v-else-if="subdomainsLoading" class="sd-empty">Scanning passive sources — this can take up to half a minute…</div>
        <div v-else-if="subdomainsError" class="sd-empty sd-warn" role="alert">
          The scan failed: {{ subdomainsError }} This is not the same as "no subdomains found". Use Scan again to retry.
        </div>
        <div v-else-if="!subdomains.length" class="sd-empty">
          <template v-if="subdomainSources.ct === 'timed_out' || subdomainSources.ct === 'failed'">
            Nothing found, but the certificate log lookup {{ subdomainSources.ct === 'timed_out' ? 'timed out' : 'failed' }},
            so this result is incomplete. Use Scan again to retry.
          </template>
          <template v-else>No subdomains found from DMARC reports, certificate SANs or certificate logs.</template>
        </div>
        <template v-else>
          <div v-if="subdomainSources.dns_active === 'wildcard_filtered'" class="sd-note" role="status">
            This domain has a wildcard DNS record, so guessed names would all appear to exist. Guessed names that only match the wildcard were left out.
          </div>
          <div v-if="subdomainSources.ct === 'timed_out' || subdomainSources.ct === 'failed'" class="sd-note sd-warn" role="status">
            The certificate log lookup {{ subdomainSources.ct === 'timed_out' ? 'timed out' : 'failed' }}; this list may be missing subdomains. Use Scan again to retry.
          </div>
          <div v-if="subdomains.some(s => s.sends_mail)" class="sd-note">
            Subdomains that send mail and have no DMARC alignment of their own need attention first —
            those are listed before the rest.
          </div>
          <div class="sd-list">
            <div v-for="s in subdomains" :key="s.hostname" class="sd-row">
              <div class="sd-row-main">
                <span class="sd-host">{{ s.hostname }}</span>
                <span v-if="s.sends_mail" class="sd-tag sd-tag-mail">Sends mail · {{ s.mail_volume.toLocaleString() }}</span>
                <span v-for="src in s.sources" :key="src" class="sd-tag sd-tag-src">{{ src }}</span>
                <span v-if="s.disposition" class="sd-tag sd-tag-disposition" :title="s.disposition_reason || ''">
                  {{ dispositionLabel(s.disposition) }}
                </span>
              </div>

              <span v-if="s.already_monitored" class="sd-monitored">Already monitored</span>
              <div v-else-if="s.sends_mail && !s.disposition" class="sd-disposition-actions">
                <button class="sd-add-btn" :disabled="addingSubdomain === s.hostname" @click="addSubdomain(s.hostname)">
                  {{ addingSubdomain === s.hostname ? 'Adding…' : 'Monitor this' }}
                </button>
                <button class="sd-disp-btn" @click="excludeTarget = s.hostname">Exclude</button>
                <button class="sd-disp-btn" :disabled="settingDisposition === s.hostname" @click="setInheritedSp(s.hostname)">
                  Covered by sp=
                </button>
              </div>
              <button
                v-else-if="!s.sends_mail"
                class="sd-add-btn"
                :disabled="addingSubdomain === s.hostname"
                @click="addSubdomain(s.hostname)"
              >{{ addingSubdomain === s.hostname ? 'Adding…' : 'Monitor this' }}</button>
            </div>
          </div>
        </template>

        <!-- Subdomains nobody listed: covered by the parent policy, no scan needed -->
        <div v-if="subdomainsLoaded && !subdomainsLoading && subdomainCoverage" class="sd-coverage" :class="'sd-cov-' + subdomainCoverage.level">
          <strong>Subdomains not listed here</strong>
          <span>{{ subdomainCoverage.summary }}</span>
        </div>
      </div>

      <!-- Exclude reason modal — required, never a silent drop -->
      <Teleport to="body">
        <div v-if="excludeTarget" class="modal-overlay" @click.self="excludeTarget = null">
          <div class="modal-box small">
            <div class="mh"><span>Exclude {{ excludeTarget }}</span><button class="mx" @click="excludeTarget = null">✕</button></div>
            <p class="exclude-hint">Why is this subdomain excluded from enforcement readiness? This is recorded, not silently dropped.</p>
            <textarea v-model="excludeReason" class="exclude-textarea" placeholder="e.g. decommissioned, intentionally third-party, no longer sends mail"></textarea>
            <div class="exclude-actions">
              <button class="btn ghost" @click="excludeTarget = null">Cancel</button>
              <button class="btn" :disabled="!excludeReason.trim()" @click="confirmExclude">Confirm exclusion</button>
            </div>
          </div>
        </div>
      </Teleport>

      <!-- Records grid -->
      <div class="records-grid">

        <!-- DMARC record -->
        <div class="record-card">
          <div class="rc-header">
            <div class="rc-title">
              <div class="rc-dot" style="background:#5b5cf0" />
              DMARC record
            </div>
            <span class="pub-badge" :class="detail.dmarc_record_published ? 'pub-yes' : 'pub-no'">
              {{ detail.dmarc_record_published ? 'Published' : 'Not published' }}
            </span>
          </div>

          <div v-if="dmarcInfo" class="dns-block">
            <div class="dns-row">
              <div class="dns-field-label">Host</div>
              <div class="dns-copy-row">
                <code class="dns-val">{{ dmarcInfo.record_host }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(dmarcInfo.record_host, 'dmarc-host')">
                  <svg v-if="copied !== 'dmarc-host'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Type</div>
              <code class="dns-val">TXT</code>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Value</div>
              <div class="dns-copy-row dns-copy-row-wrap">
                <code class="dns-val dns-val-wrap">{{ dmarcInfo.generated_record }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(dmarcInfo.generated_record, 'dmarc-val')">
                  <svg v-if="copied !== 'dmarc-val'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div v-if="dmarcInfo.current_record" class="dns-row">
              <div class="dns-field-label">Current DNS</div>
              <code class="dns-val dns-val-muted">{{ dmarcInfo.current_record }}</code>
            </div>
          </div>

          <div class="rua-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Reports sent to <code class="inline-code">{{ detail.reporting_address }}</code>
            <button class="copy-btn-inline" aria-label="Copy to clipboard" @click="copyText(detail.reporting_address, 'rua')">
              <svg v-if="copied !== 'rua'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            </button>
          </div>
        </div>

        <!-- TLSRPT record -->
        <div class="record-card">
          <div class="rc-header">
            <div class="rc-title">
              <div class="rc-dot" style="background:#2ee6c5" />
              TLS-RPT record
            </div>
            <span class="pub-badge" :class="detail.tlsrpt_record_published ? 'pub-yes' : 'pub-no'">
              {{ detail.tlsrpt_record_published ? 'Published' : 'Not published' }}
            </span>
          </div>

          <div v-if="tlsInfo" class="dns-block">
            <div class="dns-row">
              <div class="dns-field-label">Host</div>
              <div class="dns-copy-row">
                <code class="dns-val">{{ tlsInfo.tlsrpt_host }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.tlsrpt_host, 'tlsrpt-host')">
                  <svg v-if="copied !== 'tlsrpt-host'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Type</div>
              <code class="dns-val">TXT</code>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Value</div>
              <div class="dns-copy-row dns-copy-row-wrap">
                <code class="dns-val dns-val-wrap">{{ tlsInfo.tlsrpt_record }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.tlsrpt_record, 'tlsrpt-val')">
                  <svg v-if="copied !== 'tlsrpt-val'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- MTA-STS DNS record -->
        <div class="record-card">
          <div class="rc-header">
            <div class="rc-title">
              <div class="rc-dot" style="background:#8b5cf6" />
              MTA-STS DNS record
            </div>
            <span class="pub-badge" :class="detail.mta_sts_published ? 'pub-yes' : 'pub-no'">
              {{ detail.mta_sts_published ? 'Published' : 'Not published' }}
            </span>
          </div>

          <div v-if="tlsInfo" class="dns-block">
            <div class="dns-row">
              <div class="dns-field-label">Host</div>
              <div class="dns-copy-row">
                <code class="dns-val">{{ tlsInfo.mta_sts_dns_host }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.mta_sts_dns_host, 'mta-host')">
                  <svg v-if="copied !== 'mta-host'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Type</div>
              <code class="dns-val">TXT</code>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Value</div>
              <div class="dns-copy-row dns-copy-row-wrap">
                <code class="dns-val dns-val-wrap">{{ tlsInfo.mta_sts_dns_record }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.mta_sts_dns_record, 'mta-val')">
                  <svg v-if="copied !== 'mta-val'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- MTA-STS policy file -->
        <div class="record-card" v-if="tlsInfo">
          <div class="rc-header">
            <div class="rc-title">
              <div class="rc-dot" style="background:#8b5cf6" />
              MTA-STS policy file
            </div>
            <span class="pub-badge pub-info">HTTPS</span>
          </div>

          <div class="dns-block">
            <div class="dns-row">
              <div class="dns-field-label">URL</div>
              <div class="dns-copy-row">
                <code class="dns-val" style="font-size:11px">{{ tlsInfo.policy_url }}</code>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.policy_url, 'policy-url')">
                  <svg v-if="copied !== 'policy-url'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div class="dns-row">
              <div class="dns-field-label">Policy ID</div>
              <code class="dns-val">{{ detail.mta_sts_policy_id || '—' }}</code>
            </div>
            <div class="dns-row dns-row-top">
              <div class="dns-field-label">Content</div>
              <div class="dns-copy-row dns-copy-row-wrap">
                <pre class="dns-val dns-val-pre">{{ tlsInfo.mta_sts_policy }}</pre>
                <button class="copy-btn" aria-label="Copy to clipboard" @click="copyText(tlsInfo.mta_sts_policy, 'policy-body')">
                  <svg v-if="copied !== 'policy-body'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                </button>
              </div>
            </div>
            <div class="policy-note">
              Host this file at the URL above with Content-Type <code class="inline-code">text/plain</code>.
            </div>
          </div>
        </div>

      </div>

      <!-- Quick links -->
      <div class="quick-links">
        <button class="ql-btn" @click="router.push({ name: 'dmarc', query: { domain: detail.domain } })">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
          </svg>
          DMARC analytics
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="ql-arrow">
            <path d="M9 18l6-6-6-6"/>
          </svg>
        </button>
        <button class="ql-btn" @click="router.push({ name: 'tls', query: { domain: detail.domain } })">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          MTA-STS & TLS analytics
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="ql-arrow">
            <path d="M9 18l6-6-6-6"/>
          </svg>
        </button>
        <button class="ql-btn" @click="router.push({ name: 'certs' })">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="8" r="6"/><path d="M9 13l-2 8 5-3 5 3-2-8"/>
          </svg>
          Certificate health
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="ql-arrow">
            <path d="M9 18l6-6-6-6"/>
          </svg>
        </button>
      </div>

    </template>
  </div>
</template>

<style scoped>
.detail-view { max-width: 1080px; }

.back-btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: none; border: none; color: var(--muted); font-size: 13px;
  cursor: pointer; padding: 0; margin-bottom: 20px; transition: color .15s;
}
.back-btn:hover { color: var(--txt); }
.back-btn svg { width: 15px; height: 15px; }

/* ── Header ───────────────────────────────────────────────────────────── */
.page-header {
  display: flex; align-items: flex-end; justify-content: space-between;
  margin-bottom: 20px; gap: 16px; flex-wrap: wrap;
}
.header-left { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
.header-actions { display: flex; align-items: center; gap: 12px; }
.crumb { font-family: var(--mono); font-size: 10px; letter-spacing: 1px; color: var(--faint); text-transform: uppercase; width: 100%; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 26px; margin: 0; letter-spacing: -.4px; }
.last-checked { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }

.pill {
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  padding: 3px 10px; border-radius: 20px;
}
.pill-icon { width: 10px; height: 10px; }
.pill-good { background: rgba(52,224,161,.12); color: var(--good); border: 1px solid rgba(52,224,161,.25); }
.pill-warn { background: rgba(245,197,66,.10); color: var(--warn); border: 1px solid rgba(245,197,66,.2); }

.btn-secondary {
  display: flex; align-items: center; gap: 7px;
  background: rgba(255,255,255,.06); border: 1px solid var(--line2);
  border-radius: 11px; padding: 9px 16px; color: var(--muted);
  font-family: var(--disp); font-weight: 600; font-size: 13px; cursor: pointer; transition: .15s;
}
.btn-secondary svg { width: 14px; height: 14px; }
.btn-secondary:hover { color: var(--txt); border-color: var(--indigo); }
.btn-secondary:disabled { opacity: .5; cursor: not-allowed; }

/* ── Status strip ─────────────────────────────────────────────────────── */
.status-strip {
  display: flex; align-items: center; flex-wrap: wrap;
  background: var(--glass); border: 1px solid var(--line2); border-radius: 14px;
  padding: 14px 20px; margin-bottom: 22px; gap: 0;
}
.status-item { padding: 0 16px; display: flex; flex-direction: column; gap: 4px; }
.status-label { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .6px; color: var(--faint); }
.status-val { font-family: var(--mono); font-size: 13px; font-weight: 700; color: var(--txt); }
.status-div { width: 1px; height: 30px; background: var(--line); }

/* ── Sender Actions ───────────────────────────────────────────────────── */
.sender-actions {
  margin-bottom: 22px;
  background: var(--glass); border: 1px solid var(--line2); border-radius: 16px;
  padding: 18px 20px;
}

.sa-header {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;
}
.sa-title {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--disp); font-weight: 700; font-size: 14px; color: var(--txt);
}
.sa-icon { width: 15px; height: 15px; flex: none; }
.sa-count {
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  background: rgba(46,230,197,.12); color: var(--teal); border: 1px solid rgba(46,230,197,.25);
  padding: 2px 7px; border-radius: 20px;
}

.sa-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;
}

.sa-card {
  background: rgba(0,0,0,.18); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 16px; display: flex; flex-direction: column; gap: 8px;
}
.sa-card--suspicious { border-color: rgba(255,77,109,.3); }
.sa-card--unknown    { border-color: rgba(245,197,66,.2); }

.sa-card-top {
  display: flex; align-items: flex-start; justify-content: space-between; gap: 10px;
}
.sa-org {
  font-family: var(--mono); font-size: 12.5px; font-weight: 700; color: var(--txt);
  word-break: break-all;
}
.sa-badge {
  flex: none; font-family: var(--mono); font-size: 9px; font-weight: 700;
  padding: 3px 8px; border-radius: 20px; border: 1px solid transparent; white-space: nowrap;
}
.sa-ip { margin: 0; font-family: var(--mono); font-size: 10px; color: var(--faint); }
.sa-rec { margin: 0; font-size: 12px; color: var(--muted); line-height: 1.55; }

.sa-fix {
  background: rgba(91,92,240,.07); border: 1px solid rgba(91,92,240,.15);
  border-radius: 8px; padding: 8px 10px; display: flex; flex-direction: column; gap: 3px;
}
.sa-fix-label { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .5px; color: var(--indigo); }
.sa-fix-text { font-size: 11.5px; color: var(--muted); line-height: 1.5; }

.sa-card-foot { display: flex; justify-content: flex-end; gap: 8px; margin-top: 2px; }
.sa-dismiss {
  background: none; border: 1px solid var(--line2); border-radius: 8px;
  padding: 5px 12px; font-size: 11.5px; color: var(--faint); cursor: pointer; transition: .15s;
}
.sa-dismiss:hover { color: var(--txt); border-color: var(--indigo); }
.sa-dismiss:disabled { opacity: .5; cursor: not-allowed; }
.sa-snooze {
  background: none; border: 1px solid var(--line2); border-radius: 8px;
  padding: 5px 12px; font-size: 11.5px; color: #9aa6ff; cursor: pointer; transition: .15s;
}
.sa-snooze:hover { border-color: #9aa6ff; }
.sa-snooze:disabled { opacity: .5; cursor: not-allowed; }

/* ── Discovered subdomains ───────────────────────────────────────────── */
.sd-warn { color: #f3c969; }
.sd-coverage { margin-top: 14px; padding: 10px 14px; border-radius: 10px; font-size: 12.5px; display: flex; flex-direction: column; gap: 2px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--muted); }
.sd-coverage strong { color: var(--txt); font-weight: 600; }
.sd-cov-protected { border-color: rgba(60, 200, 150, .45); }
.sd-cov-partial { border-color: rgba(243, 201, 105, .5); }
.sd-cov-open { border-color: rgba(240, 90, 90, .5); }
.subdomain-card {
  background: var(--glass); border: 1px solid var(--line2); border-radius: 16px;
  padding: 18px 20px; margin-bottom: 20px;
}
.sd-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
.sd-title { display: flex; align-items: center; gap: 9px; font-family: var(--disp); font-weight: 700; font-size: 14px; }
.sd-icon { width: 16px; height: 16px; flex: none; }
.sd-scan-btn {
  background: rgba(91,92,240,.12); border: 1px solid rgba(91,92,240,.3); color: #9aa6ff;
  border-radius: 10px; padding: 7px 14px; font-family: var(--disp); font-weight: 700;
  font-size: 12px; cursor: pointer; transition: .15s;
}
.sd-scan-btn:hover:not(:disabled) { background: rgba(91,92,240,.2); }
.sd-scan-btn:disabled { opacity: .6; cursor: not-allowed; }
.sd-empty { font-size: 12.5px; color: var(--muted); line-height: 1.6; }
.sd-note { font-size: 11.5px; color: var(--amber); line-height: 1.5; margin-bottom: 10px; }
.sd-list { display: flex; flex-direction: column; gap: 8px; }
.sd-row {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 9px 12px; border-radius: 10px; background: rgba(255,255,255,.025);
  border: 1px solid var(--line); flex-wrap: wrap;
}
.sd-row-main { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.sd-host { font-family: var(--mono); font-size: 12px; color: var(--txt); }
.sd-tag {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .3px;
  padding: 2px 8px; border-radius: 6px; flex: none;
}
.sd-tag-mail { background: rgba(245,197,66,.14); color: var(--amber); }
.sd-tag-src  { background: rgba(255,255,255,.06); color: var(--faint); text-transform: uppercase; }
.sd-add-btn {
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: none;
  border-radius: 9px; padding: 6px 13px; font-family: var(--disp); font-weight: 700;
  font-size: 11.5px; cursor: pointer; flex: none;
}
.sd-add-btn:disabled { opacity: .6; cursor: not-allowed; }
.sd-monitored { font-family: var(--mono); font-size: 10.5px; color: var(--good); flex: none; }
.sd-tag-disposition { background: rgba(91,92,240,.14); color: #9aa6ff; }
.sd-disposition-actions { display: flex; gap: 6px; flex: none; }
.sd-disp-btn {
  background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--muted);
  border-radius: 9px; padding: 6px 12px; font-size: 11px; cursor: pointer;
}
.sd-disp-btn:hover { border-color: var(--indigo); color: var(--txt); }
.sd-disp-btn:disabled { opacity: .6; cursor: not-allowed; }

/* ── Exclude reason modal ─────────────────────────────────────────────── */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 300; display: grid; place-items: center; padding: 20px; }
.modal-box { width: 480px; max-width: 94vw; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 18px; padding: 22px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.mh { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.mh span { font-family: var(--disp); font-weight: 800; font-size: 15px; }
.mx { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 26px; height: 26px; cursor: pointer; font-size: 13px; }
.exclude-hint { font-size: 12px; color: var(--muted); line-height: 1.5; margin-bottom: 10px; }
.exclude-textarea {
  width: 100%; min-height: 70px; background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 9px; padding: 10px 12px; font-size: 12.5px; color: var(--txt); outline: none;
  resize: vertical; font-family: var(--body); margin-bottom: 12px;
}
.exclude-textarea:focus { border-color: var(--indigo); }
.exclude-actions { display: flex; justify-content: flex-end; gap: 10px; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none; border-radius: 11px; padding: 9px 16px; font-family: var(--disp); font-weight: 700; font-size: 12.5px; cursor: pointer; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); box-shadow: none; }
.btn:disabled { opacity: .6; cursor: not-allowed; }

/* ── Records grid ─────────────────────────────────────────────────────── */
.records-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px; }
@media (max-width: 860px) { .records-grid { grid-template-columns: 1fr; } }

.record-card {
  background: var(--glass); border: 1px solid var(--line2); border-radius: 16px; padding: 18px 20px;
}
.rc-header {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;
}
.rc-title {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--disp); font-weight: 700; font-size: 13.5px;
}
.rc-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }

.pub-badge {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .3px;
  padding: 3px 9px; border-radius: 20px;
}
.pub-yes  { background: rgba(52,224,161,.1); color: var(--good); border: 1px solid rgba(52,224,161,.2); }
.pub-no   { background: rgba(255,77,109,.08); color: var(--bad);  border: 1px solid rgba(255,77,109,.2); }
.pub-info { background: rgba(91,92,240,.1); color: var(--indigo); border: 1px solid rgba(91,92,240,.2); }

.dns-block { display: flex; flex-direction: column; gap: 10px; }
.dns-row { display: flex; align-items: flex-start; gap: 10px; }
.dns-row-top { align-items: flex-start; }
.dns-field-label {
  font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .5px;
  color: var(--faint); min-width: 52px; padding-top: 2px; flex: none;
}
.dns-copy-row {
  flex: 1; display: flex; align-items: center; gap: 8px;
  background: rgba(0,0,0,.2); border: 1px solid var(--line); border-radius: 8px; padding: 7px 10px;
}
.dns-copy-row-wrap { align-items: flex-start; }
.dns-val {
  flex: 1; font-family: var(--mono); font-size: 11.5px; color: var(--teal);
  word-break: break-all; line-height: 1.5;
}
.dns-val-wrap { white-space: pre-wrap; }
.dns-val-muted { color: var(--faint); font-size: 10.5px; }
.dns-val-pre { margin: 0; font-family: var(--mono); font-size: 11px; color: var(--teal); white-space: pre; line-height: 1.6; }

.copy-btn {
  flex: none; display: grid; place-items: center;
  background: rgba(255,255,255,.07); border: 1px solid var(--line2);
  border-radius: 6px; padding: 4px 6px; cursor: pointer; transition: .15s; align-self: flex-start;
}
.copy-btn:hover { border-color: var(--indigo); }
.copy-btn svg { width: 12px; height: 12px; }

.inline-code {
  font-family: var(--mono); font-size: 11px; color: var(--teal);
  background: rgba(46,230,197,.08); padding: 1px 5px; border-radius: 4px;
}

.rua-note {
  display: flex; align-items: center; gap: 7px; flex-wrap: wrap;
  margin-top: 12px; padding: 10px 12px;
  background: rgba(46,230,197,.05); border: 1px solid rgba(46,230,197,.12); border-radius: 8px;
  font-size: 11.5px; color: var(--muted);
}
.rua-note svg { width: 14px; height: 14px; flex: none; }

.copy-btn-inline {
  background: none; border: none; cursor: pointer; color: var(--faint);
  display: grid; place-items: center; padding: 2px; transition: .15s;
}
.copy-btn-inline:hover { color: var(--teal); }
.copy-btn-inline svg { width: 12px; height: 12px; }

.policy-note { font-size: 11px; color: var(--faint); margin-top: 6px; line-height: 1.5; }

/* ── Quick links ──────────────────────────────────────────────────────── */
.quick-links { display: flex; gap: 10px; flex-wrap: wrap; }
.ql-btn {
  display: flex; align-items: center; gap: 8px; flex: 1; min-width: 180px;
  background: var(--glass); border: 1px solid var(--line2); border-radius: 12px;
  padding: 12px 16px; color: var(--muted); font-size: 13px; cursor: pointer; transition: .15s;
}
.ql-btn svg { width: 15px; height: 15px; flex: none; }
.ql-btn:hover { color: var(--txt); border-color: var(--indigo); background: rgba(91,92,240,.06); }
.ql-arrow { margin-left: auto; opacity: .4; }

/* ── Misc ─────────────────────────────────────────────────────────────── */
.loading-state { padding: 48px; text-align: center; color: var(--muted); font-size: 13px; }

.spin { animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
