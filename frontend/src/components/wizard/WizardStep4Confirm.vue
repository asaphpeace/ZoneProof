<script setup lang="ts">
import { ref, computed } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import GateChecklist from '@/components/ui/GateChecklist.vue'

const props = defineProps<{ tlsResults: any[] }>()
const emit  = defineEmits<{ confirmed: [domains: string[]]; cancel: [] }>()

const domains = useDomainsStore()
const ui      = useUiStore()

const loading = ref(false)
const error   = ref('')

const newDomains      = computed(() => props.tlsResults.filter(r => !r.already_exists))
const reOnboardDomains = computed(() => props.tlsResults.filter(r => r.already_exists))

async function confirm() {
  loading.value = true
  error.value = ''
  try {
    for (const r of props.tlsResults) {
      await api.wizardConfirm(r.domain)
    }
    await domains.fetch()

    // Apply the hosting-mode choice from WizardStep3Tls now that domains
    // have real, activated IDs — same reason the platform declaration is
    // deferred to after this point.
    for (const r of props.tlsResults) {
      if (r.hostingMode === 'managed') {
        const dom = domains.list.find((d: any) => d.domain === r.domain)
        if (dom) await api.setMtaStsHostingMode(dom.id, 'managed')
      }
    }

    const n = newDomains.value.length
    const re = reOnboardDomains.value.length
    const parts = []
    if (n)  parts.push(`${n} domain${n > 1 ? 's' : ''} added`)
    if (re) parts.push(`${re} re-onboarded`)
    ui.toast(parts.join(' · ') + ' successfully')
    // Domains are now active and have real IDs — this is the right moment
    // to ask "which platforms send mail for these," not before (the
    // platform-declare endpoint needs a real, activated domain to attach
    // to). Still fully proactive: no DMARC data exists yet either way.
    emit('confirmed', props.tlsResults.map(r => r.domain))
  } catch (e: any) {
    error.value = e.message || 'Failed to save domains'
  } finally { loading.value = false }
}

const gates = (r: any) => [
  { label: 'DMARC record published', ok: r.dmarc_exists || false },
  { label: 'TLS-RPT record published', ok: false },
  { label: 'MTA-STS DNS record published', ok: false },
  { label: 'Policy file hosted', ok: false },
]
</script>

<template>
  <div>
    <div class="sh">Review & confirm</div>
    <p class="hint">Review the setup summary. DNS records can be published after — the Roadmap will guide you step by step.</p>

    <!-- New domains -->
    <template v-if="newDomains.length">
      <div class="section-hdr">
        <span class="dot new" />New domains <span class="count">{{ newDomains.length }}</span>
      </div>
      <div v-for="r in newDomains" :key="r.domain" class="domain-block">
        <div class="dh">{{ r.domain }}</div>
        <div class="sum-row"><span class="fl">Reporting address</span><span class="fm">{{ r.reporting_address }}</span></div>
        <div class="sum-row">
          <span class="fl">DMARC record</span>
          <span class="stat" :class="r.dmarc_exists ? 'ok' : 'warn'">{{ r.dmarc_exists ? 'Existing' : 'Generated — needs publishing' }}</span>
        </div>
        <div class="sum-row"><span class="fl">TLS-RPT</span><span class="stat warn">Needs publishing</span></div>
        <div class="sum-row"><span class="fl">MTA-STS</span><span class="stat warn">Needs publishing</span></div>
        <div style="margin-top:14px"><GateChecklist :gates="gates(r)" /></div>
      </div>
    </template>

    <!-- Re-onboarded domains -->
    <template v-if="reOnboardDomains.length">
      <div class="section-hdr">
        <span class="dot existing" />Re-onboarding <span class="count">{{ reOnboardDomains.length }}</span>
      </div>
      <div v-for="r in reOnboardDomains" :key="r.domain" class="domain-block existing-block">
        <div class="dh">{{ r.domain }} <span class="rebadge">Re-onboard</span></div>
        <div class="sum-row"><span class="fl">Reporting address</span><span class="fm">{{ r.reporting_address }}</span></div>
        <div class="sum-row"><span class="fl">DMARC status</span><span class="stat ok">Already active</span></div>
      </div>
    </template>

    <div v-if="error" class="error-box">{{ error }}</div>

    <div class="notice">
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" style="width:16px;height:16px;flex:none;margin-top:2px"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      Domains are activated immediately. The Roadmap shows what DNS records still need publishing.
    </div>

    <div class="actions">
      <button class="btn ghost" @click="emit('cancel')">Back</button>
      <button class="btn" :disabled="loading" @click="confirm">
        {{ loading ? 'Saving…' : `Confirm ${tlsResults.length} domain${tlsResults.length !== 1 ? 's' : ''}` }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 18px; margin-bottom: 8px; }
.hint { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 14px; }

.section-hdr { display: flex; align-items: center; gap: 8px; font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); margin: 14px 0 10px; }
.dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.dot.new { background: var(--teal); }
.dot.existing { background: var(--amber); }
.count { background: rgba(255,255,255,.08); border-radius: 20px; padding: 1px 7px; font-size: 9px; }

.domain-block { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin-bottom: 12px; }
.existing-block { border-color: rgba(255,190,0,.2); background: rgba(255,190,0,.04); }
.dh { font-family: var(--mono); font-size: 13px; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.rebadge { font-size: 9px; text-transform: uppercase; letter-spacing: .6px; padding: 2px 7px; background: rgba(255,190,0,.15); border: 1px solid rgba(255,190,0,.3); border-radius: 20px; color: var(--amber); }

.sum-row { display: flex; align-items: center; gap: 12px; margin-bottom: 9px; }
.fl { font-family: var(--mono); font-size: 10px; color: var(--faint); text-transform: uppercase; letter-spacing: .6px; min-width: 140px; }
.fm { font-family: var(--mono); font-size: 11.5px; color: var(--teal); }
.stat { font-family: var(--mono); font-size: 11px; }
.stat.ok { color: var(--good); }
.stat.warn { color: var(--amber); }

.error-box { padding: 12px 16px; background: rgba(255,80,80,.07); border: 1px solid rgba(255,80,80,.25); border-radius: 12px; font-size: 13px; color: var(--bad); margin-bottom: 12px; }
.notice { display: flex; gap: 10px; padding: 13px 15px; background: rgba(46,230,197,.07); border: 1px solid rgba(46,230,197,.25); border-radius: 12px; font-size: 12.5px; color: var(--muted); line-height: 1.6; margin-top: 8px; }
.actions { margin-top: 20px; display: flex; justify-content: flex-end; gap: 10px; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:11px 24px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); }
.btn:disabled { opacity:.6; cursor:not-allowed; }
</style>
