<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'

// PAIN_POINT_RESOLUTION_PLAN.md Pain 5 — two independent live checks, not
// assumptions: does the CNAME actually resolve to ZoneProof's hosting
// target, and does a real HTTPS fetch of the policy succeed right now.
const props = defineProps<{ domainId: string }>()
const ui = useUiStore()

const status = ref<any>(null)
const loading = ref(true)
const switching = ref(false)

async function load() {
  loading.value = true
  try {
    status.value = await api.mtaStsHostingStatus(props.domainId)
  } finally {
    loading.value = false
  }
}

watch(() => props.domainId, load)
onMounted(load)

async function switchToManaged() {
  switching.value = true
  try {
    await api.setMtaStsHostingMode(props.domainId, 'managed')
    ui.toast('Switched to ZoneProof-hosted — publish the CNAME shown below')
    await load()
  } finally {
    switching.value = false
  }
}

async function switchToSelf() {
  switching.value = true
  try {
    await api.setMtaStsHostingMode(props.domainId, 'self')
    ui.toast('Switched to self-hosted')
    await load()
  } finally {
    switching.value = false
  }
}
</script>

<template>
  <div v-if="!loading && status" class="hosting-status">
    <div class="hs-row">
      <span class="hs-label">MTA-STS hosting</span>
      <span class="hs-mode" :class="status.hosting_mode">{{ status.hosting_mode === 'managed' ? 'ZoneProof-hosted' : 'Self-hosted' }}</span>
      <button class="hs-refresh" @click="load">↻ Check now</button>
    </div>

    <!-- Diagnosis — shown for BOTH modes now. Previously self-hosted domains
         got nothing at all here, even though the backend already computed
         this; and even for managed mode, a single "not fetchable yet"
         boolean couldn't tell "no subdomain" apart from "a host exists but
         nothing answers HTTPS" (e.g. pointed at a mail gateway like
         Mimecast that has no web server) apart from "HTTPS works but the
         cert covers someone else's domain". -->
    <div class="hs-diagnosis" :class="status.diagnosis === 'live' ? 'ok' : status.diagnosis === 'no_dns' ? 'neutral' : 'bad'">
      <span class="hs-diagnosis-icon">{{ status.diagnosis === 'live' ? '✓' : status.diagnosis === 'no_dns' ? '○' : '✗' }}</span>
      <span class="hs-diagnosis-text">{{ status.diagnosis_message }}</span>
    </div>
    <p v-if="status.diagnosis === 'dns_no_https'" class="hs-hint hs-hint-callout">
      Note: this is unrelated to your mail server's own SMTP/STARTTLS support (port 25) — that's a
      separate service used for delivering mail, not for serving this policy file over HTTPS (port 443).
    </p>
    <p v-if="status.cert_san" class="hs-hint mono-hint">
      Certificate actually covers: <code>{{ status.cert_san }}</code>
    </p>

    <template v-if="status.hosting_mode === 'managed'">
      <div class="hs-checks">
        <span class="hs-check" :class="status.cname_correct ? 'ok' : 'bad'">
          {{ status.cname_correct ? '✓' : '✗' }} CNAME {{ status.cname_correct ? 'correctly points to' : 'does not point to' }} {{ status.cname_target }}
        </span>
      </div>
      <p v-if="!status.cname_correct" class="hs-hint">
        Publish a CNAME at <code>mta-sts.&lt;your domain&gt;</code> pointing to <code>{{ status.cname_target }}</code>.
        DNS changes can take a while to propagate — this isn't necessarily a misconfiguration yet.
      </p>
      <button class="hs-switch" :disabled="switching" @click="switchToSelf">Switch to self-hosted instead</button>
    </template>
    <template v-else>
      <button class="hs-switch primary" :disabled="switching" @click="switchToManaged">
        Switch to ZoneProof-hosted — no server needed
      </button>
    </template>
  </div>
</template>

<style scoped>
.hosting-status {
  background: var(--glass); border: 1px solid var(--line2); border-radius: 14px;
  padding: 14px 16px; margin-bottom: 14px;
}
.hs-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.hs-label { font-family: var(--mono); font-size: 9.5px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); }
.hs-mode { font-family: var(--disp); font-weight: 700; font-size: 12.5px; padding: 2px 9px; border-radius: 8px; }
.hs-mode.managed { background: rgba(46,230,197,.14); color: var(--teal); }
.hs-mode.self { background: rgba(255,255,255,.06); color: var(--muted); }
.hs-refresh { margin-left: auto; background: none; border: 1px solid var(--line2); border-radius: 8px; color: var(--muted); padding: 4px 10px; font-size: 10.5px; cursor: pointer; }
.hs-refresh:hover { border-color: var(--indigo); color: var(--txt); }

.hs-checks { display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px; }
.hs-check { font-family: var(--mono); font-size: 11px; }
.hs-check.ok { color: var(--good); }
.hs-check.bad { color: var(--amber); }

.hs-diagnosis { display: flex; gap: 8px; align-items: flex-start; padding: 10px 12px; border-radius: 10px; margin-bottom: 8px; font-size: 12px; line-height: 1.55; }
.hs-diagnosis.ok { background: rgba(46,230,197,.1); color: var(--good); }
.hs-diagnosis.bad { background: rgba(255,77,109,.08); color: var(--bad); }
.hs-diagnosis.neutral { background: rgba(255,255,255,.04); color: var(--muted); }
.hs-diagnosis-icon { flex: none; font-family: var(--mono); }
.hs-diagnosis-text { flex: 1; }

.hs-hint { font-size: 11px; color: var(--faint); line-height: 1.5; margin: 0 0 10px; }
.hs-hint code { color: #9aa6ff; background: rgba(91,92,240,.1); padding: 1px 5px; border-radius: 4px; }
.hs-hint-callout { padding: 8px 10px; background: rgba(91,92,240,.06); border-radius: 8px; }
.mono-hint { font-family: var(--mono); }

.hs-switch {
  background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--muted);
  border-radius: 9px; padding: 7px 13px; font-size: 11.5px; cursor: pointer;
}
.hs-switch.primary { background: rgba(46,230,197,.12); border-color: rgba(46,230,197,.3); color: var(--teal); font-weight: 700; }
.hs-switch:disabled { opacity: .6; cursor: not-allowed; }
</style>
