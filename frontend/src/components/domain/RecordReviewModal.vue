<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import DiffBlock from '@/components/ui/DiffBlock.vue'
import GateChecklist from '@/components/ui/GateChecklist.vue'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import { useUiStore } from '@/stores/ui'
import { api } from '@/api/client'

const props = defineProps<{ diff: any; domainId: string; track: 'dmarc' | 'tls' }>()
const emit = defineEmits<{ close: [] }>()
const ui = useUiStore()

function close() {
  emit('close')
  ui.closeModal()
}

async function markPublished() {
  if (props.track === 'dmarc') await api.dmarcMarkPublished(props.domainId)
  else await api.tlsMarkPublished(props.domainId)
  ui.toast('Marked as published — logged to the DNS timeline')
  close()
}

function copyRecord() {
  navigator.clipboard.writeText(props.diff.proposed)
  ui.toast('Record copied to clipboard')
}

// ── DNS hand-holding (GUIDED_ONBOARDING_PLAN.md Part 1 Phase 1) ──────────────
// Which record_type the backend's check-dns-live / email-instructions
// endpoints expect — derived from the record host since the `track` prop
// only distinguishes dmarc vs. tls, not mta-sts vs. tlsrpt within tls.
const recordType = computed<'dmarc' | 'mta-sts' | 'tlsrpt'>(() => {
  if (props.track === 'dmarc') return 'dmarc'
  return (props.diff?.host || '').startsWith('_mta-sts.') ? 'mta-sts' : 'tlsrpt'
})

const registrar = ref<any>(null)
const registrarLoading = ref(true)
const showSteps = ref(false)

const detected = ref(false)
const polling = ref(false)
let pollHandle: ReturnType<typeof setInterval> | null = null
let pollCount = 0
const MAX_POLLS = 120  // ~10 minutes at 5s intervals — stop silently after that, don't poll forever

const showEmailForm = ref(false)
const emailTo = ref('')
const emailSending = ref(false)
const emailSent = ref(false)

onMounted(async () => {
  try {
    registrar.value = await api.registrarInstructions(props.domainId)
  } catch {
    registrar.value = null
  } finally {
    registrarLoading.value = false
  }
  startPolling()
})

onUnmounted(() => {
  if (pollHandle) clearInterval(pollHandle)
})

function startPolling() {
  if (detected.value) return
  polling.value = true
  pollHandle = setInterval(async () => {
    pollCount++
    if (pollCount > MAX_POLLS) {
      if (pollHandle) clearInterval(pollHandle)
      polling.value = false
      return
    }
    try {
      const result = await api.checkDnsLive(props.domainId, recordType.value)
      if (result.exists) {
        detected.value = true
        polling.value = false
        if (pollHandle) clearInterval(pollHandle)
      }
    } catch { /* transient — next poll will retry */ }
  }, 5000)
}

async function sendInstructionsEmail() {
  if (!emailTo.value) return
  emailSending.value = true
  try {
    await api.emailInstructions(props.domainId, emailTo.value, recordType.value)
    emailSent.value = true
    ui.toast(`Instructions sent to ${emailTo.value}`)
  } catch (e: any) {
    ui.toast(e.message || 'Failed to send')
  } finally {
    emailSending.value = false
  }
}
</script>

<template>
  <div>
    <!-- Live detection banner -->
    <div v-if="detected" class="detect-banner detect-good">
      <span class="detect-icon">✓</span>
      <span>Detected! This record is now live in DNS.</span>
    </div>
    <div v-else-if="polling" class="detect-banner detect-wait">
      <span class="detect-pulse" />
      <span>Watching DNS — this updates automatically the moment your change goes live.</span>
    </div>

    <div style="font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin-bottom:8px">What changes</div>
    <DiffBlock :current="diff.current" :proposed="diff.proposed" :host="diff.host" />

    <!-- Hand-holding: registrar-specific publishing steps -->
    <div class="steps-toggle" @click="showSteps = !showSteps" tabindex="0" role="button" :aria-expanded="showSteps" @keydown.enter.prevent="showSteps = !showSteps" @keydown.space.prevent="showSteps = !showSteps">
      <span>{{ registrarLoading ? 'Detecting your DNS provider…' : `How to publish this on ${registrar?.name ?? 'your DNS provider'}` }}</span>
      <span class="steps-caret" :class="showSteps ? 'open' : ''">▾</span>
    </div>
    <div v-if="showSteps && registrar" class="steps-panel">
      <ol class="steps-list">
        <li v-for="(step, i) in registrar.steps" :key="i">{{ step }}</li>
      </ol>
      <a v-if="registrar.help_url" :href="registrar.help_url" target="_blank" rel="noopener" class="steps-link">
        Open {{ registrar.name }} →
      </a>

      <!-- Email to developer / whoever manages DNS -->
      <div class="email-row">
        <button v-if="!showEmailForm" class="btn ghost small" @click="showEmailForm = true">
          Email these instructions to whoever manages my DNS
        </button>
        <div v-else class="email-form">
          <input
            v-model="emailTo" type="email" placeholder="developer@example.com"
            class="email-input" :disabled="emailSending || emailSent"
          />
          <button class="btn small" :disabled="emailSending || emailSent || !emailTo" @click="sendInstructionsEmail">
            {{ emailSent ? 'Sent ✓' : emailSending ? 'Sending…' : 'Send' }}
          </button>
        </div>
      </div>

      <!-- Escalation path (GUIDED_ONBOARDING_PLAN.md Part 3 #7/#16) — a
           mailto link rather than a live chat widget, which the plan leaves
           as an open cost/build decision; this is the honest version of
           "talk to a human" the current architecture actually supports. -->
      <a class="help-link" href="mailto:support@foundationcraft.co.za?subject=Stuck%20publishing%20a%20DNS%20record">
        Still stuck? Email ZoneProof support →
      </a>
    </div>

    <AdvisorBanner :message="diff.why" style="margin-top:16px" />

    <div style="font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin:16px 0 8px">Prerequisites</div>
    <GateChecklist :gates="diff.gates" />

    <div v-if="!diff.ready" style="font-size:11.5px;color:var(--amber);margin-top:12px">
      ⚠ Gate not fully met — publishing now risks impacting legitimate mail. Resolve the items above first.
    </div>

    <div style="display:flex;gap:10px;margin-top:18px;flex-wrap:wrap">
      <button class="btn" @click="markPublished">{{ diff.ready ? 'Mark as published' : 'Publish anyway' }}</button>
      <button class="btn ghost" @click="copyRecord">Copy record</button>
      <button class="btn ghost" @click="close">Cancel</button>
    </div>

    <div style="font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:14px;padding-top:12px;border-top:1px solid var(--line)">
      Record drafted by ZoneProof · you publish manually to your DNS provider.
    </div>
  </div>
</template>

<style scoped>
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:11px 18px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
.btn.ghost { background:rgba(255,255,255,.04); border:1px solid var(--line2); color:var(--txt); box-shadow:none; }
.btn.ghost:hover { border-color:var(--indigo); }
.btn.small { padding: 7px 13px; font-size: 11.5px; border-radius: 9px; }
.btn:disabled { opacity: .6; cursor: not-allowed; }

/* ── Live detection banner ──────────────────────────────────────────── */
.detect-banner {
  display: flex; align-items: center; gap: 9px; padding: 10px 13px;
  border-radius: 11px; font-size: 12px; margin-bottom: 14px;
}
.detect-good { background: rgba(52,224,161,.1); border: 1px solid rgba(52,224,161,.3); color: var(--good); }
.detect-wait { background: rgba(91,92,240,.08); border: 1px solid rgba(91,92,240,.22); color: #9aa6ff; }
.detect-icon { font-weight: 800; }
.detect-pulse {
  width: 8px; height: 8px; border-radius: 50%; background: #9aa6ff; flex: none;
  animation: detect-blink 1.3s ease-in-out infinite;
}
@keyframes detect-blink { 50% { opacity: .25; } }

/* ── Registrar hand-holding steps ───────────────────────────────────── */
.steps-toggle {
  display: flex; align-items: center; justify-content: space-between; cursor: pointer;
  padding: 10px 13px; border-radius: 11px; background: rgba(255,255,255,.03);
  border: 1px solid var(--line); font-size: 12.5px; color: var(--txt); margin-top: 12px;
}
.steps-caret { transition: transform .2s; color: var(--faint); }
.steps-caret.open { transform: rotate(180deg); }
.steps-panel { padding: 12px 4px 0 4px; }
.steps-list { display: flex; flex-direction: column; gap: 7px; padding-left: 20px; font-size: 12.5px; color: var(--muted); line-height: 1.5; }
.steps-link { display: inline-block; margin-top: 10px; font-size: 12px; color: #9aa6ff; text-decoration: none; }
.steps-link:hover { text-decoration: underline; }
.email-row { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--line); }
.email-form { display: flex; gap: 8px; flex-wrap: wrap; }
.email-input {
  flex: 1; min-width: 180px; background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 9px; padding: 8px 12px; font-size: 12.5px; color: var(--txt); outline: none;
}
.email-input:focus { border-color: var(--indigo); }
.help-link {
  display: inline-block; margin-top: 12px; font-size: 11.5px; color: var(--faint);
  text-decoration: none;
}
.help-link:hover { color: #9aa6ff; text-decoration: underline; }
</style>
