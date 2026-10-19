<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'
import SpfCompositionBuilder from './SpfCompositionBuilder.vue'

const props = defineProps<{ domainId: string; platformKey: string }>()
const emit = defineEmits<{ close: []; done: [] }>()
const ui = useUiStore()

const card = ref<any>(null)
const loading = ref(true)
const markingDone = ref(false)
const showEmailForm = ref(false)
const emailTo = ref('')
const emailSending = ref(false)
const emailSent = ref(false)

onMounted(async () => {
  try {
    card.value = await api.platformSetupCard(props.domainId, props.platformKey)
  } finally {
    loading.value = false
  }
})

function copy(text: string) {
  navigator.clipboard.writeText(text)
  ui.toast('Copied')
}

async function markDone() {
  // The "mark as done" guard — don't silently accept a setup we have no
  // evidence is actually live. A real live-DNS check belongs here once the
  // generic check-dns-live endpoint is extended to take an arbitrary host
  // (today it only knows about dmarc/mta-sts/tlsrpt) — until then, this is
  // an explicit, honest confirmation step rather than a fake green check.
  if (!confirm('ZoneProof hasn\'t independently confirmed this DNS change is live yet. Mark as done anyway?')) return
  markingDone.value = true
  try {
    ui.toast(`${card.value?.name} marked as set up`)
    emit('done')
  } finally {
    markingDone.value = false
  }
}

async function sendEmail() {
  if (!emailTo.value) return
  emailSending.value = true
  try {
    // Sent server-side via ZoneProof's own email service — not a mailto:
    // link. mailto: only works if the person clicking it has a desktop
    // mail client configured as the OS/browser default, which silently
    // does nothing otherwise (webmail-only setups, mobile, locked-down
    // corporate machines) — that's why this looked broken.
    const result = await api.emailPlatformInstructions(props.domainId, props.platformKey, emailTo.value)
    if (result.ok) {
      emailSent.value = true
      ui.toast(`Sent to ${emailTo.value}`)
    } else {
      ui.toast('Failed to send — check the email address and try again')
    }
  } catch (e: any) {
    ui.toast(e.message || 'Failed to send')
  } finally {
    emailSending.value = false
  }
}
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="panel">
        <div v-if="loading" class="loading">Loading setup details…</div>
        <template v-else-if="card">
          <div class="mh">
            <span>{{ card.name }} setup</span>
            <button class="mx" @click="emit('close')">✕</button>
          </div>

          <p class="section-text mono-line dns-detected">
            Detected DNS provider: <b>{{ card.registrar_name }}</b>
            ({{ card.nameservers.join(', ') || 'nameservers unknown' }})
            <a v-if="card.registrar_help_url" :href="card.registrar_help_url" target="_blank" rel="noopener" class="steps-link">
              Open {{ card.registrar_name }} →
            </a>
          </p>

          <!-- SPF — always the shared composition, never this platform alone -->
          <SpfCompositionBuilder
            :record="card.spf_composition.record"
            :record-host="card.record_host"
            :mechanisms="card.spf_composition.mechanisms"
            :total-lookups="card.spf_composition.total_lookups"
            :lookup-limit="card.spf_composition.lookup_limit"
            :over-limit="card.spf_composition.over_limit"
            :near-limit="card.spf_composition.near_limit"
            :warnings="card.spf_composition.warnings"
            :existing-record-found="card.spf_composition.existing_record_found"
            :real-lookup-count="card.spf_composition.real_lookup_count"
          />

          <!-- Publish the SPF record above, right where it was just copied —
               not buried in a separate section at the bottom of the modal. -->
          <div class="section publish-block">
            <div class="section-title">How to publish this SPF record in {{ card.registrar_name }}</div>
            <ol class="steps-list">
              <li v-for="(step, i) in card.registrar_steps" :key="i">{{ step }}</li>
            </ol>
          </div>

          <!-- DKIM -->
          <div v-if="card.dkim_kind" class="section">
            <div class="section-title">DKIM</div>
            <p class="section-text">{{ card.dkim_description }}</p>
            <div v-if="card.dkim_selector_pattern" class="selector-row">
              <span class="selector-label">Typical selector</span>
              <code class="selector-val">{{ card.dkim_selector_pattern }}</code>
            </div>
          </div>
          <div v-else class="section">
            <div class="section-title">DKIM</div>
            <p class="section-text muted">
              No DKIM instructions for this deployment mode — signing responsibility usually sits
              with your own mail server here. Check your mail server's own DKIM configuration.
            </p>
          </div>

          <div v-if="card.return_path_note" class="section">
            <div class="section-title">Return-path (envelope-from)</div>
            <p class="section-text">{{ card.return_path_note }}</p>
          </div>

          <!-- Where to configure -->
          <div class="section">
            <div class="section-title">Where to configure this in {{ card.name }}</div>
            <ol class="steps-list">
              <li v-for="(step, i) in card.admin_path" :key="i">{{ step }}</li>
            </ol>
          </div>

          <div v-if="card.gotchas?.length" class="section gotchas">
            <div class="section-title">Known gotchas</div>
            <p v-for="(g, i) in card.gotchas" :key="i" class="section-text">{{ g }}</p>
          </div>

          <!-- DKIM publish step — once you've copied the selector + value
               from {{ card.name }}'s dashboard above, here's where it goes.
               Previously missing entirely: the modal explained how to GET
               the DKIM value but never how to PUBLISH it. -->
          <div v-if="card.dkim_kind" class="section publish-block">
            <div class="section-title">How to publish this DKIM record in {{ card.registrar_name }}</div>
            <div class="spf-publish-row">
              <span class="spf-publish-item"><span class="spf-publish-label">Type</span><code>{{ card.dkim_record_type }}</code></span>
              <span class="spf-publish-item"><span class="spf-publish-label">Host pattern</span><code>{{ card.dkim_host_pattern }}</code></span>
            </div>
            <p class="section-text muted">
              Replace &lt;selector&gt; with the exact selector {{ card.name }} gave you above, and use the value
              {{ card.name }} showed you — ZoneProof never sees this value, it's generated per-account.
            </p>
            <ol class="steps-list">
              <li v-for="(step, i) in card.registrar_steps_dkim" :key="i">{{ step }}</li>
            </ol>
          </div>

          <!-- Email instructions -->
          <div class="section email-section">
            <button v-if="!showEmailForm" class="btn ghost small" @click="showEmailForm = true">
              Email these instructions to my team
            </button>
            <div v-else class="email-form">
              <input v-model="emailTo" type="email" placeholder="developer@example.com" class="email-input" :disabled="emailSending || emailSent" />
              <button class="btn small" :disabled="emailSending || emailSent || !emailTo" @click="sendEmail">
                {{ emailSent ? 'Sent ✓' : emailSending ? 'Sending…' : 'Send' }}
              </button>
            </div>
          </div>

          <div class="footer">
            <button class="btn" :disabled="markingDone" @click="markDone">Mark as done</button>
            <button class="btn ghost" @click="emit('close')">Close</button>
          </div>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 300; display: grid; place-items: center; padding: 20px; }
.panel { width: 640px; max-width: 94vw; max-height: 90vh; overflow-y: auto; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 18px; padding: 24px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.loading { padding: 40px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.mh { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; }
.mh span { font-family: var(--disp); font-weight: 800; font-size: 16px; }
.mx { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 28px; height: 28px; cursor: pointer; font-size: 14px; }

.section { margin-top: 16px; }
.section-title { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); margin-bottom: 8px; }
.section-text { font-size: 12.5px; color: var(--muted); line-height: 1.6; margin: 0 0 6px; }
.section-text.muted { color: var(--faint); font-style: italic; }
.mono-line { font-family: var(--mono); font-size: 11.5px; }
.gotchas .section-text { color: var(--amber); }
.dns-detected { margin-bottom: 14px; }
.publish-block { background: rgba(255,255,255,.02); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }

.spf-publish-row { display: flex; gap: 16px; margin-bottom: 8px; flex-wrap: wrap; }
.spf-publish-item { display: flex; align-items: center; gap: 6px; font-size: 11.5px; }
.spf-publish-item code { font-family: var(--mono); color: var(--txt); background: rgba(255,255,255,.06); padding: 2px 8px; border-radius: 6px; }
.spf-publish-label { font-family: var(--mono); font-size: 9px; letter-spacing: .5px; text-transform: uppercase; color: var(--faint); }

.selector-row { display: flex; gap: 10px; align-items: center; }
.selector-label { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.selector-val { font-family: var(--mono); font-size: 11px; color: #9aa6ff; background: rgba(91,92,240,.1); padding: 2px 8px; border-radius: 5px; }

.steps-list { display: flex; flex-direction: column; gap: 6px; padding-left: 20px; font-size: 12px; color: var(--muted); line-height: 1.55; }
.steps-link { display: inline-block; margin-top: 8px; font-size: 12px; color: #9aa6ff; text-decoration: none; }
.steps-link:hover { text-decoration: underline; }

.email-section { padding-top: 12px; border-top: 1px solid var(--line); }
.email-form { display: flex; gap: 8px; flex-wrap: wrap; }
.email-input { flex: 1; min-width: 180px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 9px; padding: 8px 12px; font-size: 12.5px; color: var(--txt); outline: none; }
.email-input:focus { border-color: var(--indigo); }

.footer { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none; border-radius: 12px; padding: 11px 18px; font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); box-shadow: none; }
.btn.ghost:hover { border-color: var(--indigo); }
.btn.small { padding: 7px 13px; font-size: 11.5px; border-radius: 9px; }
.btn:disabled { opacity: .6; cursor: not-allowed; }
</style>
