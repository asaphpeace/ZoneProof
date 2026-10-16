<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import { useBrandGuardStore } from '@/stores/brandGuard'

// Where Brand Guard alerts go. Addresses are encrypted on the server and never shown in full again; a webhook's signing secret is shown once.
const store = useBrandGuardStore()
const auth = useAuthStore()
const channels = ref<any[]>([])
const log = ref<any[]>([])
const error = ref('')
const note = ref('')
const secret = ref<{ label: string; value: string } | null>(null)
const busy = ref('')

const KINDS: Record<string, { label: string; placeholder: string; help: string }> = {
  email: { label: 'Email', placeholder: 'secops@yourcompany.com', help: 'Sent through the same mail service as your other ZoneProof emails.' },
  slack: { label: 'Slack', placeholder: 'https://hooks.slack.com/services/…', help: 'An incoming-webhook URL from your Slack workspace.' },
  teams: { label: 'Microsoft Teams', placeholder: 'https://….webhook.office.com/…', help: 'A Workflows or incoming-webhook URL for the channel.' },
  webhook: { label: 'Webhook', placeholder: 'https://siem.yourcompany.com/hooks/zoneproof', help: 'Receives JSON. Each request is signed so you can check it came from ZoneProof.' },
}
const form = ref({ kind: 'email', label: '', target: '', min_severity: 'warn', digest: false })

async function load() {
  error.value = ''
  try { [channels.value, log.value] = await Promise.all([api.brandChannels(), api.brandNotificationLog()]) } catch (e: any) { error.value = e.message }
}
onMounted(async () => { await store.ensureLoaded(); await load() })

async function add() {
  busy.value = 'add'
  error.value = ''
  note.value = ''
  try {
    const r = await api.brandChannelCreate(form.value)
    if (r.secret) secret.value = { label: r.label, value: r.secret }
    form.value = { kind: form.value.kind, label: '', target: '', min_severity: 'warn', digest: false }
    await load()
  } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function patch(c: any, body: any) { try { await api.brandChannelUpdate(c.id, body); await load() } catch (e: any) { error.value = e.message } }
async function remove(c: any) {
  if (!confirm(`Remove "${c.label}"? Alerts will stop going there.`)) return
  try { await api.brandChannelDelete(c.id); await load() } catch (e: any) { error.value = e.message }
}
async function test(c: any) {
  busy.value = c.id
  note.value = ''
  try {
    const r = await api.brandChannelTest(c.id)
    note.value = r.ok ? `Sent a test message to "${c.label}".` : `The test to "${c.label}" failed: ${r.error}`
    await load()
  } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function copySecret() { try { await navigator.clipboard.writeText(secret.value!.value); note.value = 'Copied the signing secret.' } catch { error.value = 'Could not copy.' } }
async function siem(format: 'jsonl' | 'cef') { try { await api.brandSiemExport(format) } catch (e: any) { error.value = e.message } }
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : 'never')
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Alerts" crumb="Alerts" sub="Send Brand Guard alerts to the places your team already watches." />
      <p v-if="error" class="err" role="alert">{{ error }}</p>
      <p v-if="note" class="ok" role="status">{{ note }}</p>

      <div v-if="secret" class="secret" role="alert">
        <b>Signing secret for "{{ secret.label }}"</b>
        <code>{{ secret.value }}</code>
        <p>Copy it now. It is not shown again. Each request carries <code>X-ZoneProof-Timestamp</code> and <code>X-ZoneProof-Signature</code> (HMAC-SHA256 of the timestamp, a dot, then the body).</p>
        <button type="button" class="btn" @click="copySecret">Copy</button> <button type="button" class="btn" @click="secret = null">I have saved it</button>
      </div>

      <section class="card">
        <h3>Where alerts go</h3>
        <p v-if="!channels.length" class="help">No channels yet. Add one below. Until then alerts only appear in the app.</p>
        <ul v-else class="list">
          <li v-for="c in channels" :key="c.id">
            <div class="main">
              <div><b>{{ c.label }}</b> <span class="kind">{{ KINDS[c.kind].label }}</span> <span v-if="!c.enabled" class="off">Paused</span></div>
              <div class="mono">{{ c.target }}</div>
              <div class="fh">
                <label>Send <select :value="c.min_severity" :aria-label="`Severity for ${c.label}`" @change="patch(c, { min_severity: ($event.target as HTMLSelectElement).value })"><option value="warn">warnings and critical</option><option value="critical">critical only</option></select></label>
                <label class="chk"><input type="checkbox" :checked="c.digest" @change="patch(c, { digest: ($event.target as HTMLInputElement).checked })" /> Daily summary</label>
              </div>
              <div v-if="c.last_status" class="fh" :class="{ bad: c.last_status === 'failed' }">Last attempt {{ when(c.last_sent_at) }}: {{ c.last_status === 'ok' ? 'delivered' : 'failed' }}<template v-if="c.last_error"> ({{ c.last_error }})</template></div>
            </div>
            <div class="acts">
              <button type="button" class="btn" :disabled="busy === c.id" @click="test(c)">Send a test</button>
              <button type="button" class="btn" @click="patch(c, { enabled: !c.enabled })">{{ c.enabled ? 'Pause' : 'Resume' }}</button>
              <button type="button" class="btn danger" @click="remove(c)">Remove</button>
            </div>
          </li>
        </ul>
      </section>

      <section class="card">
        <h3>Add a channel</h3>
        <form class="form" @submit.prevent="add">
          <label>Type
            <select v-model="form.kind"><option v-for="(k, key) in KINDS" :key="key" :value="key">{{ k.label }}</option></select>
          </label>
          <label>Name <input v-model="form.label" required maxlength="80" placeholder="e.g. Security team" /></label>
          <label class="wide">{{ form.kind === 'email' ? 'Email address' : 'Address (https)' }}
            <input v-model="form.target" required :type="form.kind === 'email' ? 'email' : 'url'" :placeholder="KINDS[form.kind].placeholder" autocomplete="off" />
          </label>
          <p class="fh wide">{{ KINDS[form.kind].help }} The address is encrypted and cannot be read back.</p>
          <label>Send <select v-model="form.min_severity"><option value="warn">warnings and critical</option><option value="critical">critical only</option></select></label>
          <label class="chk"><input v-model="form.digest" type="checkbox" /> Also a daily summary</label>
          <button type="submit" class="btn primary" :disabled="busy === 'add'">{{ busy === 'add' ? 'Adding…' : 'Add channel' }}</button>
        </form>
      </section>

      <section class="card">
        <h3>Recent deliveries</h3>
        <p v-if="!log.length" class="help">Nothing sent yet.</p>
        <table v-else>
          <thead><tr><th>When</th><th>Channel</th><th>What</th><th>Result</th></tr></thead>
          <tbody><tr v-for="l in log" :key="l.id"><td>{{ when(l.sent_at) }}</td><td>{{ l.channel }}</td><td>{{ l.type }}</td><td :class="l.status">{{ l.status === 'ok' ? 'Delivered' : 'Failed' }}<template v-if="l.error">: {{ l.error }}</template></td></tr></tbody>
        </table>
      </section>

      <section class="card">
        <h3>SIEM export</h3>
        <p class="help">Brand Guard alerts and every action your team takes, for your security information system. JSON lines or CEF.</p>
        <template v-if="auth.plan === 'enterprise'">
          <button type="button" class="btn" @click="siem('jsonl')">Download JSON lines</button> <button type="button" class="btn" @click="siem('cef')">Download CEF</button>
        </template>
        <p v-else class="help">Available on the Enterprise plan.</p>
      </section>
    </template>
  </BrandFrame>
</template>

<style scoped>
.card { border: 1px solid var(--line2); border-radius: 14px; padding: 16px; margin-bottom: 16px; background: rgba(255,255,255,.02); }
h3 { margin: 0 0 8px; font-size: 15px; }
.help, .fh { font-size: 12.5px; color: var(--muted); margin: 6px 0; }
.fh.bad, td.failed { color: #ff8da1; }
td.ok { color: #6fe0b8; }
.err { color: #ff8da1; }
.ok { color: #6fe0b8; font-size: 12.5px; }
.secret { border: 1px solid #f7d27a; border-radius: 12px; padding: 14px; margin-bottom: 16px; background: rgba(245,197,66,.08); }
.secret code { display: block; margin: 8px 0; word-break: break-all; font-family: var(--mono); }
.list { list-style: none; padding: 0; margin: 0; }
.list li { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; padding: 12px 0; border-top: 1px solid var(--line2); }
.main { min-width: 0; flex: 1 1 320px; }
.kind { font: 700 10.5px var(--mono); padding: 2px 8px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; margin-left: 6px; }
.off { font: 700 10.5px var(--mono); padding: 2px 8px; border-radius: 999px; background: rgba(245,197,66,.14); color: #f7d27a; }
.mono { font-family: var(--mono); font-size: 12px; color: var(--faint); margin: 3px 0; word-break: break-all; }
.acts { display: flex; gap: 8px; align-items: flex-start; flex-wrap: wrap; }
.btn { background: rgba(255,255,255,.04); color: var(--txt); border: 1px solid var(--line2); border-radius: 8px; padding: 5px 11px; font: 600 11.5px var(--mono); cursor: pointer; }
.btn.primary { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); border-color: transparent; color: #fff; }
.btn.danger { color: #ff8da1; }
.btn:disabled { opacity: .5; }
.form { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }
.form .wide { grid-column: 1 / -1; }
label { display: grid; gap: 4px; font-size: 12px; color: var(--muted); }
label.chk { display: flex; align-items: center; gap: 6px; }
input:not([type=checkbox]), select { background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 8px; color: var(--txt); padding: 8px 10px; font: 13px var(--body); }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font: 600 11px var(--mono); color: var(--faint); padding: 6px 10px; text-transform: uppercase; }
td { padding: 8px 10px; border-top: 1px solid var(--line2); font-size: 12.5px; }
</style>
