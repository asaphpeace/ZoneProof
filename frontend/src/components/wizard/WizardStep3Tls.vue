<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import CodeBlock from '@/components/ui/CodeBlock.vue'

const props = defineProps<{ domains: string[]; dmarcResults: any[] }>()
const emit  = defineEmits<{ next: [tlsResults: any[]] }>()

const results     = ref<any[]>([])
const loading     = ref(true)
const generatingIdx = ref(0)
const error       = ref('')

onMounted(async () => {
  try {
    for (let i = 0; i < props.dmarcResults.length; i++) {
      generatingIdx.value = i
      const r = props.dmarcResults[i]
      const tls = await api.wizardTlsInfo(r.domain)
      // Default to ZoneProof-hosted — removes the "I need an HTTPS server"
      // barrier that's the single biggest reason MTA-STS adoption is low;
      // self-hosting stays available for anyone who wants control over it.
      results.value.push({ ...r, tls, hostingMode: 'managed' })
    }
  } catch (e: any) {
    error.value = e.message || 'Failed to generate TLS records'
  } finally {
    loading.value = false
  }
})

function setHostingMode(r: any, mode: 'managed' | 'self') {
  r.hostingMode = mode
}
</script>

<template>
  <div>
    <div class="sh">TLS & MTA-STS setup</div>
    <p class="hint">Publish these records to enable TLS-RPT reporting and optionally enforce MTA-STS for each domain.</p>

    <!-- Loading progress -->
    <div v-if="loading" class="progress-wrap">
      <div class="spin" />
      <div>
        <div class="prog-label">Generating TLS records for <b>{{ dmarcResults[generatingIdx]?.domain }}</b>…</div>
        <div class="prog-bar-track">
          <div class="prog-bar-fill" :style="{ width: ((generatingIdx / dmarcResults.length) * 100) + '%' }" />
        </div>
        <div class="prog-count">{{ generatingIdx + 1 }} of {{ dmarcResults.length }}</div>
      </div>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-box">
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2" style="width:18px;height:18px;flex:none"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      <div>{{ error }}</div>
    </div>

    <!-- All domains simultaneously -->
    <template v-else>
      <div v-for="r in results" :key="r.domain" class="domain-block">
        <div class="dh">{{ r.domain }}</div>

        <div class="row2">
          <div>
            <div class="section-label">TLS-RPT record</div>
            <CodeBlock :code="r.tls.tlsrpt_record" lang="dns" />
            <div class="host-hint">Publish at <span class="fm">{{ r.tls.tlsrpt_host }}</span></div>
          </div>
          <div>
            <div class="section-label">MTA-STS DNS record</div>
            <CodeBlock :code="r.tls.mta_sts_dns_record" lang="dns" />
            <div class="host-hint">Publish at <span class="fm">{{ r.tls.mta_sts_dns_host }}</span></div>
          </div>
        </div>

        <div style="margin-top:16px">
          <div class="section-label">MTA-STS policy hosting</div>

          <div class="hosting-toggle">
            <button
              class="hosting-opt" :class="{ active: r.hostingMode === 'managed' }"
              @click="setHostingMode(r, 'managed')"
            >
              <b>ZoneProof-hosted</b>
              <span>Recommended — just publish one CNAME, no server needed</span>
            </button>
            <button
              class="hosting-opt" :class="{ active: r.hostingMode === 'self' }"
              @click="setHostingMode(r, 'self')"
            >
              <b>Self-hosted</b>
              <span>Advanced — you run the HTTPS file yourself</span>
            </button>
          </div>

          <template v-if="r.hostingMode === 'managed'">
            <div class="host-hint" style="margin-bottom:8px">Publish a CNAME at <span class="fm">{{ r.tls.mta_sts_cname_host }}</span></div>
            <CodeBlock :code="r.tls.mta_sts_cname_target" lang="dns" />
            <p class="managed-note">
              ZoneProof will serve the policy file from this hostname automatically, always
              computed from your domain's current MX records — no file to host or keep updated yourself.
            </p>
          </template>
          <template v-else>
            <div class="host-hint" style="margin-bottom:8px">Host at <span class="fm">{{ r.tls.policy_url }}</span></div>
            <CodeBlock :code="r.tls.mta_sts_policy" lang="text" />
          </template>
        </div>

        <div style="margin-top:12px;display:flex;align-items:center;gap:8px">
          <span class="section-label" style="margin-bottom:0">Reporting address</span>
          <span class="fm">{{ r.tls.reporting_address }}</span>
        </div>
      </div>

      <div class="actions">
        <button class="btn" @click="emit('next', results)">
          Review & confirm {{ results.length > 1 ? `(${results.length} domains)` : '' }} →
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 18px; margin-bottom: 8px; }
.hint { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 18px; }

.progress-wrap { display: flex; align-items: flex-start; gap: 14px; padding: 20px 0; }
.spin { width: 20px; height: 20px; border: 2px solid var(--line2); border-top-color: var(--teal); border-radius: 50%; animation: spin .8s linear infinite; flex: none; margin-top: 2px; }
@keyframes spin { to { transform: rotate(360deg); } }
.prog-label { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.prog-bar-track { width: 260px; height: 4px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; }
.prog-bar-fill { height: 100%; background: linear-gradient(90deg,#2ee6c5,#5b5cf0); border-radius: 4px; transition: width .35s ease; }
.prog-count { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 5px; }

.error-box { display: flex; gap: 12px; padding: 16px; background: rgba(255,80,80,.07); border: 1px solid rgba(255,80,80,.25); border-radius: 14px; font-size: 13px; color: var(--muted); }

.domain-block { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 14px; padding: 18px; margin-bottom: 14px; }
.dh { font-family: var(--mono); font-size: 13px; font-weight: 600; margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }

.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 560px) { .row2 { grid-template-columns: 1fr; } }

.section-label { font-family: var(--mono); font-size: 9.5px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); margin-bottom: 8px; }
.host-hint { font-size: 11px; color: var(--faint); margin-top: 6px; }
.fm { font-family: var(--mono); font-size: 11px; color: var(--teal); }

.hosting-toggle { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px; }
.hosting-opt {
  display: flex; flex-direction: column; gap: 2px; text-align: left;
  background: rgba(255,255,255,.03); border: 1px solid var(--line2); border-radius: 11px;
  padding: 10px 12px; cursor: pointer; color: var(--muted); font-size: 12px;
}
.hosting-opt b { color: var(--txt); }
.hosting-opt span { font-size: 10.5px; color: var(--faint); }
.hosting-opt.active { border-color: var(--indigo); background: rgba(91,92,240,.1); }
.hosting-opt.active b { color: #9aa6ff; }
.managed-note { font-size: 11px; color: var(--faint); line-height: 1.5; margin-top: 8px; }

.actions { margin-top: 8px; display: flex; justify-content: flex-end; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:11px 24px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
</style>
