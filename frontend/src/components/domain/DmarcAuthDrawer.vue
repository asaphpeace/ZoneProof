<script setup lang="ts">
/**
 * Right-side drawer showing full auth detail for a single source IP.
 * Receives the DmarcIpOut object (which contains auth_details[]).
 * Renders verdict, identity, DKIM, SPF, and outcome for the dominant detail.
 */
import { ref } from 'vue'
import AskFollowUp from '@/components/ui/AskFollowUp.vue'
import DkimFailureDiagnosis from './DkimFailureDiagnosis.vue'
import PlatformSetupModal from './PlatformSetupModal.vue'
import ConceptCardButton from '@/components/ui/ConceptCardButton.vue'

const props = defineProps<{ ip: any; domainId?: string }>()
const emit = defineEmits<{ close: [] }>()

const setupPlatformKey = ref<string | null>(null)
const arcInfoOpen = ref(false)

// known_esp comes from verdict_service.py's _KNOWN_ESPS naming, which isn't
// guaranteed to match the platform library's key spelling 1:1 — this is a
// best-effort map for the common ones; an unmapped ESP just gets no "Fix
// this" button rather than a broken one.
const ESP_TO_PLATFORM_KEY: Record<string, string> = {
  'salesforce': 'salesforce_mc', 'salesforce mc': 'salesforce_mc',
  'mailchimp': 'mailchimp', 'sendgrid': 'sendgrid', 'amazon ses': 'amazon_ses',
  'mailgun': 'mailgun', 'postmark': 'postmark', 'sparkpost': 'sparkpost',
  'hubspot': 'hubspot', 'klaviyo': 'klaviyo', 'zendesk': 'zendesk',
  'constant contact': 'constant_contact',
}
function platformKeyFor(knownEsp: string | null | undefined): string | null {
  if (!knownEsp) return null
  return ESP_TO_PLATFORM_KEY[knownEsp.trim().toLowerCase()] ?? null
}

function seedContext(det: any): string {
  return `Source ${props.ip.source_ip}${props.ip.rdns ? ` (${props.ip.rdns})` : ''}, ${props.ip.volume} messages. ` +
    `DKIM result=${det.dkim_result || 'none'} aligned=${det.dkim_aligned}, ` +
    `SPF result=${det.spf_result || 'none'} aligned=${det.spf_aligned}, ` +
    `DMARC result=${det.dmarc_result}. Header-From=${det.header_from}, Envelope-From=${det.envelope_from || 'none'}.`
}

function resultColor(r: string | null | undefined) {
  if (!r) return 'var(--faint)'
  const lo = r.toLowerCase()
  if (lo === 'pass') return 'var(--good)'
  if (lo === 'fail') return 'var(--bad)'
  if (lo === 'softfail' || lo === 'neutral') return 'var(--amber)'
  return 'var(--faint)'
}

function alignBadge(aligned: boolean, result?: string | null) {
  if (aligned) return { text: 'ALIGNED', color: 'var(--good)', bg: 'rgba(52,224,161,.15)' }
  if (result === 'pass') return { text: 'NOT ALIGNED', color: 'var(--amber)', bg: 'rgba(245,197,66,.14)' }
  return { text: 'FAIL', color: 'var(--bad)', bg: 'rgba(255,77,109,.15)' }
}

const verdictStyle: Record<string, { color: string; bg: string; border: string }> = {
  good:  { color: 'var(--good)', bg: 'rgba(52,224,161,.1)',  border: 'rgba(52,224,161,.3)'  },
  warn:  { color: '#a0e0ff',     bg: 'rgba(46,200,230,.1)', border: 'rgba(46,200,230,.3)'  },
  amber: { color: 'var(--amber)',bg: 'rgba(245,197,66,.1)', border: 'rgba(245,197,66,.3)'  },
  bad:   { color: 'var(--bad)',  bg: 'rgba(255,77,109,.1)', border: 'rgba(255,77,109,.3)'  },
}
</script>

<template>
  <!-- Backdrop -->
  <Teleport to="body">
    <div class="backdrop" aria-hidden="true" @click="emit('close')" />

    <div class="drawer">
      <!-- Drawer header -->
      <div class="dh">
        <div>
          <div class="dh-label">IP Authentication Detail</div>
          <div class="dh-ip">{{ ip.source_ip }}</div>
          <div v-if="ip.rdns" class="dh-rdns">{{ ip.rdns }}</div>
        </div>
        <button class="close-btn" @click="emit('close')">✕</button>
      </div>

      <!-- Volume pill -->
      <div class="vol-pill">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        {{ ip.volume.toLocaleString() }} messages
      </div>

      <!-- Loop over auth_details (usually one, occasionally multiple) -->
      <div v-for="(det, idx) in ip.auth_details" :key="idx" class="detail-block" :class="{ 'mt-12': idx > 0 }">
        <div v-if="ip.auth_details.length > 1" class="multi-label">
          Auth group {{ idx + 1 }} of {{ ip.auth_details.length }} · {{ det.volume.toLocaleString() }} msgs
        </div>

        <!-- ── Verdict banner ───────────────────────────────────────── -->
        <div class="verdict-banner" :style="{
          background: verdictStyle[det.verdict_color]?.bg,
          border: `1px solid ${verdictStyle[det.verdict_color]?.border}`,
        }">
          <div class="verdict-top">
            <span class="verdict-badge" :style="{ color: verdictStyle[det.verdict_color]?.color }">
              {{ det.verdict_label || det.verdict }}
            </span>
            <span class="verdict-dmarc" :style="{ color: det.dmarc_result === 'pass' ? 'var(--good)' : 'var(--bad)' }">
              DMARC {{ det.dmarc_result?.toUpperCase() }}
            </span>
          </div>
          <p class="verdict-detail">{{ det.verdict_detail || det.explanation }}</p>
          <DkimFailureDiagnosis
            v-if="det.dkim_failure_hypotheses?.length"
            :hypotheses="det.dkim_failure_hypotheses"
            :platform-key="platformKeyFor(det.known_esp)"
            @open-platform-setup="key => (setupPlatformKey = key)"
            @open-arc-info="arcInfoOpen = true"
          />
          <AskFollowUp screen="dmarc" :domain-id="domainId" :seed-context="seedContext(det)" />
        </div>

        <!-- ── Identity ─────────────────────────────────────────────── -->
        <div class="section">
          <div class="sec-title">Identity</div>

          <div class="field">
            <span class="fk">Header-From</span>
            <span class="fv mono">{{ det.header_from }}</span>
            <span class="fhint">What recipients see in the From: field</span>
          </div>

          <div class="field">
            <span class="fk">
              Envelope-From
              <ConceptCardButton
                concept-id="dmarc.return_path"
                :context="{ envelope_from: det.envelope_from || 'none', header_from: det.header_from }"
                screen="dmarc" :domain-id="domainId"
              />
            </span>
            <span class="fv mono">{{ det.envelope_from || '—' }}</span>
            <span class="fhint">MAIL FROM (bounce path) — must match for SPF alignment</span>
          </div>

          <!-- Envelope mismatch warning -->
          <div v-if="det.envelope_mismatch" class="env-notice" :class="det.known_esp ? 'esp' : 'spoof'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;flex:none;margin-top:1px">
              <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
            </svg>
            <span v-if="det.known_esp">
              Envelope domain differs from header-from — this is normal for <b>{{ det.known_esp }}</b> which routes bounces under their own domain.
            </span>
            <span v-else>
              Envelope domain doesn't match <b>{{ det.header_from }}</b> — possible spoofing or misconfigured third-party sender.
            </span>
          </div>
        </div>

        <!-- ── DKIM ─────────────────────────────────────────────────── -->
        <div class="section">
          <div class="sec-title">DKIM signature</div>

          <div class="field">
            <span class="fk">Signing domain (d=)</span>
            <span class="fv mono">{{ det.dkim_domain || 'none' }}</span>
            <span class="fhint">Must match {{ det.header_from }} for alignment</span>
          </div>
          <div class="field">
            <span class="fk">Selector (s=)</span>
            <span class="fv mono">{{ det.dkim_selector || '—' }}</span>
            <span v-if="det.dkim_selector" class="fhint">DNS lookup: {{ det.dkim_selector }}._domainkey.{{ det.dkim_domain || det.header_from }}</span>
          </div>
          <div class="field">
            <span class="fk">Signature result</span>
            <span class="fv fw" :style="{ color: resultColor(det.dkim_result) }">{{ (det.dkim_result || 'none').toUpperCase() }}</span>
          </div>
          <div class="field">
            <span class="fk">
              Alignment
              <ConceptCardButton
                concept-id="dmarc.alignment"
                :context="{ auth_domain: det.dkim_domain || 'none', header_from: det.header_from }"
                screen="dmarc" :domain-id="domainId"
              />
            </span>
            <span class="badge" :style="`color:${alignBadge(det.dkim_aligned, det.dkim_result).color};background:${alignBadge(det.dkim_aligned, det.dkim_result).bg}`">
              {{ alignBadge(det.dkim_aligned, det.dkim_result).text }}
            </span>
            <span v-if="!det.dkim_aligned && det.dkim_domain" class="fhint">
              Signed as {{ det.dkim_domain }}, not {{ det.header_from }}
            </span>
          </div>
        </div>

        <!-- ── SPF ──────────────────────────────────────────────────── -->
        <div class="section">
          <div class="sec-title">SPF check</div>

          <div class="field">
            <span class="fk">Domain checked</span>
            <span class="fv mono">{{ det.spf_domain || det.envelope_from || '—' }}</span>
            <span class="fhint">Envelope-from domain evaluated against SPF record</span>
          </div>
          <div class="field">
            <span class="fk">SPF result</span>
            <span class="fv fw" :style="{ color: resultColor(det.spf_result) }">{{ (det.spf_result || 'none').toUpperCase() }}</span>
          </div>
          <div class="field">
            <span class="fk">Alignment</span>
            <span class="badge" :style="`color:${alignBadge(det.spf_aligned, det.spf_result).color};background:${alignBadge(det.spf_aligned, det.spf_result).bg}`">
              {{ alignBadge(det.spf_aligned, det.spf_result).text }}
            </span>
            <span v-if="!det.spf_aligned && det.spf_domain" class="fhint">
              SPF passed for {{ det.spf_domain }}, not {{ det.header_from }}
            </span>
          </div>
        </div>

        <!-- ── Outcome ──────────────────────────────────────────────── -->
        <div class="section outcome">
          <div class="sec-title">DMARC outcome</div>

          <div class="outcome-row">
            <div class="outcome-col">
              <div class="oc-label">Result</div>
              <div class="oc-val" :style="{ color: det.dmarc_result === 'pass' ? 'var(--good)' : 'var(--bad)' }">
                {{ (det.dmarc_result || '').toUpperCase() }}
              </div>
            </div>
            <div class="outcome-col">
              <div class="oc-label">Disposition</div>
              <div class="oc-val mono">{{ det.disposition || 'none' }}</div>
            </div>
            <div class="outcome-col">
              <div class="oc-label">Volume</div>
              <div class="oc-val mono">{{ (det.volume || 0).toLocaleString() }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <PlatformSetupModal
      v-if="setupPlatformKey && domainId"
      :domain-id="domainId"
      :platform-key="setupPlatformKey"
      @close="setupPlatformKey = null"
      @done="setupPlatformKey = null"
    />

    <div v-if="arcInfoOpen" class="arc-overlay" @click.self="arcInfoOpen = false">
      <div class="arc-box">
        <div class="arc-head"><span>About ARC</span><button class="arc-x" @click="arcInfoOpen = false">✕</button></div>
        <p>
          ARC (Authenticated Received Chain) lets a forwarder or mailing list cryptographically attest
          that a message passed authentication before it modified it — giving the receiving server a way
          to trust the original authentication even though DKIM itself broke in transit.
        </p>
        <p>
          This only works if the forwarder supports it — there's nothing to configure on your sending
          domain. If the forwarder doesn't support ARC, this failure is expected and not something a DNS
          change on your end can fix.
        </p>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,.45);
  backdrop-filter: blur(3px); z-index: 300;
}
.drawer {
  position: fixed; top: 0; right: 0; bottom: 0; width: 440px; max-width: 96vw;
  background: #0d0f1f; border-left: 1px solid var(--line2);
  box-shadow: -20px 0 60px rgba(0,0,0,.5);
  z-index: 301; overflow-y: auto; padding: 24px;
  animation: slideIn .22s cubic-bezier(.25,.46,.45,.94);
}
@keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }

/* Header */
.dh { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; gap: 12px; }
.dh-label { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
.dh-ip { font-family: var(--mono); font-size: 16px; font-weight: 700; color: var(--txt); }
.dh-rdns { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-top: 3px; }
.close-btn { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 30px; height: 30px; cursor: pointer; font-size: 14px; flex: none; }
.close-btn:hover { border-color: var(--line2); color: var(--txt); }

.vol-pill { display: inline-flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 10.5px; color: var(--muted); background: rgba(255,255,255,.05); border: 1px solid var(--line); border-radius: 20px; padding: 4px 12px; margin-bottom: 20px; }

.mt-12 { margin-top: 12px; }
.multi-label { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); margin-bottom: 10px; }

/* Verdict banner */
.verdict-banner { border-radius: 14px; padding: 14px 16px; margin-bottom: 14px; }
.verdict-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; flex-wrap: wrap; gap: 8px; }
.verdict-badge { font-family: var(--disp); font-weight: 800; font-size: 15px; }
.verdict-dmarc { font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 1px; }
.verdict-detail { font-size: 12.5px; color: var(--muted); line-height: 1.65; margin: 0; }

/* Sections */
.section { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; margin-bottom: 10px; }
.sec-title { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); margin-bottom: 12px; }

.field { display: grid; grid-template-columns: 140px 1fr; gap: 3px 10px; margin-bottom: 10px; align-items: baseline; }
.field:last-child { margin-bottom: 0; }
.fk { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.fv { font-size: 12.5px; color: var(--txt); }
.fv.mono { font-family: var(--mono); }
.fv.fw { font-weight: 700; }
.fhint { grid-column: 2; font-size: 10.5px; color: var(--muted); line-height: 1.4; margin-top: -1px; }
.badge { font-family: var(--mono); font-size: 9px; font-weight: 700; padding: 2px 8px; border-radius: 6px; }

/* Envelope notice */
.env-notice { display: flex; align-items: flex-start; gap: 8px; font-size: 11.5px; line-height: 1.5; padding: 10px 12px; border-radius: 10px; margin-top: 10px; }
.env-notice.esp     { background: rgba(245,197,66,.09); color: var(--amber); border: 1px solid rgba(245,197,66,.25); }
.env-notice.spoof   { background: rgba(255,80,80,.08); color: var(--bad); border: 1px solid rgba(255,80,80,.25); }

/* Outcome */
.outcome { background: rgba(255,255,255,.02); }
.outcome-row { display: flex; gap: 0; }
.outcome-col { flex: 1; }
.outcome-col + .outcome-col { border-left: 1px solid var(--line); padding-left: 16px; margin-left: 16px; }
.oc-label { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .8px; color: var(--faint); margin-bottom: 5px; }
.oc-val { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.oc-val.mono { font-family: var(--mono); font-size: 13px; }

/* ARC info popover */
.arc-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 320; display: grid; place-items: center; padding: 20px; }
.arc-box { width: 420px; max-width: 92vw; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 16px; padding: 20px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.arc-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.arc-head span { font-family: var(--disp); font-weight: 800; font-size: 14px; }
.arc-x { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 24px; height: 24px; cursor: pointer; font-size: 12px; }
.arc-box p { font-size: 12.5px; color: var(--muted); line-height: 1.6; margin: 0 0 10px; }
</style>
