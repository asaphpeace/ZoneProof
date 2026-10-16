<script setup lang="ts">
import { ref, computed } from 'vue'
import { api } from '@/api/client'

const emit = defineEmits<{ close: [] }>()

type Step = 'input' | 'scanning' | 'result'

const step        = ref<Step>('input')
const domainInput = ref('')
const result      = ref<any>(null)
const error       = ref('')
const notFound    = ref(false)
const scanStep    = ref(0)  // 0-3 for animated progress

const SCAN_STEPS = ['Resolving DNS records', 'Checking DMARC & SPF', 'Probing TLS certificate', 'Calculating verdict']

const inputValid = computed(() => /^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$/.test(domainInput.value.trim()))

async function runScan() {
  const domain = domainInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]
  if (!domain) return
  step.value = 'scanning'
  scanStep.value = 0
  error.value = ''
  notFound.value = false
  result.value = null

  // Animate progress steps while waiting for the real result
  const interval = setInterval(() => {
    if (scanStep.value < SCAN_STEPS.length - 1) scanStep.value++
  }, 700)

  try {
    result.value = await api.scanDomain(domain)
    scanStep.value = SCAN_STEPS.length - 1
    await new Promise(r => setTimeout(r, 400))
    step.value = 'result'
  } catch (e: any) {
    if (e.message === 'domain_not_found') {
      notFound.value = true
    } else {
      error.value = e.message || 'Scan failed'
    }
    step.value = 'input'
  } finally {
    clearInterval(interval)
  }
}

function reset() {
  step.value = 'input'
  result.value = null
  error.value = ''
  notFound.value = false
  scanStep.value = 0
}

const STATUS_ICON: Record<string, string> = {
  pass: '✓', warn: '⚠', fail: '✕', info: '·'
}
const STATUS_COLOR: Record<string, string> = {
  pass: 'var(--good)', warn: 'var(--amber)', fail: 'var(--bad)', info: 'var(--faint)'
}
const CAT_LABEL: Record<string, string> = {
  spf: 'SPF', dmarc: 'DMARC', mx: 'MX', mta_sts: 'MTA-STS', cert: 'Certificate', bimi: 'BIMI'
}

// Ring geometry (reuse SentinelRing math at smaller size)
const R = 38
const CIRC = 2 * Math.PI * R
function arc(score: number) { return CIRC * (score / 100) }
function gap(score: number) { return CIRC - arc(score) }
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="modal">

        <!-- ── Header ─────────────────────────────────────────── -->
        <div class="mhead">
          <div class="mhead-left">
            <span class="mhead-tag">DOMAIN SCAN</span>
            <span v-if="result" class="mhead-domain">{{ result.domain }}</span>
          </div>
          <button class="mx-btn" @click="emit('close')">✕</button>
        </div>

        <!-- ── Input step ─────────────────────────────────────── -->
        <div v-if="step === 'input'" class="input-step">
          <div class="input-eyebrow">Instant email security check — no account required</div>
          <div class="input-row">
            <div class="input-wrap" :class="{ invalid: domainInput && !inputValid }">
              <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
              </svg>
              <input
                v-model="domainInput"
                class="domain-input"
                placeholder="example.com"
                @keyup.enter="inputValid && runScan()"
                autofocus
              />
            </div>
            <button class="scan-btn" :disabled="!inputValid" @click="runScan">
              Scan domain
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </button>
          </div>
          <div v-if="notFound" class="not-found-msg">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            Domain not found — check the spelling and try again
          </div>
          <div v-else-if="error" class="error-msg">{{ error }}</div>
          <div class="input-hint">
            Checks SPF · DMARC · MX · MTA-STS · TLS certificate in real time
          </div>
        </div>

        <!-- ── Scanning step ──────────────────────────────────── -->
        <div v-else-if="step === 'scanning'" class="scanning-step">
          <div class="scan-orb">
            <div class="scan-ring" />
            <svg class="scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 3"/>
            </svg>
          </div>
          <div class="scan-domain-label">{{ domainInput.trim() }}</div>
          <div class="scan-steps">
            <div
              v-for="(s, i) in SCAN_STEPS"
              :key="i"
              :class="['scan-step-item', i < scanStep ? 'done' : i === scanStep ? 'active' : 'pending']"
            >
              <span class="step-dot" />
              {{ s }}
            </div>
          </div>
        </div>

        <!-- ── Result step ────────────────────────────────────── -->
        <div v-else-if="step === 'result' && result" class="result-step">
          <div class="result-grid">

            <!-- Left: findings list -->
            <div class="findings-col">
              <div class="findings-label">Security findings</div>
              <div
                v-for="f in result.findings"
                :key="f.category + f.title"
                class="finding-row"
                :class="f.status"
              >
                <div class="finding-header">
                  <span class="finding-icon" :style="`color:${STATUS_COLOR[f.status]}`">
                    {{ STATUS_ICON[f.status] }}
                  </span>
                  <span class="finding-cat">{{ CAT_LABEL[f.category] || f.category.toUpperCase() }}</span>
                  <span class="finding-title">{{ f.title }}</span>
                </div>
                <div class="finding-detail">{{ f.detail }}</div>
              </div>
            </div>

            <!-- Right: verdict card -->
            <div class="verdict-col">
              <div class="verdict-card" :class="{ 'no-email': !result.is_email_domain }">
                <!-- Mini score ring -->
                <div class="verdict-ring-wrap">
                  <svg class="verdict-ring" viewBox="0 0 92 92">
                    <circle cx="46" cy="46" :r="R" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="8" />
                    <circle
                      cx="46" cy="46" :r="R" fill="none"
                      :stroke="result.grade_color"
                      stroke-width="8"
                      stroke-linecap="round"
                      :stroke-dasharray="`${arc(result.score)} ${gap(result.score)}`"
                      transform="rotate(-90 46 46)"
                    />
                    <text x="46" y="42" text-anchor="middle" class="vscore" :fill="result.grade_color">{{ result.score }}</text>
                    <text x="46" y="56" text-anchor="middle" class="vgrade" fill="rgba(255,255,255,.4)">{{ result.grade }}</text>
                  </svg>
                </div>
                <div class="verdict-domain">{{ result.domain }}</div>
                <div class="verdict-summary">{{ result.summary }}</div>

                <!-- Pass / warn / fail chips -->
                <div class="verdict-chips">
                  <span
                    v-for="s in ['pass', 'warn', 'fail']"
                    :key="s"
                    class="vchip"
                    :class="s"
                  >
                    {{ result.findings.filter((f: any) => f.status === s).length }}
                    {{ s }}
                  </span>
                </div>
              </div>

              <button class="scan-again-btn" @click="reset">
                ← Scan another domain
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  </Teleport>
</template>

<style scoped>
/* ── Overlay ────────────────────────────────────────────────── */
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.65);
  backdrop-filter: blur(6px); z-index: 300;
  display: grid; place-items: center; padding: 20px;
}
.modal {
  width: 860px; max-width: 96vw; max-height: 90vh; overflow-y: auto;
  background: #0b0d1e; border: 1px solid rgba(255,255,255,.1);
  border-radius: 22px; padding: 28px;
  box-shadow: 0 40px 100px rgba(0,0,0,.8), inset 0 1px 0 rgba(255,255,255,.07);
}

/* ── Header ─────────────────────────────────────────────────── */
.mhead {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 24px;
}
.mhead-left { display: flex; align-items: center; gap: 12px; }
.mhead-tag {
  font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px;
  text-transform: uppercase; color: var(--faint);
  border: 1px solid var(--line2); border-radius: 6px; padding: 3px 8px;
}
.mhead-domain {
  font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--txt);
}
.mx-btn {
  background: none; border: 1px solid var(--line); border-radius: 8px;
  color: var(--muted); width: 28px; height: 28px; cursor: pointer; font-size: 14px;
  display: grid; place-items: center; flex: none;
}
.mx-btn:hover { border-color: var(--line2); color: var(--txt); }

/* ── Input step ─────────────────────────────────────────────── */
.input-step { display: flex; flex-direction: column; gap: 16px; }
.input-eyebrow {
  font-family: var(--disp); font-weight: 700; font-size: 18px;
  letter-spacing: -.4px; color: var(--txt);
}
.input-row { display: flex; gap: 10px; flex-wrap: wrap; }
.input-wrap {
  flex: 1; min-width: 200px; position: relative;
  display: flex; align-items: center;
}
.input-icon {
  position: absolute; left: 13px; width: 16px; height: 16px;
  color: var(--faint); pointer-events: none;
}
.domain-input {
  width: 100%; background: rgba(255,255,255,.04);
  border: 1px solid var(--line2); border-radius: 13px;
  padding: 12px 14px 12px 40px;
  font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--txt);
  outline: none; transition: border-color .15s;
}
.domain-input:focus { border-color: rgba(91,92,240,.7); box-shadow: 0 0 0 3px rgba(91,92,240,.15); }
.input-wrap.invalid .domain-input { border-color: rgba(255,77,109,.4); }

.scan-btn {
  display: flex; align-items: center; gap: 8px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0);
  border: none; border-radius: 13px; padding: 12px 20px;
  font-family: var(--disp); font-weight: 700; font-size: 14px; color: #fff;
  cursor: pointer; white-space: nowrap; transition: opacity .15s;
}
.scan-btn svg { width: 15px; height: 15px; }
.scan-btn:disabled { opacity: .4; cursor: not-allowed; }
.scan-btn:not(:disabled):hover { opacity: .85; }

.not-found-msg {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--mono); font-size: 11px; color: var(--amber);
  background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25);
  border-radius: 8px; padding: 10px 14px;
}
.not-found-msg svg { width: 14px; height: 14px; flex: none; }

.error-msg {
  font-family: var(--mono); font-size: 11px; color: var(--bad);
  background: rgba(255,77,109,.08); border: 1px solid rgba(255,77,109,.2);
  border-radius: 8px; padding: 8px 12px;
}
.input-hint {
  font-family: var(--mono); font-size: 10px; color: var(--faint);
}

/* ── Scanning step ──────────────────────────────────────────── */
.scanning-step {
  display: flex; flex-direction: column; align-items: center;
  padding: 32px 0; gap: 20px;
}
.scan-orb {
  position: relative; width: 72px; height: 72px;
  display: grid; place-items: center;
}
.scan-ring {
  position: absolute; inset: 0; border-radius: 50%;
  border: 2px solid rgba(91,92,240,.2);
  border-top-color: #5b5cf0;
  animation: spin 1s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.scan-icon { width: 36px; height: 36px; color: #9aa6ff; }
.scan-domain-label {
  font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--txt);
}
.scan-steps { display: flex; flex-direction: column; gap: 10px; min-width: 260px; }
.scan-step-item {
  display: flex; align-items: center; gap: 10px;
  font-family: var(--mono); font-size: 11px; transition: color .3s;
}
.scan-step-item.done    { color: var(--good); }
.scan-step-item.active  { color: #9aa6ff; }
.scan-step-item.pending { color: var(--faint); }
.step-dot {
  width: 6px; height: 6px; border-radius: 50%; flex: none;
  background: currentColor;
}

/* ── Result step ────────────────────────────────────────────── */
.result-step {}
.result-grid {
  display: grid; grid-template-columns: 1fr 280px; gap: 24px; align-items: start;
}
@media (max-width: 680px) { .result-grid { grid-template-columns: 1fr; } }

/* findings */
.findings-col { display: flex; flex-direction: column; gap: 0; }
.findings-label {
  font-family: var(--mono); font-size: 9px; letter-spacing: .8px;
  text-transform: uppercase; color: var(--faint); margin-bottom: 10px;
}
.finding-row {
  border-bottom: 1px solid var(--line); padding: 12px 4px;
}
.finding-row:last-child { border-bottom: none; }
.finding-header {
  display: flex; align-items: center; gap: 8px; margin-bottom: 4px;
}
.finding-icon { font-size: 12px; font-weight: 700; width: 16px; text-align: center; flex: none; }
.finding-cat {
  font-family: var(--mono); font-size: 9px; font-weight: 700;
  letter-spacing: .6px; color: var(--faint);
  background: rgba(255,255,255,.05); border-radius: 5px;
  padding: 2px 6px; flex: none;
}
.finding-title { font-size: 13px; font-weight: 600; color: var(--txt); }
.finding-detail {
  font-family: var(--mono); font-size: 10.5px; color: var(--muted);
  line-height: 1.6; white-space: pre-wrap; padding-left: 24px;
}

/* verdict */
.verdict-col { display: flex; flex-direction: column; gap: 14px; }
.verdict-card {
  background: rgba(255,255,255,.03); border: 1px solid var(--line2);
  border-radius: 18px; padding: 22px 18px;
  display: flex; flex-direction: column; align-items: center; gap: 10px;
  text-align: center;
}
.verdict-ring-wrap { position: relative; }
.verdict-ring { width: 92px; height: 92px; }
.vscore { font-family: var(--disp); font-weight: 900; font-size: 22px; }
.vgrade { font-family: var(--disp); font-weight: 700; font-size: 11px; }
.verdict-domain {
  font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--txt);
}
.verdict-summary {
  font-size: 12px; color: var(--muted); line-height: 1.6;
}
.verdict-chips { display: flex; gap: 6px; flex-wrap: wrap; justify-content: center; }
.vchip {
  font-family: var(--mono); font-size: 9.5px; font-weight: 700;
  padding: 3px 9px; border-radius: 8px;
}
.vchip.pass { background: rgba(52,224,161,.12); color: var(--good); }
.vchip.warn { background: rgba(245,197,66,.12); color: var(--amber); }
.vchip.fail { background: rgba(255,77,109,.12); color: var(--bad); }

.verdict-card.no-email { opacity: .65; }
.verdict-card.no-email .vscore { fill: var(--faint) !important; }

.scan-again-btn {
  background: none; border: 1px solid var(--line2); border-radius: 11px;
  color: var(--muted); padding: 10px 14px; cursor: pointer;
  font-family: var(--mono); font-size: 11px; transition: .15s;
  width: 100%;
}
.scan-again-btn:hover { border-color: var(--line); color: var(--txt); }
</style>
