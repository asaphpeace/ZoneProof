<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useDomainsStore } from '@/stores/domains'

const emit  = defineEmits<{ close: [] }>()
const router  = useRouter()
const domains = useDomainsStore()

const step = ref<1 | 2>(1)

// Step 1 state
const periodDays   = ref<30 | 60 | 90>(30)
const domainScope  = ref<'all' | 'subset'>('all')
const selectedDomains = ref<string[]>([])

const PERIOD_OPTIONS = [
  { value: 30,  label: 'Last 30 days' },
  { value: 60,  label: 'Last 60 days' },
  { value: 90,  label: 'Last 90 days' },
]

function toggleDomain(name: string) {
  const i = selectedDomains.value.indexOf(name)
  if (i === -1) selectedDomains.value.push(name)
  else selectedDomains.value.splice(i, 1)
}

const domainList = computed(() =>
  domainScope.value === 'all'
    ? domains.list.map(d => d.domain)
    : selectedDomains.value
)

const canProceed = computed(() =>
  domainScope.value === 'all' || selectedDomains.value.length > 0
)

// Report sections always included
const SECTIONS = [
  { icon: '◎', label: 'Executive summary', sub: 'ZoneProof Score, KPIs, plain-English posture overview' },
  { icon: '⊞', label: 'Domain portfolio', sub: 'Per-domain grade, DMARC stage, MTA-STS, cert health' },
  { icon: '⚠', label: 'Threat surface',   sub: 'Impersonation attempts blocked vs exposed' },
  { icon: '→', label: 'Recommendations',  sub: 'Ordered action list from highest to lowest risk' },
]

function generate() {
  const params = new URLSearchParams({
    period: String(periodDays.value),
    domains: domainScope.value === 'all' ? 'all' : domainList.value.join(','),
  })
  const url = router.resolve({ name: 'report', query: Object.fromEntries(params) }).href
  window.open(url, '_blank')
  emit('close')
}
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="wizard">

        <!-- Header -->
        <div class="wiz-header">
          <div>
            <div class="wiz-eyebrow">Email Security Report</div>
            <div class="wiz-title">{{ step === 1 ? 'Report scope' : 'Review & generate' }}</div>
          </div>
          <button class="close-btn" @click="emit('close')">✕</button>
        </div>

        <!-- Step indicator -->
        <div class="steps-row">
          <div :class="['step-dot', step >= 1 ? 'active' : '']">1</div>
          <div class="step-line" />
          <div :class="['step-dot', step >= 2 ? 'active' : '']">2</div>
        </div>

        <!-- ── Step 1: Scope ───────────────────────────────────────── -->
        <div v-if="step === 1" class="wiz-body">

          <!-- Date range -->
          <div class="field-group">
            <div class="field-label">Date range</div>
            <div class="option-row">
              <button
                v-for="opt in PERIOD_OPTIONS" :key="opt.value"
                :class="['option-btn', periodDays === opt.value ? 'active' : '']"
                @click="periodDays = opt.value as 30 | 60 | 90"
              >{{ opt.label }}</button>
            </div>
          </div>

          <!-- Domain scope -->
          <div class="field-group">
            <div class="field-label">Domains</div>
            <div class="option-row">
              <button
                :class="['option-btn', domainScope === 'all' ? 'active' : '']"
                @click="domainScope = 'all'"
              >
                All domains
                <span class="opt-count">{{ domains.list.length }}</span>
              </button>
              <button
                :class="['option-btn', domainScope === 'subset' ? 'active' : '']"
                @click="domainScope = 'subset'"
              >Select specific domains</button>
            </div>

            <!-- Domain checkboxes -->
            <div v-if="domainScope === 'subset'" class="domain-list">
              <label
                v-for="d in domains.list" :key="d.domain"
                :class="['domain-check', selectedDomains.includes(d.domain) ? 'checked' : '']"
              >
                <input
                  type="checkbox"
                  :checked="selectedDomains.includes(d.domain)"
                  @change="toggleDomain(d.domain)"
                />
                <span class="check-box">
                  <svg v-if="selectedDomains.includes(d.domain)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <path d="M20 6L9 17l-5-5"/>
                  </svg>
                </span>
                <span class="domain-name">{{ d.domain }}</span>
              </label>
            </div>
          </div>
        </div>

        <!-- ── Step 2: Review ──────────────────────────────────────── -->
        <div v-if="step === 2" class="wiz-body">
          <div class="review-summary">
            <div class="review-row">
              <span class="review-lbl">Period</span>
              <span class="review-val">Last {{ periodDays }} days</span>
            </div>
            <div class="review-row">
              <span class="review-lbl">Domains</span>
              <span class="review-val">
                {{ domainScope === 'all' ? `All ${domains.list.length} domains` : domainList.join(', ') }}
              </span>
            </div>
          </div>

          <div class="sections-label">Report will include</div>
          <div class="sections-list">
            <div v-for="s in SECTIONS" :key="s.label" class="section-item">
              <span class="section-icon">{{ s.icon }}</span>
              <div>
                <div class="section-name">{{ s.label }}</div>
                <div class="section-sub">{{ s.sub }}</div>
              </div>
              <svg class="section-check" viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
                <path d="M20 6L9 17l-5-5"/>
              </svg>
            </div>
          </div>

          <div class="pdf-note">
            Opens in a new tab as a printable page. Use your browser's
            <b>Print → Save as PDF</b> to download.
          </div>
        </div>

        <!-- Footer -->
        <div class="wiz-footer">
          <button v-if="step === 2" class="btn-ghost" @click="step = 1">← Back</button>
          <span v-else />
          <button
            v-if="step === 1"
            class="btn-primary"
            :disabled="!canProceed"
            @click="step = 2"
          >Continue →</button>
          <button
            v-else
            class="btn-primary"
            @click="generate"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/>
              <line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
            Generate report
          </button>
        </div>

      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.65);
  backdrop-filter: blur(6px); z-index: 300;
  display: grid; place-items: center; padding: 20px;
}
.wizard {
  width: 520px; max-width: 96vw; max-height: 90vh; overflow-y: auto;
  background: #0d0f1e; border: 1px solid var(--line2); border-radius: 20px;
  box-shadow: 0 40px 100px rgba(0,0,0,.7);
  display: flex; flex-direction: column;
}

/* Header */
.wiz-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  padding: 22px 24px 0;
}
.wiz-eyebrow { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--teal); margin-bottom: 4px; }
.wiz-title { font-family: var(--disp); font-weight: 800; font-size: 18px; }
.close-btn { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 28px; height: 28px; cursor: pointer; font-size: 13px; }
.close-btn:hover { color: var(--txt); }

/* Step indicator */
.steps-row { display: flex; align-items: center; gap: 8px; padding: 18px 24px 0; }
.step-dot {
  width: 26px; height: 26px; border-radius: 50%; border: 1.5px solid var(--line2);
  display: grid; place-items: center; font-family: var(--mono); font-size: 11px;
  color: var(--faint); flex: none; transition: .2s;
}
.step-dot.active { background: linear-gradient(135deg, #5b5cf0, #4b4ce0); border-color: transparent; color: #fff; }
.step-line { flex: 1; height: 1.5px; background: var(--line2); }

/* Body */
.wiz-body { padding: 20px 24px; display: flex; flex-direction: column; gap: 22px; flex: 1; }

/* Field groups */
.field-group { display: flex; flex-direction: column; gap: 10px; }
.field-label { font-family: var(--mono); font-size: 9.5px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); }

.option-row { display: flex; gap: 8px; flex-wrap: wrap; }
.option-btn {
  padding: 9px 16px; border-radius: 11px; border: 1px solid var(--line2);
  background: rgba(255,255,255,.03); color: var(--muted); cursor: pointer;
  font-family: var(--mono); font-size: 12px; transition: .14s;
  display: flex; align-items: center; gap: 7px;
}
.option-btn:hover { border-color: rgba(91,92,240,.5); color: var(--txt); }
.option-btn.active { background: rgba(91,92,240,.15); border-color: rgba(91,92,240,.6); color: #9aa6ff; }
.opt-count { background: rgba(91,92,240,.2); padding: 1px 6px; border-radius: 10px; font-size: 10px; }

/* Domain checkboxes */
.domain-list { display: flex; flex-direction: column; gap: 4px; margin-top: 6px; max-height: 200px; overflow-y: auto; }
.domain-check {
  display: flex; align-items: center; gap: 10px; padding: 8px 12px;
  border-radius: 10px; cursor: pointer; transition: background .12s;
}
.domain-check:hover { background: rgba(255,255,255,.04); }
.domain-check input { display: none; }
.check-box {
  width: 18px; height: 18px; border-radius: 5px; border: 1.5px solid var(--line2);
  display: grid; place-items: center; flex: none; transition: .15s;
}
.domain-check.checked .check-box { background: #5b5cf0; border-color: #5b5cf0; }
.check-box svg { width: 11px; height: 11px; color: #fff; }
.domain-name { font-family: var(--mono); font-size: 12px; }

/* Review step */
.review-summary {
  background: rgba(255,255,255,.03); border: 1px solid var(--line);
  border-radius: 12px; padding: 14px 16px; display: flex; flex-direction: column; gap: 8px;
}
.review-row { display: flex; align-items: baseline; gap: 12px; }
.review-lbl { font-family: var(--mono); font-size: 9.5px; text-transform: uppercase; letter-spacing: .7px; color: var(--faint); width: 60px; flex: none; }
.review-val { font-size: 13px; color: var(--txt); }

.sections-label { font-family: var(--mono); font-size: 9.5px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); }
.sections-list { display: flex; flex-direction: column; gap: 2px; }
.section-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 12px;
  border-radius: 10px; background: rgba(255,255,255,.025);
}
.section-icon { font-size: 15px; width: 22px; text-align: center; flex: none; color: var(--teal); }
.section-name { font-size: 13px; font-weight: 600; }
.section-sub  { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 2px; }
.section-check { width: 15px; height: 15px; flex: none; margin-left: auto; }

.pdf-note {
  font-family: var(--mono); font-size: 10.5px; color: var(--faint);
  background: rgba(255,255,255,.03); border: 1px solid var(--line);
  border-radius: 10px; padding: 10px 14px; line-height: 1.6;
}
.pdf-note b { color: var(--muted); }

/* Footer */
.wiz-footer {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 24px 22px; border-top: 1px solid var(--line); margin-top: auto;
}
.btn-ghost {
  background: none; border: 1px solid var(--line2); border-radius: 11px;
  padding: 10px 16px; color: var(--muted); font-family: var(--mono); font-size: 12px;
  cursor: pointer; transition: .14s;
}
.btn-ghost:hover { border-color: var(--indigo); color: var(--txt); }
.btn-primary {
  display: flex; align-items: center; gap: 8px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: none;
  border-radius: 12px; padding: 11px 20px; font-family: var(--disp); font-weight: 700;
  font-size: 13px; cursor: pointer; transition: opacity .15s;
}
.btn-primary svg { width: 15px; height: 15px; }
.btn-primary:disabled { opacity: .45; cursor: not-allowed; }
</style>
