<script setup lang="ts">
import { ref, computed } from 'vue'
import AiBadge from './AiBadge.vue'
import { useScopeStore } from '@/stores/scope'
import NextStep from '@/components/ui/NextStep.vue'

const props = defineProps<{
  entry: {
    id: string
    record_type: string
    record_host: string
    previous_value: string | null
    current_value: string | null
    change_summary: string | null
    change_type: string        // added | modified | removed
    is_security_alert: boolean
    detected_at: string
    domain_name?: string | null
    risk_severity?: string | null    // info | warn | critical
    risk_explanation?: string | null
    risk_action?: string | null
    risk_is_ai?: boolean
  }
}>()

const expanded = ref(false)
const scope = useScopeStore()

// The page that explains what a change of this record type means in practice.
const evidence = computed(() => {
  const t = props.entry.record_type
  if (['DMARC', 'SPF', 'DKIM'].includes(t)) return { to: 'dmarc', label: 'See who is sending' }
  if (['MTA-STS', 'TLS-RPT', 'MX'].includes(t)) return { to: 'tls', label: 'See TLS delivery' }
  return null
})
const linkDomain = computed(() => props.entry.domain_name || scope.domain)

const TYPE_COLOR: Record<string, string> = {
  DMARC:    '#9aa6ff',
  SPF:      '#f5c542',
  'MTA-STS':'#2ee6c5',
  'TLS-RPT':'#2ee6c5',
  DKIM:     '#b07bff',
  MX:       '#9098b5',
}

const typeColor = computed(() => TYPE_COLOR[props.entry.record_type] ?? '#9098b5')

const changeIcon = computed(() => props.entry.change_type === 'added' ? '+' : props.entry.change_type === 'removed' ? '−' : '~')

const changeIconColor = computed(() =>
  props.entry.change_type === 'added'   ? 'var(--good)'
  : props.entry.change_type === 'removed' ? 'var(--bad)'
  : 'var(--amber)'
)

const relativeTime = computed(() => {
  const d = new Date(props.entry.detected_at)
  const diff = Date.now() - d.getTime()
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days  = Math.floor(diff / 86400000)
  if (mins  <  1) return 'Just now'
  if (mins  < 60) return `${mins}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days  <  7) return `${days}d ago`
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
})

const fullTimestamp = computed(() =>
  new Date(props.entry.detected_at).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
)

// Truncate long DNS values for the summary line
function truncate(val: string | null, len = 80): string {
  if (!val) return '—'
  return val.length > len ? val.slice(0, len) + '…' : val
}

// Split multi-part SPF/DMARC values into tokens for diff highlighting
function tokenize(val: string | null): string[] {
  if (!val) return []
  return val.split(/[;\s]+/).map(t => t.trim()).filter(Boolean)
}

const addedTokens = computed(() => {
  const prev = new Set(tokenize(props.entry.previous_value))
  return tokenize(props.entry.current_value).filter(t => !prev.has(t))
})

const removedTokens = computed(() => {
  const curr = new Set(tokenize(props.entry.current_value))
  return tokenize(props.entry.previous_value).filter(t => !curr.has(t))
})

const hasDiff = computed(() =>
  props.entry.change_type === 'modified' &&
  (addedTokens.value.length > 0 || removedTokens.value.length > 0)
)

// One-click rollback (#1 in GUIDED_ONBOARDING_PLAN.md Part 3) — ZoneProof doesn't
// write DNS directly yet (no Domain Connect/Entri integration), so "rollback"
// means making the previous value trivially easy to republish: copy it to the
// clipboard with the exact host it belongs to, instead of asking the user to
// scroll back through the diff and retype it by hand.
const ROLLBACK_TYPES = new Set(['DMARC', 'MTA-STS', 'TLS-RPT'])
const canRollback = computed(() =>
  ROLLBACK_TYPES.has(props.entry.record_type) &&
  !!props.entry.previous_value &&
  props.entry.change_type !== 'added'
)
const copied = ref(false)
async function copyPreviousValue() {
  if (!props.entry.previous_value) return
  await navigator.clipboard.writeText(props.entry.previous_value)
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

const RISK_COLOR: Record<string, string> = {
  critical: 'var(--bad)',
  warn:     'var(--warn)',
  info:     'var(--teal)',
}
const RISK_BG: Record<string, string> = {
  critical: 'rgba(255,77,109,.12)',
  warn:     'rgba(245,197,66,.1)',
  info:     'rgba(46,230,197,.08)',
}
const riskColor = computed(() => RISK_COLOR[props.entry.risk_severity ?? ''] ?? 'var(--faint)')
const riskBg    = computed(() => RISK_BG[props.entry.risk_severity ?? ''] ?? 'transparent')
</script>

<template>
  <div :class="['entry', entry.is_security_alert ? 'alert' : '']">
    <!-- Left gutter: change icon + connector line -->
    <div class="gutter">
      <div
        class="change-icon"
        :style="`color:${changeIconColor};border-color:${changeIconColor}44;background:${changeIconColor}12`"
      >{{ changeIcon }}</div>
      <div class="connector" />
    </div>

    <!-- Content -->
    <div class="body" @click="expanded = !expanded" tabindex="0" role="button" :aria-expanded="expanded" @keydown.enter.prevent="expanded = !expanded" @keydown.space.prevent="expanded = !expanded">
      <!-- Top row -->
      <div class="top-row">
        <div class="top-left">
          <!-- Record type badge -->
          <span class="type-badge" :style="`color:${typeColor};border-color:${typeColor}40;background:${typeColor}12`">
            {{ entry.record_type }}
          </span>

          <!-- Risk severity badge (AI-generated) -->
          <span v-if="entry.risk_severity" class="risk-badge"
            :style="`color:${riskColor};background:${riskBg};border-color:${riskColor}44`">
            <span class="risk-dot" :style="`background:${riskColor}`" />
            {{ entry.risk_severity.toUpperCase() }}
          </span>

          <!-- Legacy security alert flag (shown only if no AI risk yet) -->
          <span v-else-if="entry.is_security_alert" class="alert-flag">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Security change
          </span>

          <!-- Summary -->
          <span class="summary">{{ entry.change_summary }}</span>
        </div>

        <div class="top-right">
          <span v-if="entry.domain_name" class="domain-chip">{{ entry.domain_name }}</span>
          <span class="timestamp" :title="fullTimestamp">{{ relativeTime }}</span>
          <svg class="expand-caret" :class="expanded ? 'open' : ''" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M6 9l6 6 6-6"/>
          </svg>
        </div>
      </div>

      <!-- Record host -->
      <div class="host-line">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
        </svg>
        {{ entry.record_host }}
      </div>

      <!-- Token-level diff highlight (always visible for modified) -->
      <div v-if="hasDiff && !expanded" class="mini-diff">
        <span v-for="t in removedTokens" :key="t" class="diff-token removed">{{ t }}</span>
        <span v-for="t in addedTokens"   :key="t" class="diff-token added">{{ t }}</span>
      </div>

      <!-- Expanded full diff -->
      <div v-if="expanded" class="diff-block">
        <div v-if="entry.previous_value" class="diff-line old">
          <span class="diff-marker">−</span>
          <code>{{ entry.previous_value }}</code>
          <button
            v-if="canRollback"
            class="rollback-btn"
            :class="copied ? 'copied' : ''"
            title="Copy this previous value so you can republish it at your DNS provider"
            @click.stop="copyPreviousValue"
          >{{ copied ? '✓ Copied' : 'Revert: copy this' }}</button>
        </div>
        <div v-else class="diff-line meta">
          <span class="diff-marker"> </span>
          <code class="muted-code">No previous value — record was newly created</code>
        </div>
        <div v-if="entry.current_value" class="diff-line new">
          <span class="diff-marker">+</span>
          <code>{{ entry.current_value }}</code>
        </div>
        <div v-else class="diff-line meta">
          <span class="diff-marker"> </span>
          <code class="muted-code">Record removed — no current value</code>
        </div>
        <div v-if="canRollback" class="rollback-hint">
          Paste the copied value back into your DNS provider at <code>{{ entry.record_host }}</code> to undo this change.
        </div>

        <!-- AI risk assessment drawer -->
        <div v-if="entry.risk_explanation" class="risk-drawer"
          :style="`border-top-color:${riskColor}33;background:${riskBg}`">
          <div class="risk-drawer-head">
            <span class="risk-drawer-label" :style="`color:${riskColor}`">Risk Assessment</span>
            <AiBadge v-if="entry.risk_is_ai" :loading="false" />
          </div>
          <p class="risk-text">{{ entry.risk_explanation }}</p>
          <div v-if="entry.risk_action" class="risk-action">
            <span class="risk-action-label">Recommended action</span>
            {{ entry.risk_action }}
          </div>
        </div>

        <!-- Legacy static explanation (shown only if no AI risk yet) -->
        <div v-else-if="entry.is_security_alert" class="alert-explain">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span v-if="entry.change_type === 'removed' && entry.record_type === 'DMARC'">
            DMARC record removed — your domain is now unprotected against spoofing.
          </span>
          <span v-else-if="entry.change_type === 'removed' && entry.record_type === 'MX'">
            MX record removed — inbound mail routing may be broken.
          </span>
          <span v-else-if="entry.record_type === 'SPF'">
            SPF record contains a permissive <code>+all</code> or <code>all</code> mechanism — any server can send email as your domain.
          </span>
          <span v-else-if="entry.record_type === 'DMARC'">
            DMARC policy was downgraded — previously stronger enforcement has been weakened.
          </span>
          <span v-else>This change may weaken your email security posture. Review carefully.</span>
        </div>

        <!-- Where this change shows up in real traffic, and what it does to the plan -->
        <div class="entry-links">
          <NextStep v-if="evidence" :to="evidence.to" :label="evidence.label" :domain="linkDomain" />
          <NextStep to="roadmap" label="Open the roadmap" :domain="linkDomain" />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.entry-links { display: flex; flex-wrap: wrap; gap: 6px 18px; margin-top: 10px; }
.entry {
  display: flex; gap: 0; padding: 0;
}
.entry.alert .body { border-left: 2px solid rgba(255,77,109,.4); }

/* ── Gutter ──────────────────────────────────────────────────── */
.gutter {
  display: flex; flex-direction: column; align-items: center;
  width: 36px; flex: none; padding-top: 14px;
}
.change-icon {
  width: 26px; height: 26px; border-radius: 8px; border: 1px solid;
  display: grid; place-items: center; font-family: var(--mono);
  font-size: 14px; font-weight: 700; flex: none; line-height: 1;
}
.connector { flex: 1; width: 2px; background: var(--line); margin-top: 6px; min-height: 12px; }
.entry:last-child .connector { display: none; }

/* ── Body ────────────────────────────────────────────────────── */
.body {
  flex: 1; min-width: 0; padding: 12px 0 12px 12px;
  cursor: pointer; border-radius: 10px; transition: background .12s;
  border-bottom: 1px solid var(--line);
}
.entry:last-child .body { border-bottom: none; }
.body:hover { background: rgba(255,255,255,.03); }

/* ── Top row ─────────────────────────────────────────────────── */
.top-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; margin-bottom: 5px; flex-wrap: wrap; }
.top-left  { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.top-right { display: flex; align-items: center; gap: 8px; flex: none; }

.type-badge {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .5px;
  padding: 3px 8px; border-radius: 6px; border: 1px solid; flex: none;
}
.alert-flag {
  display: flex; align-items: center; gap: 4px;
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .3px;
  color: var(--bad); background: rgba(255,77,109,.1); border: 1px solid rgba(255,77,109,.3);
  padding: 2px 8px; border-radius: 6px; flex: none;
}
.alert-flag svg { width: 10px; height: 10px; }

.summary { font-size: 13px; font-weight: 600; color: var(--txt); }

.domain-chip { font-family: var(--mono); font-size: 10px; color: var(--teal); }
.timestamp   { font-family: var(--mono); font-size: 10.5px; color: var(--faint); white-space: nowrap; cursor: help; }
.expand-caret { width: 14px; height: 14px; color: var(--faint); transition: transform .2s; flex: none; }
.expand-caret.open { transform: rotate(180deg); }

/* ── Host line ───────────────────────────────────────────────── */
.host-line {
  display: flex; align-items: center; gap: 5px;
  font-family: var(--mono); font-size: 10.5px; color: var(--faint);
  margin-bottom: 6px;
}
.host-line svg { width: 11px; height: 11px; flex: none; }

/* ── Mini diff tokens ────────────────────────────────────────── */
.mini-diff { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 4px; }
.diff-token {
  font-family: var(--mono); font-size: 10px; padding: 2px 7px;
  border-radius: 5px; font-weight: 600;
}
.diff-token.removed { background: rgba(255,77,109,.12); color: var(--bad); text-decoration: line-through; }
.diff-token.added   { background: rgba(52,224,161,.12); color: var(--good); }

/* ── Full diff block ─────────────────────────────────────────── */
.diff-block {
  margin-top: 10px; border-radius: 10px; overflow: hidden;
  border: 1px solid var(--line); background: rgba(0,0,0,.25);
}
.diff-line {
  display: flex; gap: 0; align-items: flex-start; padding: 8px 12px;
}
.diff-line.old  { background: rgba(255,77,109,.07); border-bottom: 1px solid rgba(255,77,109,.15); }
.diff-line.new  { background: rgba(52,224,161,.06); }
.diff-line.meta { background: rgba(255,255,255,.02); }
.diff-marker {
  font-family: var(--mono); font-size: 13px; font-weight: 700; width: 18px; flex: none;
  line-height: 1.5;
}
.diff-line.old  .diff-marker { color: var(--bad); }
.diff-line.new  .diff-marker { color: var(--good); }
.diff-line.old { flex-wrap: wrap; gap: 8px; }
code {
  font-family: var(--mono); font-size: 11px; line-height: 1.6;
  word-break: break-all; white-space: pre-wrap; color: var(--txt);
}
.muted-code { color: var(--faint) !important; font-style: italic; }

/* ── Rollback ────────────────────────────────────────────────── */
.rollback-btn {
  font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: .3px;
  padding: 4px 10px; border-radius: 7px; flex: none; margin-left: auto;
  background: rgba(255,77,109,.12); border: 1px solid rgba(255,77,109,.3); color: var(--bad);
  cursor: pointer; transition: .15s; white-space: nowrap;
}
.rollback-btn:hover { background: rgba(255,77,109,.2); }
.rollback-btn.copied { background: rgba(52,224,161,.15); border-color: rgba(52,224,161,.4); color: var(--good); }
.rollback-hint {
  font-size: 11px; color: var(--muted); line-height: 1.5; padding: 8px 12px;
  background: rgba(255,255,255,.02); border-top: 1px solid var(--line);
}
.rollback-hint code { font-size: 10px; color: #9aa6ff; }

/* ── Risk badge ──────────────────────────────────────────────── */
.risk-badge {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .5px;
  padding: 2px 8px; border-radius: 6px; border: 1px solid; flex: none;
}
.risk-dot {
  width: 5px; height: 5px; border-radius: 50%; flex: none;
}

/* ── Risk assessment drawer ──────────────────────────────────── */
.risk-drawer {
  border-top: 1px solid; padding: 12px 14px;
  display: flex; flex-direction: column; gap: 8px;
}
.risk-drawer-head {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
}
.risk-drawer-label {
  font-family: var(--mono); font-size: 9px; font-weight: 700;
  letter-spacing: .8px; text-transform: uppercase;
}
.risk-text {
  font-size: 12.5px; line-height: 1.65; color: var(--txt); margin: 0;
}
.risk-action {
  font-family: var(--mono); font-size: 10.5px; color: var(--muted);
  background: rgba(255,255,255,.04); border-radius: 8px; padding: 8px 12px;
  border: 1px solid var(--line); line-height: 1.55;
}
.risk-action-label {
  display: block; font-size: 8.5px; letter-spacing: .6px; text-transform: uppercase;
  color: var(--faint); margin-bottom: 3px;
}

/* ── Alert explanation ───────────────────────────────────────── */
.alert-explain {
  display: flex; gap: 9px; align-items: flex-start;
  padding: 10px 12px; background: rgba(255,77,109,.07);
  border-top: 1px solid rgba(255,77,109,.2);
  font-size: 12px; color: #ffb3c1; line-height: 1.5;
}
.alert-explain svg { width: 14px; height: 14px; color: var(--bad); flex: none; margin-top: 1px; }
.alert-explain code { font-size: 10.5px; background: rgba(255,77,109,.15); padding: 1px 5px; border-radius: 4px; color: var(--bad); }
</style>
