<script setup lang="ts">
import { ref, computed } from 'vue'

// PAIN_POINT_RESOLUTION_PLAN.md Pain 5 — mirrors EnforcementReadinessCard's
// per-source checklist for MX hosts. Critically, "Fix this" branches by
// fix_category: a cert/server issue (the common case) routes to mail-server
// guidance, never the DNS registrar flow — those are different owners.
const props = defineProps<{
  mxHosts: {
    mx_host: string
    total_sessions: number
    successful_sessions: number
    failed_sessions: number
    pass_pct: number
    failure_explanation: string | null
    severity: string
    fix_action: string | null
    fix_category: 'dns' | 'server' | null
  }[]
}>()

const serverFixOpen = ref<{ host: string; action: string } | null>(null)

const counts = computed(() => {
  const ready = props.mxHosts.filter(h => h.severity === 'ok').length
  return { ready, total: props.mxHosts.length }
})

function fixThis(h: any) {
  if (h.fix_category === 'server') {
    serverFixOpen.value = { host: h.mx_host, action: h.fix_action }
  }
  // "dns" category is handled by the existing Review TLS record flow on
  // this page already — no separate modal needed, the registrar
  // hand-holding lives there.
}
</script>

<template>
  <div v-if="mxHosts.length" class="mx-card">
    <div class="mc-header">
      <span class="mc-title">MX host readiness</span>
      <span class="mc-pill" :class="{ complete: counts.ready === counts.total }">
        {{ counts.ready }} / {{ counts.total }} hosts clean
      </span>
    </div>

    <div v-for="h in mxHosts" :key="h.mx_host" :class="['mx-row', h.severity]">
      <span class="mx-icon" :class="h.severity">{{ h.severity === 'ok' ? '✓' : h.severity === 'critical' ? '✗' : '⚠' }}</span>
      <div class="mx-main">
        <span class="mx-host">{{ h.mx_host }}</span>
        <span class="mx-pct" :class="h.severity">{{ h.pass_pct }}% pass</span>
        <span v-if="h.failure_explanation" class="mx-explain">{{ h.failure_explanation }}</span>
      </div>
      <span v-if="h.fix_category" class="mx-owner-tag" :class="h.fix_category">
        {{ h.fix_category === 'dns' ? 'DNS fix' : 'Mail server fix' }}
      </span>
      <button v-if="h.fix_category === 'server'" class="mx-fix-btn" @click="fixThis(h)">Fix this →</button>
    </div>

    <div v-if="serverFixOpen" class="server-fix-overlay" @click.self="serverFixOpen = null">
      <div class="server-fix-box">
        <div class="sf-head"><span>{{ serverFixOpen.host }}</span><button class="sf-x" @click="serverFixOpen = null">✕</button></div>
        <p class="sf-note">
          This is a mail-server / hosting-provider issue, not a DNS record — there's nothing to
          publish here. The fix happens on whatever runs your mail server (Exchange, Postfix, your
          hosting provider's mail config).
        </p>
        <p class="sf-action">{{ serverFixOpen.action }}</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.mx-card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; padding: 16px 18px; margin-top: 14px; }
.mc-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
.mc-title { font-family: var(--disp); font-weight: 700; font-size: 13.5px; }
.mc-pill { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--amber); background: rgba(245,197,66,.12); border: 1px solid rgba(245,197,66,.3); padding: 4px 11px; border-radius: 20px; }
.mc-pill.complete { color: var(--good); background: rgba(52,224,161,.12); border-color: rgba(52,224,161,.3); }

.mx-row { display: flex; align-items: center; gap: 9px; padding: 9px 4px; border-bottom: 1px solid rgba(255,255,255,.04); flex-wrap: wrap; }
.mx-row:last-of-type { border-bottom: none; }
.mx-icon { font-weight: 800; font-size: 12px; flex: none; width: 16px; text-align: center; }
.mx-icon.ok { color: var(--good); }
.mx-icon.critical { color: var(--bad); }
.mx-icon.warning { color: var(--amber); }
.mx-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
.mx-host { font-family: var(--mono); font-size: 12px; color: var(--txt); }
.mx-pct { font-family: var(--mono); font-size: 10px; }
.mx-pct.ok { color: var(--good); }
.mx-pct.critical { color: var(--bad); }
.mx-pct.warning { color: var(--amber); }
.mx-explain { font-size: 10.5px; color: var(--faint); }
.mx-owner-tag { font-family: var(--mono); font-size: 8.5px; font-weight: 700; padding: 2px 7px; border-radius: 6px; flex: none; }
.mx-owner-tag.dns { background: rgba(91,92,240,.14); color: #9aa6ff; }
.mx-owner-tag.server { background: rgba(245,197,66,.14); color: var(--amber); }
.mx-fix-btn { flex: none; background: rgba(245,197,66,.14); border: 1px solid rgba(245,197,66,.35); color: var(--amber); border-radius: 9px; padding: 5px 11px; font-size: 11px; font-weight: 700; cursor: pointer; }

.server-fix-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 300; display: grid; place-items: center; padding: 20px; }
.server-fix-box { width: 420px; max-width: 92vw; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 16px; padding: 20px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.sf-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.sf-head span { font-family: var(--mono); font-weight: 700; font-size: 13px; }
.sf-x { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 24px; height: 24px; cursor: pointer; font-size: 12px; }
.sf-note { font-size: 11.5px; color: var(--faint); line-height: 1.55; margin: 0 0 10px; }
.sf-action { font-size: 12.5px; color: var(--amber); line-height: 1.55; margin: 0; }
</style>
