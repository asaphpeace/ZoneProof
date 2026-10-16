<script setup lang="ts">
/**
 * Unified status chip covering: am, mini, stg, pill, cls variants.
 * variant: 'am' | 'mini' | 'stg' | 'pill' | 'cls'
 * value: the string value that maps to color
 */
defineProps<{ variant?: string; value: string; label?: string; dashed?: boolean }>()
</script>

<template>
  <span :class="chipClass">{{ label ?? value }}</span>
</template>

<script lang="ts">
const AM_MAP: Record<string, string>  = { PASS:'pass', ALIGNED:'pass', UNALIGNED:'warn', FAIL:'fail', NONE:'fail' }
const STG_MAP: Record<string, string> = { reject:'good', enforce:'good', quarantine:'indigo', testing:'indigo', monitor:'amber', none:'bad', 'NO RECORD':'bad' }
const PILL_MAP: Record<string, string>= { ok:'ok', danger:'danger', warn:'warnp', warnp:'warnp' }
const CLS_MAP: Record<string, string> = { authorized:'auth', forwarded:'fwd', unauth:'unauth', spoof:'susp', unknown:'susp' }

export default {
  computed: {
    chipClass(): string[] {
      const v = this.variant || 'am'
      const val = (this.value || '').toLowerCase()
      const cls: string[] = []
      if (v === 'am')   cls.push('am', AM_MAP[this.value] || 'fail')
      if (v === 'mini') cls.push('miniam', val === 'pass' || val === 'p' ? 'p' : val === 'warn' || val === 'w' ? 'w' : 'f')
      if (v === 'stg')  cls.push('stg', STG_MAP[val] || 'none')
      if (v === 'pill') cls.push('pill', PILL_MAP[val] || 'ok')
      if (v === 'cls')  { cls.push('cls', CLS_MAP[val] || 'susp'); if (this.dashed) cls.push('dashed') }
      return cls
    }
  }
}
</script>

<style scoped>
.am { font-family:var(--mono);font-size:9.5px;font-weight:700;padding:4px 8px;border-radius:7px;display:inline-flex; }
.am.pass { background:rgba(52,224,161,.15);color:var(--good) }
.am.fail { background:rgba(255,77,109,.15);color:var(--bad) }
.am.warn { background:rgba(245,197,66,.15);color:var(--amber) }

.miniam { font-size:8.5px;font-weight:700;padding:2px 6px;border-radius:5px;width:fit-content; }
.miniam.p { background:rgba(52,224,161,.15);color:var(--good) }
.miniam.f { background:rgba(255,77,109,.15);color:var(--bad) }
.miniam.w { background:rgba(245,197,66,.15);color:var(--amber) }

.stg { font-family:var(--mono);font-size:9px;font-weight:700;padding:4px 9px;border-radius:7px;width:fit-content; }
.stg.good    { background:rgba(52,224,161,.16);color:var(--good) }
.stg.indigo  { background:rgba(91,92,240,.16);color:#9aa6ff }
.stg.amber   { background:rgba(245,197,66,.16);color:var(--amber) }
.stg.bad,.stg.none { background:rgba(255,77,109,.16);color:var(--bad) }

.pill { font-family:var(--mono);font-size:10px;font-weight:700;padding:4px 10px;border-radius:20px; }
.pill.ok    { background:rgba(52,224,161,.15);color:var(--good) }
.pill.danger{ background:rgba(255,77,109,.16);color:var(--bad) }
.pill.warnp { background:rgba(245,197,66,.16);color:var(--amber) }

.cls { font-size:10px;font-weight:600;padding:5px 10px;border-radius:20px;width:fit-content;cursor:pointer; }
.cls.auth   { background:rgba(52,224,161,.14);color:var(--good) }
.cls.fwd    { background:rgba(91,92,240,.16);color:#9aa6ff }
.cls.unauth { background:rgba(245,197,66,.16);color:var(--amber) }
.cls.susp   { background:rgba(255,77,109,.16);color:var(--bad) }
.cls.dashed { background:transparent!important;border:1px dashed currentColor; }
</style>
