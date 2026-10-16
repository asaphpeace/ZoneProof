<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import { funnelPct, funnelReason } from '@/components/brand/brandLabels'

const store = useBrandGuardStore()
const data = ref<any>(null)
const loading = ref(false)
const error = ref('')
const days = ref(30)
const allBrands = ref(false)

async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api.brandFunnel(days.value, allBrands.value ? undefined : store.profile?.id)
  } catch (e: any) {
    error.value = e.message || 'Could not load the funnel'
  } finally {
    loading.value = false
  }
}
watch([days, allBrands, () => store.profile?.id], load)
onMounted(async () => { await store.ensureLoaded(); await load() })

// Each stage counts its own things (names, candidates, visits), so a row's bar is its own pass rate, not a share of the first row.
const stages = computed<any[]>(() => data.value?.stages ?? [])
const missingFor = (key: string) => (data.value?.not_built ?? []).filter((m: any) => m.after === key)
const empty = computed(() => stages.value.length > 0 && stages.value.every(s => !s.entered && !s.passed))
const outcomes = computed(() => Object.entries(data.value?.outcomes ?? {}).sort((a: any, b: any) => b[1] - a[1]))
const spark = (s: any) => {
  const top = Math.max(1, ...s.daily.map((d: any) => d.entered))
  return s.daily.map((d: any) => ({ day: d.day, h: Math.round((d.entered / top) * 100), n: d.entered }))
}
const STATE_NOTE: Record<string, string> = { probe: 'Off: the worker is not switched on', render: 'Off: the renderer is not switched on' }
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Funnel" crumb="Funnel" no-scan sub="Where the work goes: how many items entered and left each stage, and why the rest dropped out. Counts only, never domain names." />

      <div class="bar">
        <label>Period
          <select v-model.number="days"><option :value="7">Last 7 days</option><option :value="30">Last 30 days</option><option :value="90">Last 90 days</option></select>
        </label>
        <label v-if="store.profiles.length > 1" class="all"><input v-model="allBrands" type="checkbox" /> All brands</label>
      </div>

      <p v-if="error" class="err" role="alert">{{ error }}</p>
      <p v-if="empty && !loading" class="note">Nothing has been counted in this period yet. Counting started with the first scan after this was added, so run a scan and come back.</p>
      <p class="note">Each stage counts its own things (names, candidates, visits), so this is a series of filters, not one pile that shrinks. The bar in each row is that stage's own pass rate.</p>

      <ol class="funnel" v-if="stages.length">
        <template v-for="s in stages" :key="s.key">
          <li class="stage" :class="{ off: s.state === 'off' }">
            <div class="head">
              <div><h3>{{ s.label }}</h3><span class="unit">{{ s.unit }}</span></div>
              <span v-if="s.state === 'off'" class="chip off">{{ STATE_NOTE[s.needs] }}</span>
            </div>
            <div class="nums">
              <b>{{ s.entered.toLocaleString() }}</b> in <span class="arrow">→</span> <b>{{ s.passed.toLocaleString() }}</b> <span class="pm">{{ s.passed_means }}</span>
              <span class="rate">{{ funnelPct(s.pass_rate) }}</span>
            </div>
            <div class="track" role="img" :aria-label="`${funnelPct(s.pass_rate)} passed`"><i :style="{ width: ((s.pass_rate ?? 0) * 100) + '%' }" /></div>
            <ul v-if="Object.keys(s.detail).length" class="reasons">
              <li v-for="(n, k) in s.detail" :key="k"><span>{{ funnelReason(String(k)) }}</span><b>{{ Number(n).toLocaleString() }}</b></li>
            </ul>
            <div v-if="s.entered" class="spark" aria-hidden="true"><span v-for="d in spark(s)" :key="d.day" :style="{ height: Math.max(d.h, d.n ? 6 : 2) + '%' }" :title="`${d.day}: ${d.n}`" /></div>
          </li>
          <li v-for="m in missingFor(s.key)" :key="m.label" class="missing"><span class="tag">Not built</span> {{ m.label }}<span v-if="m.plan" class="plan"> (plan {{ m.plan }})</span></li>
        </template>
      </ol>

      <section v-if="outcomes.length" class="stand">
        <h3>Where your candidates stand now</h3>
        <div class="chips"><span v-for="[k, n] in outcomes" :key="k" class="chip">{{ funnelReason('status_' + k) }} <b>{{ n }}</b></span></div>
      </section>
    </template>
  </BrandFrame>
</template>

<style scoped>
.bar { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
.bar label { font: 500 12px var(--mono); color: var(--muted); display: flex; gap: 8px; align-items: center; }
.bar select { min-height: 36px; padding: 0 10px; border-radius: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); font: 500 13px var(--body); }
.err { color: #ff8da1; }
.note { font-size: 12.5px; color: var(--faint); max-width: 75ch; margin: 0 0 12px; }
.funnel { list-style: none; padding: 0; margin: 0 0 20px; display: grid; gap: 10px; }
.stage { background: rgba(255,255,255,.02); border: 1px solid var(--line2); border-radius: 14px; padding: 14px 16px; }
.stage.off { opacity: .6; }
.head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
h3 { margin: 0; font-size: 14px; }
.unit { font: 500 11px var(--mono); color: var(--faint); }
.nums { margin-top: 8px; font-size: 13px; color: var(--muted); display: flex; gap: 6px; align-items: baseline; flex-wrap: wrap; }
.nums b { font: 700 16px var(--mono); color: var(--txt); }
.pm { color: var(--faint); font-size: 12px; }
.arrow { color: var(--faint); }
.rate { margin-left: auto; font: 700 13px var(--mono); color: var(--txt); }
.track { height: 6px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; margin: 8px 0; }
.track i { display: block; height: 100%; background: linear-gradient(90deg, #5b5cf0, #4b4ce0); }
.reasons { list-style: none; padding: 0; margin: 8px 0 0; display: flex; gap: 8px 10px; flex-wrap: wrap; }
.reasons li { font-size: 12px; background: rgba(255,255,255,.05); border: 1px solid var(--line2); border-radius: 999px; padding: 2px 10px; color: var(--muted); display: flex; gap: 8px; }
.reasons b { font: 700 12px var(--mono); color: var(--txt); }
.spark { display: flex; align-items: flex-end; gap: 2px; height: 28px; margin-top: 10px; }
.spark span { flex: 1; min-width: 2px; background: rgba(91,92,240,.55); border-radius: 2px 2px 0 0; }
.chip { font: 600 11px var(--mono); padding: 3px 10px; border-radius: 999px; border: 1px solid var(--line2); color: var(--muted); display: inline-flex; gap: 6px; }
.chip.off { border-color: rgba(245,197,66,.35); color: #f7d27a; background: rgba(245,197,66,.08); }
.chip b { color: var(--txt); }
.missing { border: 1px dashed var(--line2); border-radius: 10px; padding: 8px 14px; font-size: 12.5px; color: var(--faint); margin-left: 24px; }
.tag { font: 700 10px var(--mono); text-transform: uppercase; letter-spacing: .06em; margin-right: 8px; padding: 1px 7px; border-radius: 4px; border: 1px dashed var(--line2); }
.plan { color: var(--faint); }
.stand h3 { margin-bottom: 8px; }
.chips { display: flex; gap: 8px; flex-wrap: wrap; }
</style>
